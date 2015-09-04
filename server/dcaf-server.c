/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *
 */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"

#include <string.h>
#include "tinydtls.h"
#include "dtls.h"
#include "net/ip/uip-debug.h"
#include "debug.h"
#include "coap.h"
#include "cn-cbor.h"
#include "queue.h"
#include "common.h"
#include <math.h>

#ifndef DTLS_PSK
#error "need a tinydtls that is built with PSK support"
#endif

#define UIP_IP_BUF ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

#define PRINTF(...) printf(__VA_ARGS__)
#define PRINT6ADDR(addr)                                                       \
  PRINTF(" %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%"   \
         "02x%02x ",                                                           \
         ((u8_t *)addr)[0], ((u8_t *)addr)[1], ((u8_t *)addr)[2],              \
         ((u8_t *)addr)[3], ((u8_t *)addr)[4], ((u8_t *)addr)[5],              \
         ((u8_t *)addr)[6], ((u8_t *)addr)[7], ((u8_t *)addr)[8],              \
         ((u8_t *)addr)[9], ((u8_t *)addr)[10], ((u8_t *)addr)[11],            \
         ((u8_t *)addr)[12], ((u8_t *)addr)[13], ((u8_t *)addr)[14],           \
         ((u8_t *)addr)[15])

/* the default port for secure CoAP communication */
#define COAP_DEFAULT_PORT 5683
#define COAPS_DEFAULT_PORT 5684

#define DCAF_MAX_FACE 128    /* Maximum length of a Ticket Face */
#define DCAF_MAX_VERIFIER 16 /* Maximum length of a Ticket Verifier */

#define DCAF_MAX_SAM_INFORMATION_MESSAGE 64
#define DCAF_SAM_KEY_MAX_SIZE 16
#define DCAF_SAM_HOST_MAX_SIZE 64
#define DCAF_SAM_AUTH_URI_MAX_SIZE 128
#define DCAF_REVOCATION_WINDOW_SIZE 32
#define DCAF_SAM_DEFAULT_KEY                                                   \
  "\xd8\xd5\x07\xfa\xb8\xeb\x11\x41\xb1\x17\x2c\x28\x61\x2a\x56\x05"

#define DCAF_SAM_DEFAULT_AUTH_RESSOURCE "https://[aaaa::1]:8080/ep"

#define DTLS_PSK_GEN_HMAC_SHA256 0x00
#define DCAF_TYPE_SAM 0x00
#define DCAF_TYPE_SAI 0x01
#define DCAF_TYPE_CAI 0x02
#define DCAF_TYPE_E 0x03
#define DCAF_TYPE_K 0x04
#define DCAF_TYPE_TS 0x05
#define DCAF_TYPE_L 0x06
#define DCAF_TYPE_G 0x07
#define DCAF_TYPE_F 0x08
#define DCAF_TYPE_V 0x09
#define DCAF_TYPE_SQ 0x0A
#define DCAF_TYPE_KEY 0x0B
#define DCAF_TYPE_SAM_URI 0x0C

#define COAP_MEDIATYPE_APPLICATION_DCAF 70
#define DCAF_RS_TICKET_STORE_MAX_SIZE 3

#define RESOURCE_TEMP_1 "temp/1"
#define RESOURCE_KEY "key"
#define RESOURCE_REVOCATION "revocations"

typedef struct dcaf_context_t {
  coap_context_t *coap_context;
  struct uip_udp_conn *dtls_conn;
  dtls_context_t *dtls_context;
} dcaf_context_t;
static dcaf_context_t context;

// K(SAM,S)
static unsigned char dcaf_sam_secret[DCAF_SAM_KEY_MAX_SIZE] =
    DCAF_SAM_DEFAULT_KEY;
static size_t dcaf_sam_secret_size = sizeof(DCAF_SAM_DEFAULT_KEY) - 1;
// SAM Ticket-URI
static unsigned char dcaf_sam_auth_res[DCAF_SAM_AUTH_URI_MAX_SIZE] =
    DCAF_SAM_DEFAULT_AUTH_RESSOURCE;
// Revocation Window
static long revocation_bitmap = 0; /* revocation window 32 bits */
static long revocation_last_seq = 0;
// Ticket Store (Client Tickets are stored)
struct ticket_store_entry {
  const session_t *session;
  unsigned char face_data[DCAF_MAX_FACE];
  size_t face_len;
  const cn_cbor *cn_face;
};
static struct ticket_store_entry ticket_faces[DCAF_RS_TICKET_STORE_MAX_SIZE];
static size_t ticket_store_size = 0;
static int ticket_store_ptr = 0;
// Data for measure processing time
#ifdef DCAF_TIME
struct energy_time {
  unsigned short source;
  long cpu;
  long lpm;
  long transmit;
  long listen;
};
static struct energy_time server_last;
static struct energy_time server_diff;
static struct energy_time server_last2;
static struct energy_time server_diff2;
#endif

static void print_local_addresses(void) {
  int i;
  uint8_t state;

  for (i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if (uip_ds6_if.addr_list[i].isused &&
        (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      printf("\n");
    }
  }
}

static void init_network() {
#ifndef NDEBUG
  printf("call: init_network\n");
#endif

  static dtls_handler_t dtls_cb = {
      .write = dtls_send_to_peer,
      .read = dtls_read_from_peer,
      .event = dtls_event,
      .get_psk_key = get_psk_key,
  };
  uip_ipaddr_t ipaddr;
#ifndef NDEBUG
  printf("dtls server started\n");
#endif
  /* set the network prefix to aaaa::/64 and generate EUI-64 address
   * from our L2 address */
  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0x200, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

  context.dtls_conn = udp_new(NULL, 0, NULL);
  udp_bind(context.dtls_conn, uip_htons(COAPS_DEFAULT_PORT));

  context.dtls_context = dtls_new_context(context.dtls_conn);
  if (context.dtls_context) {
    dtls_set_handler(context.dtls_context, &dtls_cb);
  }

  coap_address_t ca;
  coap_address_init(&ca);
  uip_ipaddr_copy(&ca.addr, &ipaddr);
  ca.port = uip_htons(COAP_DEFAULT_PORT);
  ca.size = sizeof(ca.addr) + sizeof(ca.port);

  context.coap_context = coap_new_context(&ca);
  context.coap_context->network_send = dcaf_network_send;

  init_resources(context.coap_context);
}


PROCESS(dcaf_rs1_process, "dcaf_rs1_process");
AUTOSTART_PROCESSES(&dcaf_rs1_process);

PROCESS_THREAD(dcaf_rs1_process, ev, data) {
  PROCESS_BEGIN();

  dtls_init();
  init_network();
  print_local_addresses();

  if (!context.dtls_context) {
    dtls_emerg("cannot create context\n");
    PROCESS_EXIT();
  }

#ifdef ENABLE_POWERTRACE
  powertrace_start(CLOCK_SECOND * 2);
#endif

  while (1) {
    PROCESS_WAIT_EVENT();
    if (ev == tcpip_event) {
#ifndef NDEBUG
      printf("event: TCPIP-EVENT\n");
#endif
      handle_tcpip_event();
    }
  }

  PROCESS_END();
}
