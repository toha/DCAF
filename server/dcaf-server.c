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

/**
* tinydtls handler to get psk
*/
static int get_psk_key(struct dtls_context_t *ctx, const session_t *sess,
                       const unsigned char *id, size_t id_len,
                       const dtls_psk_key_t **result) {
#ifndef NDEBUG
  printf("call: get_psk_key\n");
  printf("client id = (%d Byte)\n", id_len);
  hexdump(id, id_len);
#endif
#ifdef DCAF_TIME
  server_last.cpu = energest_type_time(ENERGEST_TYPE_CPU);
#endif

  if (3 <= id_len && 0 == strncmp("sam", id, 3)) {
    // Its SAM! Use key K(SAM,S)
    static dtls_psk_key_t sam_psk;
    sam_psk.key = (unsigned char *)dcaf_sam_secret;
    sam_psk.key_length = dcaf_sam_secret_size;
    *result = &sam_psk;

#ifndef NDEBUG
    printf("using k(SAM,S) as psk\n");
#endif

    return 0;
  }

  static unsigned char verifier[DTLS_HMAC_DIGEST_SIZE];
  static dtls_psk_key_t psk = {.key = verifier};

  dtls_hmac_context_t *hmac_ctx; // for ticket verifier generation

  if (DCAF_MAX_FACE < id_len) {
#ifndef NDEBUG
    printf("ticket face too long\n");
#endif
    *result = NULL;
    return -1;
  }

  struct ticket_store_entry *found_ticket = NULL;
  // Perform sanity checks before overwriting our internal key.
  if (id_len == 0) {
#ifndef NDEBUG
    printf("ticket face empty\n");
#endif

    if (0 != get_ticket_face(sess, &found_ticket) || found_ticket == NULL) {
#ifndef NDEBUG
      printf("ticket not found\n");
#endif
      *result = NULL;
      return -1;
    }
  } else {
#ifndef NDEBUG
    printf("ticket face not empty\n");
#endif
    if (0 != get_ticket_face(sess, &found_ticket) && found_ticket == NULL) {
// create ticket and save
#ifndef NDEBUG
      printf("save ticket\n");
#endif
      // save face in ticket store
      found_ticket = &ticket_faces[ticket_store_ptr];
      memset(found_ticket, 0, sizeof(struct ticket_store_entry));

      found_ticket->session = sess;
      memcpy(found_ticket->face_data, id, id_len);
      found_ticket->face_len = id_len;
      found_ticket->cn_face = NULL;

      if (ticket_store_ptr >= DCAF_RS_TICKET_STORE_MAX_SIZE - 1) {
        ticket_store_ptr = 0;
      } else {
        ticket_store_ptr++;
      }

      if (ticket_store_size < DCAF_RS_TICKET_STORE_MAX_SIZE) {
        ticket_store_size++;
      }
    } else {
// Update ticket
#ifndef NDEBUG
      printf("update saved ticket face of client\n");
#endif
      memcpy(found_ticket->face_data, id, id_len);
      found_ticket->face_len = id_len;
    }
  }

  // clear key storage
  memset(verifier, 0, sizeof(verifier));
  psk.key_length = 0;

#ifndef NDEBUG
  printf("k = \n");
  hexdump(dcaf_sam_secret, dcaf_sam_secret_size);
  printf("face = \n");
  hexdump(found_ticket->face_data, found_ticket->face_len);
#endif
  // calculate ticket verifier
  hmac_ctx = dtls_hmac_new(dcaf_sam_secret, dcaf_sam_secret_size);

  dtls_hmac_update(hmac_ctx, found_ticket->face_data, found_ticket->face_len);

  psk.key_length = dtls_hmac_finalize(hmac_ctx, psk.key);
  if (psk.key_length > DCAF_MAX_VERIFIER) {
    psk.key_length = DCAF_MAX_VERIFIER; // clamp verifier length
  }
#ifdef DCAF_TIME
  server_diff.cpu = energest_type_time(ENERGEST_TYPE_CPU) - server_last.cpu;
  printf("Time: calc psk with hmac on ticket face: %li\n", server_diff.cpu);
#endif

#ifndef NDEBUG
  printf("genereated verifier\n");
  hexdump(psk.key, psk.key_length);
#endif

  *result = &psk;
  dtls_hmac_free(hmac_ctx);
  return 0;
}

/**
* tinydtls handler which will be called on every connection state change
*/
static int dtls_event(struct dtls_context_t *ctx, session_t *sess,
                      dtls_alert_level_t level, unsigned short code) {
#ifndef NDEBUG
  printf("call: dtls_event\n");
#endif
  dtls_peer_t *peer;

  if (level == 0 && code == DTLS_EVENT_CONNECTED) {
    peer = dtls_get_peer(ctx, sess);
    if (peer == NULL) {
#ifndef NDEBUG
      printf("peer not found\n");
#endif
      return -1;
    }
  }
  return 0;
}

/**
* tinydtls handler which will be called to send network data
*/
static ssize_t dcaf_network_send(struct coap_context_t *c,
                                 const coap_endpoint_t *local_interface,
                                 const coap_address_t *dst, unsigned char *data,
                                 size_t datalen) {
#ifndef NDEBUG
  printf("call: dcaf_network_send\n");
#endif
  uint16_t local_port = uip_htons(local_interface->addr.port);
  // DTLS or raw coap connection?
  if (COAPS_DEFAULT_PORT == local_port) {
    session_t ss;
    dtls_session_init(&ss);
    uip_ipaddr_copy(&ss.addr, &dst->addr);
    ss.ifindex = local_interface->ifindex;
    ss.port = dst->port;
    ss.size = sizeof(ss.addr) + sizeof(ss.port);

    ssize_t res = dtls_write(context.dtls_context, &ss, (uint8 *)data, datalen);
    return res;

  } else if (COAP_DEFAULT_PORT == local_port) {
    return coap_network_send(context.coap_context, local_interface, dst, data,
                             datalen);
  } else {
    return 0;
  }
}

/**
* tinydtls handler which will be called to read network data
*/
static int dtls_read_from_peer(struct dtls_context_t *ctx, session_t *session,
                               uint8 *data, size_t len) {
#ifndef NDEBUG
  printf("call: dtls_read_from_peer\n");
#endif
  coap_packet_t *packet;
  packet = (coap_packet_t *)custom_coap_malloc_packet();
  coap_address_init(&(packet)->dst); /* the local interface address */
  coap_address_init(&(packet)->src); /* the remote peer */

  uip_ipaddr_copy(&packet->src.addr, &UIP_IP_BUF->srcipaddr);
  packet->src.port = UIP_UDP_BUF->srcport;
  uip_ipaddr_copy(&packet->dst.addr, &UIP_IP_BUF->destipaddr);
  packet->dst.port = UIP_UDP_BUF->destport;

  packet->length = len;
  memcpy(&packet->payload, data, len);

#ifdef DCAF_TIME
  server_last.cpu = energest_type_time(ENERGEST_TYPE_CPU);
#endif

  int a = coap_handle_message(context.coap_context,
                              context.coap_context->endpoint, packet);
  coap_free_packet(packet);

  return a;
}

/**
* tinydtls handler which will be called to route data to contiki
*/
static int dtls_send_to_peer(struct dtls_context_t *ctx, session_t *sess,
                             uint8 *data, size_t len) {
#ifndef NDEBUG
  printf("call: dtls_send_to_peer\n");
#endif
  struct uip_udp_conn *conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);
  uip_ipaddr_copy(&conn->ripaddr, &sess->addr);
  conn->rport = sess->port;
  uip_udp_packet_send(conn, data, len);

  /* Restore server connection to allow data from any node */
  memset(&conn->ripaddr, 0, sizeof(conn->ripaddr));
  memset(&conn->rport, 0, sizeof(conn->rport));

  return len;
}

static void dtls_handle_read(dtls_context_t *ctx) {
#ifndef NDEBUG
  printf("call: dtls_handle_read\n");
#endif
  session_t session;
  memset(&session, 0, sizeof(session_t));
  uip_ipaddr_copy(&session.addr, &UIP_IP_BUF->srcipaddr);
  session.port = UIP_UDP_BUF->srcport;
  session.size = sizeof(session.addr) + sizeof(session.port);

  dtls_handle_message(ctx, &session, uip_appdata, uip_datalen());
}

static void handle_tcpip_event() {
#ifndef NDEBUG
  printf("call: handle_tcpip_event\n");
#endif
  if (uip_newdata()) {
    uint16_t destport = uip_htons(UIP_UDP_BUF->destport);
    if (COAP_DEFAULT_PORT == destport) {
      coap_read(context.coap_context);
    } else {
      dtls_handle_read(context.dtls_context);
    }
  }
}


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
