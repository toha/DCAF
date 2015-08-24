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

#include "net/ip/uip-debug.h"
#include "debug.h"
#include "dtls.h"
#include "coap.h"

//#include "cbor.h"
#include "queue.h"
#include "common.h"
#include "cn-cbor.h"
#ifndef DTLS_PSK
#error "need a tinydtls that is built with PSK support"
#endif

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
#define UIP_IP_BUF ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

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

#define COAP_MEDIATYPE_APPLICATION_DCAF 70
#define COAP_DEFAULT_PORT 5683
#define COAPS_DEFAULT_PORT 5684

#define DCAF_MAX_FACE 128    /* Maximum length of a Ticket Face */
#define DCAF_MAX_VERIFIER 16 /* Maximum length of a Ticket Verifier */
#define DCAF_MAX_ACCESS_REQUEST_CBOR 128

#define DCAF_RS1_URI "coaps://[aaaa::200:0:0:2]/temp/1"
#define DCAF_RS1_URI_LENGTH sizeof(DCAF_RS1_URI) - 1

#define DCAF_CAM1_URI "coaps://[aaaa::200:0:0:1]/client-auth"
#define DCAF_CAM1_URI_LENGTH sizeof(DCAF_CAM1_URI) - 1
#define DCAF_CAM1_STATIC_PAYLOAD d

#define DCAF_CAM_ID "Client_identity"
#define DCAF_CAM_ID_LENGTH sizeof(DCAF_CAM_ID) - 1
#define DCAF_CAM_SECRET "secretPSK"
#define DCAF_CAM_SECRET_LENGTH sizeof(DCAF_CAM_SECRET) - 1

static struct etimer et;
static struct etimer et2;
#define TOGGLE_INTERVAL 30
#define TOGGLE_INTERVAL2 5


static coap_context_t *dcaf_coap_context;
static struct uip_udp_conn *dcaf_dtls_conn;
static dtls_context_t *dcaf_dtls_context;

typedef unsigned char method_t;
static unsigned char _token_data[8];
str the_token = {0, _token_data};

static session_t server_dst;
static coap_address_t server_dst_nocrypt;
static session_t cam_dst;

static uint8_t dcaf_access_request_payload[DCAF_MAX_ACCESS_REQUEST_CBOR];
static size_t dcaf_access_request_payload_length = 0;
static uint8_t dcaf_ticket_face[DCAF_MAX_FACE];
static size_t dcaf_ticket_face_length = 0;
static uint8_t dcaf_ticket_verifier[DCAF_MAX_VERIFIER];
static size_t dcaf_ticket_verifier_length = 0;

static int server_connected = 0;

struct dcaf_msg_hnd {
  session_t dst;
  unsigned short msg_id;
  void (*hnd)(struct coap_context_t *ctx,
              const coap_endpoint_t *local_interface,
              const coap_address_t *remote, coap_pdu_t *sent,
              coap_pdu_t *received, const coap_tid_t id);
};

static struct dcaf_msg_hnd msg_state;

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

static int get_psk_key(struct dtls_context_t *ctx, const session_t *sess,
                       const unsigned char *id, size_t id_len,
                       const dtls_psk_key_t **result) {

#ifndef NDEBUG
  printf("call: get_psk_key\n");
#endif

  if (uip_ipaddr_cmp(&sess->addr, &cam_dst.addr)) {
    static const dtls_psk_key_t cam_psk = {
        .id = (unsigned char *)DCAF_CAM_ID,
        .id_length = DCAF_CAM_ID_LENGTH,
        .key = (unsigned char *)DCAF_CAM_SECRET,
        .key_length = DCAF_CAM_SECRET_LENGTH};
    *result = &cam_psk;
  } else {

    static dtls_psk_key_t server_psk;
    server_psk.id = (unsigned char *)dcaf_ticket_face;
    server_psk.id_length = dcaf_ticket_face_length;
    server_psk.key = (unsigned char *)dcaf_ticket_verifier;
    server_psk.key_length = dcaf_ticket_verifier_length;

    *result = &server_psk;
  }
  return 0;
}
