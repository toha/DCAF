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

static void connect_cam() { dtls_connect(dcaf_dtls_context, &cam_dst); }

static void
handle_sam_information_response(struct coap_context_t *ctx,
                                const coap_endpoint_t *local_interface,
                                const coap_address_t *remote, coap_pdu_t *sent,
                                coap_pdu_t *received, const coap_tid_t id) {
#if !defined(NDEBUG) || defined(DCAF_DEBUG)
  printf("C<-S: got sam information message\n");
#endif
#ifdef DCAF_TIME
  server_last.cpu = energest_type_time(ENERGEST_TYPE_CPU);
#endif

  size_t payload_len;
  unsigned char *payload;
  if (!coap_get_data(received, &payload_len, &payload) || 0 >= payload_len) {
    return;
  }

  const cn_cbor *samicb;
  samicb = cn_cbor_decode((char *)payload, payload_len, NULL);

  if (!samicb || samicb->type != CN_CBOR_MAP) {
#ifndef NDEBUG
    printf("no cbor in sam information message found\n");
#endif
    return;
  }

  const cn_cbor *sam = cn_cbor_mapget_int(samicb, DCAF_TYPE_SAM);
  const cn_cbor *ts = cn_cbor_mapget_int(samicb, DCAF_TYPE_TS);

  cn_cbor *map;
  map = cn_cbor_map_create(NULL);
  cn_cbor_mapput_int(map, DCAF_TYPE_SAM, sam, NULL);
  cn_cbor *sai_auth_list = cn_cbor_array_create(NULL);
  cn_cbor *auth_list = cn_cbor_array_create(NULL);
  cn_cbor *auth_list_uri = cn_cbor_string_create(DCAF_RS1_URI, NULL);
  cn_cbor *auth_list_methods = cn_cbor_int_create(1, NULL);
  cn_cbor_array_append(auth_list, auth_list_uri, NULL);
  cn_cbor_array_append(auth_list, auth_list_methods, NULL);
  cn_cbor_array_append(sai_auth_list, auth_list, NULL);
  cn_cbor_mapput_int(map, DCAF_TYPE_SAI, sai_auth_list, NULL);
  cn_cbor_mapput_int(map, DCAF_TYPE_TS, ts, NULL);

  dcaf_access_request_payload_length = cbor_encoder_write(
      dcaf_access_request_payload, 0, DCAF_MAX_ACCESS_REQUEST_CBOR, map);

#ifndef NDEBUG
  printf("created cbor access request (%d Byte):\n",
         dcaf_access_request_payload_length);
  hexdump(dcaf_access_request_payload, dcaf_access_request_payload_length);
#endif

  free(auth_list_uri->v.str);
  free(map);
// cn_cbor_free(samicb);

#ifdef DCAF_TIME
  server_diff.cpu = energest_type_time(ENERGEST_TYPE_CPU) - server_last.cpu;
  printf("Time: handle sam information message: %li\n", server_diff.cpu);
#endif

// Next connect to cam
// start DTLS-Handshake with CAM
#if !defined(NDEBUG) || defined(DCAF_DEBUG)
  printf("C->CAM: start dtls handshake\n");
#endif
  connect_cam();
}

static void handle_server_response(struct coap_context_t *ctx,
                                   const coap_endpoint_t *local_interface,
                                   const coap_address_t *remote,
                                   coap_pdu_t *sent, coap_pdu_t *received,
                                   const coap_tid_t id) {

#if !defined(NDEBUG) || defined(DCAF_DEBUG)
  printf("C<-S: got resource response\n");
#endif
#ifdef DCAF_TIME
  server_last.cpu = energest_type_time(ENERGEST_TYPE_CPU);
#endif

  char buffer[10];
  size_t payload_len;
  unsigned char *payload;
  if (!coap_get_data(received, &payload_len, &payload) || 0 >= payload_len) {
    return;
  }
#ifdef DCAF_TIME
  server_diff2.cpu = energest_type_time(ENERGEST_TYPE_CPU) - server_last2.cpu;
  printf("Time: complete authorized resource request: %li\n", server_diff2.cpu);
#endif

  if (payload_len < 10) {
    strncpy(buffer, payload, payload_len);
    buffer[payload_len] = '\0';

    printf("C: sensor value: %s C\n", buffer);
  }
}

static void send_cam_request() {
#ifdef DCAF_TIME
  server_last.cpu = energest_type_time(ENERGEST_TYPE_CPU);
#endif

  coap_pdu_t *pdu;
  create_coap_message(handle_cam_response, DCAF_CAM1_URI, DCAF_CAM1_URI_LENGTH,
                      2, &pdu);

  coap_add_data(pdu, dcaf_access_request_payload_length,
                dcaf_access_request_payload);
  coap_send_confirmed(dcaf_coap_context, dcaf_coap_context->endpoint,
                      (coap_address_t *)(&cam_dst), pdu);
  coap_free(pdu);
#ifdef DCAF_TIME
  server_diff.cpu = energest_type_time(ENERGEST_TYPE_CPU) - server_last.cpu;
  printf("Time create and send cam request: %li\n", server_diff.cpu);
#endif
}


static void send_authorized_resource_request() {
#ifdef DCAF_TIME
  server_last.cpu = energest_type_time(ENERGEST_TYPE_CPU);
  server_last2.cpu = energest_type_time(ENERGEST_TYPE_CPU);
#endif

  coap_pdu_t *pdu;
  create_coap_message(handle_server_response, DCAF_RS1_URI, DCAF_RS1_URI_LENGTH,
                      1, &pdu);

  coap_send_confirmed(dcaf_coap_context, dcaf_coap_context->endpoint,
                      (coap_address_t *)(&server_dst), pdu);
  coap_free(pdu);
#ifdef DCAF_TIME
  server_diff.cpu = energest_type_time(ENERGEST_TYPE_CPU) - server_last.cpu;
  printf("Time create and send authorized resource request: %li\n",
#endif
}

static void send_unauthorized_resource_request() {
#ifdef DCAF_TIME
  server_last.cpu = energest_type_time(ENERGEST_TYPE_CPU);
#endif

  coap_pdu_t *pdu;
  create_coap_message(handle_sam_information_response, DCAF_RS1_URI,
                      DCAF_RS1_URI_LENGTH, 1, &pdu);

  coap_send_confirmed(dcaf_coap_context, dcaf_coap_context->endpoint,
                      (coap_address_t *)(&server_dst_nocrypt), pdu);
  coap_free(pdu);
#ifdef DCAF_TIME
  server_diff.cpu = energest_type_time(ENERGEST_TYPE_CPU) - server_last.cpu;
  printf("Time: create and send unauthorized resource request: %li\n",
         server_diff.cpu);
#endif
}

static int dtls_event(struct dtls_context_t *ctx, session_t *sess,
                      dtls_alert_level_t level, unsigned short code) {

#ifndef NDEBUG
  printf("call: dtls_event\n");
#endif

  if (level == 0 && code == DTLS_EVENT_CONNECTED) {
    if (uip_ipaddr_cmp(&sess->addr, &cam_dst.addr)) {
#if !defined(NDEBUG) || defined(DCAF_DEBUG)
      printf("C<->CAM: dtls connection established\n");
#endif

#if !defined(NDEBUG) || defined(DCAF_DEBUG)
      printf("C->CAM: send access request\n");
#endif
      send_cam_request();
    } else {

      server_connected = 1;
#if !defined(NDEBUG) || defined(DCAF_DEBUG)
      printf("C<->S: dtls connection established\n");
      printf("C->S: send authorized resource request /temp/1\n");
#endif
      send_authorized_resource_request();
    }
  }

  return 0;
}

PROCESS(dcaf_c1_process, "dcaf_c1_process");
AUTOSTART_PROCESSES(&dcaf_c1_process);
PROCESS_THREAD(dcaf_c1_process, ev, data) {
  PROCESS_BEGIN();
  dtls_init();
  init_network();

  if (!dcaf_dtls_context) {
    dtls_emerg("cannot create context\n");
    PROCESS_EXIT();
  }

#ifdef ENABLE_POWERTRACE
  powertrace_start(CLOCK_SECOND * 2);
#endif

  etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);
  etimer_set(&et2, TOGGLE_INTERVAL2 * CLOCK_SECOND);

  while (1) {
    PROCESS_YIELD();
    if (ev == tcpip_event) {

#ifndef NDEBUG
      printf("event: TCPIP-EVENT\n");
#endif
      handle_tcpip_event();
    } else if (etimer_expired(&et2)) {
      if (server_connected == 1) {
#if !defined(NDEBUG) || defined(DCAF_DEBUG)
        printf("C->S: send authorized resource request /temp/1\n");
#endif
        send_authorized_resource_request();
      }
      etimer_reset(&et2);

    } else if (etimer_expired(&et)) {
#if !defined(NDEBUG) || defined(DCAF_DEBUG)
      printf("C->S: send unauthorized resource request\n");
#endif
      send_unauthorized_resource_request();
    }
  }
  PROCESS_END();
}
