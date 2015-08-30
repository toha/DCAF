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

static ssize_t dcaf_network_send(struct coap_context_t *c,
                                 const coap_endpoint_t *local_interface,
                                 const coap_address_t *dst, unsigned char *data,
                                 size_t datalen) {
#ifndef NDEBUG
  printf("call: dcaf_network_send\n");
#endif
  uint16_t local_port = uip_htons(local_interface->addr.port);
  uint16_t remote_port = uip_htons(dst->port);

  if (COAP_DEFAULT_PORT == remote_port) {
    return coap_network_send(c, local_interface, dst, data, datalen);
  } else {
    session_t ss;
    dtls_session_init(&ss);
    uip_ipaddr_copy(&ss.addr, &dst->addr);
    ss.ifindex = local_interface->ifindex;
    ss.port = dst->port;
    ss.size = sizeof(ss.addr) + sizeof(ss.port);

    return dtls_write(dcaf_dtls_context, &ss, (uint8 *)data, datalen);
  }
}

static int read_from_peer(struct dtls_context_t *ctx, session_t *session,
                          uint8 *data, size_t len) {
#ifndef NDEBUG
  printf("call: read_from_peer\n");
#endif

  coap_packet_t *packet_state;
  packet_state = (coap_packet_t *)custom_coap_malloc_packet();
  coap_address_init(&(packet_state)->dst); /* the local interface address */
  coap_address_init(&(packet_state)->src); /* the remote peer */

  uip_ipaddr_copy(&packet_state->src.addr, &UIP_IP_BUF->srcipaddr);
  packet_state->src.port = UIP_UDP_BUF->srcport;
  uip_ipaddr_copy(&packet_state->dst.addr, &UIP_IP_BUF->destipaddr);
  packet_state->dst.port = UIP_UDP_BUF->destport;

  packet_state->length = len;
  memcpy(&packet_state->payload, data, len);

  int a = coap_handle_message(dcaf_coap_context, dcaf_coap_context->endpoint,
                              packet_state);

  coap_free_packet(packet_state);

  return a;
}

static int send_to_peer(struct dtls_context_t *ctx, session_t *session,
                        uint8 *data, size_t len) {

  struct uip_udp_conn *conn = (struct uip_udp_conn *)dtls_get_app_data(ctx);

  uip_ipaddr_copy(&conn->ripaddr, &session->addr);
  conn->rport = session->port;

#ifndef NDEBUG
  PRINTF("send to ");
  PRINT6ADDR(&conn->ripaddr);
  PRINTF(":%u\n", uip_ntohs(conn->rport));
#endif

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

  static session_t session;
  uip_ipaddr_copy(&session.addr, &UIP_IP_BUF->srcipaddr);
  session.port = UIP_UDP_BUF->srcport;
  session.size = sizeof(session.addr) + sizeof(session.port);

  ((char *)uip_appdata)[uip_datalen()] = 0;
#ifndef NDEBUG
  PRINTF("client received message from ");
  PRINT6ADDR(&session.addr);
  PRINTF(":%d\n", uip_ntohs(session.port));
#endif

  dtls_handle_message(ctx, &session, uip_appdata, uip_datalen());
}

static void handle_tcpip_event() {

#ifndef NDEBUG
  printf("call: handle_tcpip_event\n");
#endif

  if (uip_newdata()) {
    uint16_t srcport = uip_htons(UIP_UDP_BUF->srcport);
    if (COAP_DEFAULT_PORT == srcport) {
      coap_read(dcaf_coap_context);
    } else {
      dtls_handle_read(dcaf_dtls_context);
    }
  }
}

static inline void coap_message_handler(struct coap_context_t *ctx,
                                        const coap_endpoint_t *local_interface,
                                        const coap_address_t *remote,
                                        coap_pdu_t *sent, coap_pdu_t *received,
                                        const coap_tid_t id) {
  msg_state.hnd(ctx, local_interface, remote, sent, received, id);
}

static int dtls_event(struct dtls_context_t *ctx, session_t *sess,
                      dtls_alert_level_t level, unsigned short code);

static dtls_handler_t dtls_cb = {
    .write = send_to_peer,
    .read = read_from_peer,
    .event = dtls_event,
    .get_psk_key = get_psk_key,
};

static void init_network() {

#ifndef NDEBUG
  printf("call: init_network\n");
#endif

  uip_ipaddr_t ipaddr;

  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0x200, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

  uip_ip6addr(&cam_dst.addr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0x1);
  cam_dst.port = uip_htons(COAPS_DEFAULT_PORT);
  cam_dst.size = sizeof(cam_dst.addr) + sizeof(cam_dst.port);

  uip_ip6addr(&server_dst.addr, 0xaaaa, 0, 0, 0, 0x200, 0, 0, 0x2);
  server_dst.port = uip_htons(COAPS_DEFAULT_PORT);
  server_dst.size = sizeof(server_dst.addr) + sizeof(server_dst.port);

  uip_ip6addr(&server_dst_nocrypt.addr, 0xaaaa, 0, 0, 0, 0x200, 0, 0, 0x2);
  server_dst_nocrypt.port = uip_htons(COAP_DEFAULT_PORT);
  server_dst_nocrypt.size =
      sizeof(server_dst_nocrypt.addr) + sizeof(server_dst_nocrypt.port);

  // dtls connection and context. first for cam
  dcaf_dtls_conn = udp_new(&cam_dst.addr, 0, NULL);
  udp_bind(dcaf_dtls_conn, cam_dst.port);

  dtls_set_log_level(DTLS_LOG_DEBUG);

  dcaf_dtls_context = dtls_new_context(dcaf_dtls_conn);
  if (dcaf_dtls_context) {
    dtls_set_handler(dcaf_dtls_context, &dtls_cb);
  }

  coap_address_t ca;
  coap_address_init(&ca);
  uip_ipaddr_copy(&ca.addr, &ipaddr);
  ca.port = uip_htons(20221);
  ca.size = sizeof(ca.addr) + sizeof(ca.port);

  dcaf_coap_context = coap_new_context(&ca);
  dcaf_coap_context->network_send = dcaf_network_send;

  coap_register_response_handler(dcaf_coap_context, coap_message_handler);
}

static int create_pdu(coap_context_t *ctx, char *uri, size_t uri_length,
                      method_t method, coap_pdu_t **pdu) {

  size_t segmentbufsize = 255;
  unsigned char segmentbuf[segmentbufsize];
  unsigned char *segmentbufptr = segmentbuf;

  coap_uri_t curi;

  if (!(*pdu = coap_new_pdu())) {
    return -1;
  }

  (*pdu)->hdr->type = COAP_MESSAGE_CON;
  (*pdu)->hdr->id = coap_new_message_id(ctx);
  (*pdu)->hdr->code = method;

  (*pdu)->hdr->token_length = the_token.length;
  if (!coap_add_token(*pdu, the_token.length, the_token.s)) {
    return -2;
  }

  if (0 != coap_split_uri(uri, uri_length, &curi)) {
    return -3;
  }

  int split_path_res = coap_split_path(curi.path.s, curi.path.length,
                                       segmentbuf, &segmentbufsize);
  if (0 > split_path_res) {
    return -4;
  }

  while (split_path_res--) {
    coap_add_option((*pdu), COAP_OPTION_URI_PATH,
                    COAP_OPT_LENGTH(segmentbufptr),
                    COAP_OPT_VALUE(segmentbufptr));
    segmentbufptr += COAP_OPT_SIZE(segmentbufptr);
  }

  unsigned char buf[3];
  coap_add_option((*pdu), COAP_OPTION_CONTENT_TYPE,
                  coap_encode_var_bytes(buf, COAP_MEDIATYPE_APPLICATION_DCAF),
                  buf);

  return 0;
}

static void
create_coap_message(void (*hnd)(struct coap_context_t *ctx,
                                const coap_endpoint_t *local_interface,
                                const coap_address_t *remote, coap_pdu_t *sent,
                                coap_pdu_t *received, const coap_tid_t id),
                    char *uri, size_t uri_length, method_t method,
                    coap_pdu_t **pdu) {
  create_pdu(dcaf_coap_context, uri, uri_length, method, pdu);

  msg_state.msg_id = (*pdu)->hdr->id;
  msg_state.hnd = hnd;
}

static void connect_server() {
  dcaf_dtls_conn = udp_new(&server_dst.addr, 0, NULL);
  dcaf_dtls_context->app = dcaf_dtls_conn;
  dtls_connect(dcaf_dtls_context, &server_dst);
}

static void handle_cam_response(struct coap_context_t *ctx,
                                const coap_endpoint_t *local_interface,
                                const coap_address_t *remote, coap_pdu_t *sent,
                                coap_pdu_t *received, const coap_tid_t id) {
#ifdef DCAF_TIME
  server_last.cpu = energest_type_time(ENERGEST_TYPE_CPU);
#endif

  size_t payload_len;
  unsigned char *payload;

  if (!coap_get_data(received, &payload_len, &payload) || 0 >= payload_len) {
    return;
  }

  const cn_cbor *camcb;
  camcb = cn_cbor_decode((char *)payload, payload_len, NULL);

  if (!camcb || camcb->type != CN_CBOR_MAP) {
#ifndef NDEBUG
    printf("no cbor ticket found\n");
#endif
    return;
  }

#if !defined(NDEBUG) || defined(DCAF_DEBUG)
  printf("C<-CAM: got ticket from cam\n");
#endif

#ifndef NDEBUG
  printf("payload (%d Byte):\n", payload_len);
#endif

  const cn_cbor *f = cn_cbor_mapget_int(camcb, DCAF_TYPE_F);
  const cn_cbor *v = cn_cbor_mapget_int(camcb, DCAF_TYPE_V);
  if (!f || !v) {
    return;
  }

  dcaf_ticket_face_length =
      cbor_encoder_write(dcaf_ticket_face, 0, DCAF_MAX_FACE, f);

  dcaf_ticket_verifier_length = v->length;
  memcpy(&dcaf_ticket_verifier, v->v.str, v->length);

#ifndef NDEBUG
  printf("ticket face (%d Byte):\n", dcaf_ticket_face_length);
  hexdump(dcaf_ticket_face, dcaf_ticket_face_length);
  printf("verifier (%d Byte):\n", dcaf_ticket_face_length);
  hexdump(dcaf_ticket_verifier, dcaf_ticket_verifier_length);
#endif
#ifdef DCAF_TIME
  server_diff.cpu = energest_type_time(ENERGEST_TYPE_CPU) - server_last.cpu;
  printf("Time: Handle CAM response (coap + create face): %li\n",
         server_diff.cpu);
#endif

  // Got a Ticket. Start DTLS-Handshake with Server
  dtls_close(dcaf_dtls_context, &cam_dst);
  dtls_free_context(dcaf_dtls_context);

#if !defined(NDEBUG) || defined(DCAF_DEBUG)
  printf("C->S: start dtls handshake\n");
#endif
  connect_server();
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
