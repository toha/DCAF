#include "commissioning.h"
#include <libcoap/coap.h>
#include "lib/coap-client/client.h"

#define DCAF_TYPE_KEY 0x0B
#define DCAF_TYPE_SAM_URI 0x0C

#define COAP_APPLICATION_SEND_SECURE 0x01
#define DCAF_COMMISSIONING_MSG_MAG_LENGTH 255

void coap_comissioning_hndl(struct coap_context_t *ctx,
                            const coap_endpoint_t *local_interface,
                            const coap_address_t *remote, coap_pdu_t *sent,
                            coap_pdu_t *received, const coap_tid_t id) {
  // Nothing to do async cause coap-client is working synchronously internally
}

int try_send_commissioning(json_t *commissioning_msg) {
  printf("Send commissioning\n");

  json_t *j_rs_uri = json_object_get(commissioning_msg, "server_uri");
  json_t *j_ticket_json = json_object_get(commissioning_msg, "ticket");
  json_t *j_new_key = json_object_get(commissioning_msg, "new_key");
  json_t *j_new_sam = json_object_get(commissioning_msg, "new_sam");

  if (!j_rs_uri || !j_ticket_json || !j_new_sam || !j_new_key ||
      !json_is_string(j_rs_uri) || !json_is_object(j_ticket_json) ||
      !json_is_string(j_new_key) || !json_is_string(j_new_sam)) {
    return -1;
  }

  char *rs_uri = json_string_value(j_rs_uri);
  char *new_sam = json_string_value(j_new_sam);
  char *new_key_b64 = json_string_value(j_new_key);
  size_t new_key_size = 0;
  unsigned char *new_key =
      base64_decode(new_key_b64, strlen(new_key_b64), &new_key_size);

  if (0 >= new_key_size) {
    printf("Invalid B64 Key\n");
    return -2;
  }

  struct dcaf_ticket commissioning_ticket;
  if (0 != json2ticket(j_ticket_json, &commissioning_ticket)) {
    printf("Error on json2ticket\n");
    return -3;
  }

  hexDump("Ticket Verifier", commissioning_ticket.verifier,
          commissioning_ticket.verifier_size);

  // Build Payload
  unsigned char commissioning_msg_cbor[DCAF_COMMISSIONING_MSG_MAG_LENGTH];
  cbor_stream_t commissioning_msg_cbor_stream;
  cbor_init(&commissioning_msg_cbor_stream, commissioning_msg_cbor,
            sizeof(commissioning_msg_cbor));

  cbor_serialize_map(&commissioning_msg_cbor_stream, 2);
  cbor_serialize_int(&commissioning_msg_cbor_stream, DCAF_TYPE_KEY);
  cbor_serialize_byte_string_len(&commissioning_msg_cbor_stream, new_key,
                                 new_key_size);
  cbor_serialize_int(&commissioning_msg_cbor_stream, DCAF_TYPE_SAM_URI);
  cbor_serialize_byte_string(&commissioning_msg_cbor_stream, new_sam);
  hexDump("Cbor Payload Commissioning", commissioning_msg_cbor,
          commissioning_msg_cbor_stream.pos);

  unsigned char ticket_cborface[DCAF_MAX_FACE];
  cbor_stream_t ticket_cbor_face_stream;
  cbor_init(&ticket_cbor_face_stream, ticket_cborface, sizeof(ticket_cborface));
  size_t ticket_cbor_face_size =
      ticket_face2cbor(&commissioning_ticket.face, &ticket_cbor_face_stream);

  hexDump("Cbor Face of Commissioning Ticket", ticket_cborface,
          ticket_cbor_face_stream.pos);
  // Try Commissioning Request
  coap_pdu_t *received_pdu;
  int a = coap_client_run(
      &coap_comissioning_hndl, &received_pdu, 2, rs_uri, ticket_cborface,
      ticket_cbor_face_stream.pos, commissioning_ticket.verifier,
      commissioning_ticket.verifier_size, commissioning_msg_cbor,
      commissioning_msg_cbor_stream.pos);

  free(new_key);
  if (0 == a && received_pdu) {
    printf("Process incoming %d.%02d response:\n",
           (received_pdu->hdr->code >> 5), received_pdu->hdr->code & 0x1F);
    if (COAP_RESPONSE_200 == received_pdu->hdr->code) {
      printf("Commissioning succesful!\n");
      return 0;
    } else {
      printf("Commissioning failed!\n");
      return -1;
    }
  }

  return a;
}
