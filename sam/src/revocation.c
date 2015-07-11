#include "revocation.h"
#include <libcoap/coap.h>
#include "lib/coap-client/client.h"

#define REVOCATION_MAX_WAIT_SEC 600
#define COAP_MEDIATYPE_APPLICATION_DCAF 70

#define DCAF_REVOCATION_URI_PREFIX1 "coaps://["
#define DCAF_REVOCATION_URI_PREFIX2 "]:5684/revocations"

#define COAP_APPLICATION_SEND_SECURE 0x01
#define DCAF_REVOCATION_MSG_MAG_LENGTH 255

void my_coap_response_handler(struct coap_context_t *ctx,
                              const coap_endpoint_t *local_interface,
                              const coap_address_t *remote, coap_pdu_t *sent,
                              coap_pdu_t *received, const coap_tid_t id) {
  // Nothing to do async cause coap-client is working synchronously (internally)
}

int send_revocation(struct dcaf_revocation *revocation,
                    coap_pdu_t *received_pdu) {
  printf("Send Revocation\n");

  struct resource_server rs;
  if (0 != dao_get_rs(revocation->ticket.face.AIs[0].rs, &rs)) {
    printf("server not found\n");
    return -1;
  }

  // build payload
  unsigned char revocation_msg_cbor[DCAF_REVOCATION_MSG_MAG_LENGTH];
  cbor_stream_t revocation_msg_cbor_stream;
  cbor_init(&revocation_msg_cbor_stream, revocation_msg_cbor,
            sizeof(revocation_msg_cbor));

  cbor_serialize_array(&revocation_msg_cbor_stream, 1); //

  cbor_serialize_int(&revocation_msg_cbor_stream,
                     revocation->ticket.face.sequence_number);

  size_t uri_length = strlen(DCAF_REVOCATION_URI_PREFIX1) + strlen(rs.id) +
                      strlen(DCAF_REVOCATION_URI_PREFIX2);

  char *rs_uri = (char *)malloc(sizeof(char) * uri_length + 1);
  strncpy(rs_uri, DCAF_REVOCATION_URI_PREFIX1,
          strlen(DCAF_REVOCATION_URI_PREFIX1));
  int idx = strlen(DCAF_REVOCATION_URI_PREFIX1);
  strncpy(&rs_uri[idx], rs.id, strlen(rs.id));
  idx += strlen(rs.id);
  strncpy(&rs_uri[idx], DCAF_REVOCATION_URI_PREFIX2,
          strlen(DCAF_REVOCATION_URI_PREFIX2));
  idx += strlen(DCAF_REVOCATION_URI_PREFIX2);
  rs_uri[idx] = '\0';

  size_t rs_secret_size = 0;
  unsigned char *rs_secret =
      base64_decode(rs.secret, strlen(rs.secret), &rs_secret_size);

  int a = coap_client_run(&my_coap_response_handler, &received_pdu, 2, rs_uri,
                          "sam", 3, rs_secret, rs_secret_size,
                          revocation_msg_cbor, revocation_msg_cbor_stream.pos);

  free(rs_secret);
  if (0 == a && received_pdu) {
    printf("Process incoming %d.%02d response:\n",
           (received_pdu->hdr->code >> 5), received_pdu->hdr->code & 0x1F);
    free(rs_uri);
    if (COAP_RESPONSE_200 == received_pdu->hdr->code) {
      printf("Revocation succesful!\n");
      return 0;
    } else {
      printf("Revocation failed!\n");
      return -1;
    }
  }
}

int revocation_run() {
  LIST_HEAD(all_revocations_list, dcaf_revocation) revocation_list;
  LIST_INIT(&revocation_list);
  if (0 != dao_get_revocations(&revocation_list)) {
    return MG_FALSE;
  }
  struct dcaf_revocation *np;
  LIST_FOREACH(np, &revocation_list, next) {
    // skip delivered revocations
    if (0 != np->delivery_time) {
      continue;
    }

    // exponential backoff timer
    int diff_last = get_timestamp_secs() - np->last_try;
    int wait_time = power(2, np->tries);
    if (wait_time > REVOCATION_MAX_WAIT_SEC) {
      wait_time = REVOCATION_MAX_WAIT_SEC;
    }
    if (wait_time > diff_last) {
      continue;
    }

    printf("Waittime (%d) exceeded for revocation %s - try to send!\n", wait_time,
           np->ticket.id);

    coap_pdu_t *received_pdu;
    int send_res = send_revocation(np, received_pdu);

    // update revocation
    np->tries++;

    if (0 == send_res) {
      printf("Send revocation successful\n");
      np->delivery_time = get_timestamp_secs();

    } else {
      np->last_try = get_timestamp_secs();
    }

    pthread_mutex_lock(&dao_mutex);
    if (0 != dao_edit_revocation(np->ticket.id, np)) {
      pthread_mutex_unlock(&dao_mutex);
      printf("Update revocation error!\n");
      return 1;
    }
    pthread_mutex_unlock(&dao_mutex);
  }
  return 0;
}

int init_revocation_thread() {
  while (1) {
    revocation_run();
    sleep(1);
  }
}
