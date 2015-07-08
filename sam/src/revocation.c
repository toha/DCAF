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
