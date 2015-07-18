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
}
