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


int revocation_run() {
  LIST_HEAD(all_revocations_list, dcaf_revocation) revocation_list;
  LIST_INIT(&revocation_list);
  if (0 != dao_get_revocations(&revocation_list)) {
    return MG_FALSE;
  }
  struct dcaf_revocation *np;
  LIST_FOREACH(np, &revocation_list, next) {
    // skip delivered revocations

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
