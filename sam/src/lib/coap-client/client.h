#ifndef _COAP_CLIENT_H_
#define _COAP_CLIENT_H_

#include <libcoap/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/fcntl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <libcoap/coap.h>

typedef void (*sam_coap_response_handler_t)(
    struct coap_context_t *ctx, const coap_endpoint_t *local_interface,
    const coap_address_t *remote, coap_pdu_t *sent, coap_pdu_t *received,
    const coap_tid_t id);
#endif
