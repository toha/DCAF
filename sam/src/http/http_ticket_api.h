#ifndef _HTTP_TICKET_API_H_
#define _HTTP_TICKET_API_H_

#include "http_srv.h"
#include "../common.h"
#include "../lib/mongoose/mongoose.h"
#include "../dao.h"
#include "../messages.h"
#include "../models.h"
#include "../tickets.h"
#include <jansson.h>
#include <uriparser/Uri.h>
#include <tinydtls/tinydtls.h>
#include <tinydtls/dtls.h>
#include <tinydtls/hmac.h>
#include <tinydtls/sha2/sha2.h>
#include "../lib/riot-cbor/cbor.h"

int handle_ticket_request_message(struct mg_connection *conn, enum mg_event ev);
#endif
