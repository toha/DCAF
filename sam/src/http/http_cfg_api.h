#ifndef _HTTP_CFG_API_H_
#define _HTTP_CFG_API_H_

#include "../common.h"
#include "../lib/mongoose/mongoose.h"
#include "../dao.h"
#include <jansson.h>

int handle_resource_owner_request(struct mg_connection *conn, enum mg_event ev);
int ro_api_init();

int api_get_ticket(struct mg_connection *conn, char *ticketid);
int api_add_ticket(struct mg_connection *conn, char *ticketid);
int api_add_revocation(struct mg_connection *conn);
#endif
