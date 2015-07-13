#ifndef _HTTP_SRV_H_
#define _HTTP_SRV_H_

#include "../common.h"
#include "../lib/mongoose/mongoose.h"
#include "http_cfg_api.h"
#include "http_ticket_api.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#define SHA1LEN 20

// start webserver
void startweb(void);

char *get_client_cert_b64_fingerprint(struct mg_connection *conn);

#endif
