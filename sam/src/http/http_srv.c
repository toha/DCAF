#include "http_srv.h"

static int event_handler(struct mg_connection *conn, enum mg_event ev) {

  if (ev == MG_HTTP_ERROR) {
    return MG_FALSE; // Authorize all requests (NO HTTP-AUTH)
  }
  if (ev == MG_AUTH) {
    return MG_TRUE; // Authorize all requests (NO HTTP-AUTH)
  } else if (ev == MG_REQUEST) {

    if (!strncmp(conn->uri, "/ep", 3) &&
        !strcmp(conn->request_method, "POST")) {
      return handle_ticket_request_message(conn, ev);
    } else if (!strncmp(conn->uri, "/cfg/", 5)) {

      // ROP AUTH
      char *req_b64_fngpnt = get_client_cert_b64_fingerprint(conn);
      if (!strcmp(req_b64_fngpnt, dao_get_cfg_rop_fingerprint())) {
        // Fingerprint ok - rop authenticated
        return handle_resource_owner_request(conn, ev);
      } else {
        // Fingerprint NOT ok
        return http_send_error(conn, 403, "");
      }

    } else {
      return MG_FALSE;
    }
  } else {
    return MG_FALSE; // Rest of the events are not processed
  }
}

void startweb(void) {
  struct mg_server *server = mg_create_server(NULL, event_handler);
  mg_set_option(server, "document_root", "../src/http/html");
  mg_set_option(server, "listening_port", dao_get_cfg_listen_str());
  printf("listening on: %s\n", dao_get_cfg_listen_str());

  for (;;) {
    mg_poll_server(server, 1000); // Infinite loop, Ctrl-C to stop
  }
  mg_destroy_server(&server);
}

char *get_client_cert_b64_fingerprint(struct mg_connection *conn) {
  X509 *cert = SSL_get_peer_certificate(conn->ssl);
  STACK_OF(X509) *sk = sk_X509_new_null();
  sk_X509_push(sk, cert);

  if (!cert) {
    return "";
  }

  char buf[SHA1LEN];
  const EVP_MD *digest = EVP_sha1();
  unsigned len;
  int rc = X509_digest(cert, digest, (unsigned char *)buf, &len);
  if (rc == 0 || len != SHA1LEN) {
    return "";
  }
  // Fingerprint to b64
  size_t b64_length = 0;
  char *b64_fingerprint = base64_encode(buf, SHA1LEN, &b64_length);
  b64_fingerprint[b64_length] = '\0';

  X509_free(cert);

  return b64_fingerprint;
}
