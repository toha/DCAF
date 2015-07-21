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
