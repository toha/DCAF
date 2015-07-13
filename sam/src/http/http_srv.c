#include "http_srv.h"


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
