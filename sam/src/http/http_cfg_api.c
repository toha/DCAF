#include "http_cfg_api.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <pthread.h>

#define SHA1LEN 20

int ro_api_init() { return 0; }

/**
* HTTP-Handler for all Requests below /cfg/...
*/
int handle_resource_owner_request(struct mg_connection *conn,
                                  enum mg_event ev) {
  int mgflag = MG_FALSE;

  pthread_mutex_lock(&dao_mutex);

  if (!strcmp(conn->uri, "/cfg/subjects")) {
    mgflag = api_get_subjects(conn);
  } else if (!strncmp(conn->uri, "/cfg/subjects/", 14)) {
    // split subjectname from uri
    char *subjectid = (char *)malloc(strlen(conn->uri) - 14 + 1);
    subjectid = strcpy(subjectid, conn->uri + 14);

    if (!strcmp(conn->request_method, "GET")) {
      mgflag = api_get_subject(conn, subjectid);
    } else if (!strcmp(conn->request_method, "PUT")) {
      mgflag = api_add_or_edit_subject(conn, subjectid);
    } else if (!strcmp(conn->request_method, "DELETE")) {
      mgflag = api_del_subject(conn, subjectid);
    }

    free(subjectid);
  } else if (!strcmp(conn->uri, "/cfg/rules")) {
    mgflag = api_get_rules(conn);
  } else if (!strncmp(conn->uri, "/cfg/rules/", 11)) {
    // split rule from uri
    char *rule = (char *)malloc(strlen(conn->uri) - 11 + 1);

    rule = strcpy(rule, conn->uri + 11);

    if (!strcmp(conn->request_method, "GET")) {
      mgflag = api_get_rule(conn, rule);
    } else if (!strcmp(conn->request_method, "PUT")) {
      mgflag = api_add_or_edit_rule(conn, rule);
    } else if (!strcmp(conn->request_method, "DELETE")) {
      mgflag = api_del_rule(conn, rule);
    }

    free(rule);
  } else if (!strcmp(conn->uri, "/cfg/rs")) {
    mgflag = api_get_allrs(conn);
  } else if (!strncmp(conn->uri, "/cfg/rs/", 8)) {
    // split rs from uri
    char *rs = (char *)malloc(strlen(conn->uri) - 8 + 1);
    rs = strcpy(rs, conn->uri + 8);

    if (!strcmp(conn->request_method, "GET")) {
      mgflag = api_get_rs(conn, rs);
    } else if (!strcmp(conn->request_method, "PUT")) {
      mgflag = api_add_or_edit_rs(conn, rs);
    } else if (!strcmp(conn->request_method, "DELETE")) {
      mgflag = api_del_rs(conn, rs);
    }

    free(rs);
  } else if (!strcmp(conn->uri, "/cfg/tickets")) {
    mgflag = api_get_tickets(conn);
  } else if (!strncmp(conn->uri, "/cfg/tickets/", 13)) {
    char *ticket = (char *)malloc(strlen(conn->uri) - 13 + 1);
    ticket = strcpy(ticket, conn->uri + 13);

    if (!strcmp(conn->request_method, "GET")) {
      mgflag = api_get_ticket(conn, ticket);
    } else if (!strcmp(conn->request_method, "PUT")) {
      // Tickets are not added over the REST API
      mgflag = MG_FALSE;
    }
    free(ticket);
  } else if (!strcmp(conn->uri, "/cfg/revocations")) {
    if (!strcmp(conn->request_method, "GET")) {
      mgflag = api_get_revocations(conn);
    } else if (!strcmp(conn->request_method, "POST")) {
      mgflag = api_add_revocation(conn);
    }

  } else if (!strcmp(conn->uri, "/cfg/commissioning")) {
    if (!strcmp(conn->request_method, "POST")) {
      mgflag = api_try_commissioning(conn);
    }
  } else {
    mgflag = MG_FALSE;
  }

  pthread_mutex_unlock(&dao_mutex);

  return mgflag;
}
