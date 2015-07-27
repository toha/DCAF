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


int api_get_subjects(struct mg_connection *conn) {
  LIST_HEAD(all_subjects_list, subject) subject_list;
  LIST_INIT(&subject_list);

  if (0 != dao_get_subjects(&subject_list)) {
    return MG_FALSE;
  }

  json_t *j_all_subjects = json_array();
  struct subject *np;
  LIST_FOREACH(np, &subject_list, next) {
    json_t *j_subject;
    if (0 != subject2json(np, &j_subject)) {
      return MG_FALSE;
    }
    json_array_append(j_all_subjects, j_subject);
  }

  char *subjectstxt = json_dumps(j_all_subjects, 0);
  mg_printf_data(conn, "%s", subjectstxt);
  free(subjectstxt);

  return MG_TRUE;
}

int api_get_subject(struct mg_connection *conn, char *subjectid) {
  struct subject c;
  int subject_result = dao_get_subject(subjectid, &c);

  json_t *j_subject;
  if (0 == subject_result && 0 == subject2json(&c, &j_subject)) {
    char *subjecttxt = json_dumps(j_subject, 0);
    mg_printf_data(conn, "%s", subjecttxt);
    free(subjecttxt);
    return MG_TRUE;
  } else {
    return MG_FALSE;
  }
}

int api_add_or_edit_subject(struct mg_connection *conn, char *subjectid) {
  struct subject existing_subject;
  if (0 == dao_get_subject(subjectid, &existing_subject)) {
    // existing -> update
    return api_edit_subject(conn, subjectid);
  } else {
    // new -> add
    return api_add_subject(conn, subjectid);
  }
}

int api_add_subject(struct mg_connection *conn, char *subjectid) {

  char *postdata = conn->content;
  json_error_t error;
  json_t *new_subject = json_loadb(postdata, conn->content_len, 0, &error);

  struct subject c;
  json2subject(new_subject, &c);
  int r = dao_add_subject(&c);
  if (0 == r) {
    mg_printf_data(conn, "");
    return MG_TRUE;
  } else {
    return MG_FALSE;
  }
}

int api_del_subject(struct mg_connection *conn, char *subjectid) {
  if (0 == dao_del_subject(subjectid)) {
    mg_printf_data(conn, "");
    return MG_TRUE;
  } else {
    return MG_FALSE;
  }
}

int api_edit_subject(struct mg_connection *conn, char *subjectid) {
  char *postdata = conn->content;
  json_error_t error;
  json_t *new_subject = json_loadb(postdata, conn->content_len, 0, &error);

  struct subject c;
  if (0 == json2subject(new_subject, &c) &&
      0 == dao_edit_subject(subjectid, &c)) {
    mg_printf_data(conn, "");
    return MG_TRUE;
  } else {
    return MG_FALSE;
  }
}
