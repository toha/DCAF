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


int api_get_rules(struct mg_connection *conn) {
  LIST_HEAD(all_rules_list, rule) rule_list;
  LIST_INIT(&rule_list);

  if (0 != dao_get_rules(&rule_list)) {
    return MG_FALSE;
  }

  json_t *j_all_rules = json_array();
  struct rule *np;
  LIST_FOREACH(np, &rule_list, next) {
    json_t *j_rule;
    if (0 != rule2json(np, &j_rule)) {
      return MG_FALSE;
    }
    json_array_append(j_all_rules, j_rule);
  }

  char *rulestxt = json_dumps(j_all_rules, 0);
  mg_printf_data(conn, "%s", rulestxt);
  free(rulestxt);

  return MG_TRUE;
}

int api_get_rule(struct mg_connection *conn, char *ruleid) {
  struct rule r;
  json_t *j_rule;
  if (0 == dao_get_rule(ruleid, &r) && 0 == rule2json(&r, &j_rule)) {
    char *ruletxt = json_dumps(j_rule, 0);
    mg_printf_data(conn, "%s", ruletxt);
    free(ruletxt);
    return MG_TRUE;
  } else {
    return MG_FALSE;
  }
}

int api_add_or_edit_rule(struct mg_connection *conn, char *ruleid) {
  struct rule existing_rule;
  if (0 == dao_get_rule(ruleid, &existing_rule)) {
    // existing -> update
    int a = api_edit_rule(conn, ruleid);
    return a;
  } else {
    // new -> add
    return api_add_rule(conn, ruleid);
  }
}

int api_add_rule(struct mg_connection *conn, char *ruleid) {
  json_t *existing_rule;
  if (0 == dao_get_rule(ruleid, &existing_rule)) {
    printf("rule already exists\n");
    return MG_FALSE;
  }
  char *postdata = conn->content;
  json_error_t error;
  json_t *j_new_rule = json_loadb(postdata, conn->content_len, 0, &error);

  struct rule new_rule;
  if (0 == json2rule(j_new_rule, &new_rule) && 0 == dao_add_rule(&new_rule)) {
    mg_printf_data(conn, "");
    return MG_TRUE;
  } else {
    return MG_FALSE;
  }
}

int api_del_rule(struct mg_connection *conn, char *ruleid) {
  if (0 == dao_del_rule(ruleid)) {
    mg_printf_data(conn, "");
    return MG_TRUE;
  } else {
    return MG_FALSE;
  }
}

int api_edit_rule(struct mg_connection *conn, char *ruleid) {
  char *postdata = conn->content;
  json_error_t error;
  json_t *j_new_rule = json_loadb(postdata, conn->content_len, 0, &error);
  struct rule new_rule;
  if (0 == json2rule(j_new_rule, &new_rule) &&
      0 == dao_edit_rule(ruleid, new_rule)) {
    mg_printf_data(conn, "");
    return MG_TRUE;
  } else {
    return MG_FALSE;
  }
}


int api_get_allrs(struct mg_connection *conn) {
  LIST_HEAD(all_rs_list, resource_server) rs_list;
  LIST_INIT(&rs_list);

  if (0 != dao_get_allrs(&rs_list)) {
    return MG_FALSE;
  }

  json_t *j_all_rs = json_array();
  struct resource_server *np;
  LIST_FOREACH(np, &rs_list, next) {
    json_t *j_rs;
    if (0 != resource_server2json(np, &j_rs)) {
      return MG_FALSE;
    }
    json_array_append(j_all_rs, j_rs);
  }

  char *rstxt = json_dumps(j_all_rs, 0);
  mg_printf_data(conn, "%s", rstxt);
  free(rstxt);

  return MG_TRUE;
}

int api_get_rs(struct mg_connection *conn, char *rsid) {
  json_t *j_rs;
  struct resource_server rs;
  if (0 == dao_get_rs(rsid, &rs) && 0 == resource_server2json(&rs, &j_rs)) {
    char *rstxt = json_dumps(j_rs, 0);
    mg_printf_data(conn, "%s", rstxt);
    free(rstxt);
    return MG_TRUE;
  } else {
    return MG_FALSE;
  }
}

int api_add_or_edit_rs(struct mg_connection *conn, char *rsid) {
  struct resource_server existing_rs;
  if (0 == dao_get_rs(rsid, &existing_rs)) {
    // existing -> update
    return api_edit_rs(conn, rsid);
  } else {
    // new -> add
    return api_add_rs(conn, rsid);
  }
}


int api_add_rs(struct mg_connection *conn, char *rsid) {
  json_t *existing_rs;
  if (0 == dao_get_rs(rsid, &existing_rs)) {
    printf("rs already exists\n");
    return MG_FALSE;
  }
  char *postdata = conn->content;
  json_error_t error;
  json_t *j_new_rs = json_loadb(postdata, conn->content_len, 0, &error);

  struct resource_server new_rs;
  if (0 == json2resource_server(j_new_rs, &new_rs) &&
      0 == dao_add_rs(&new_rs)) {
    mg_printf_data(conn, "");
    return MG_TRUE;
  } else {
    return MG_FALSE;
  }
}

int api_del_rs(struct mg_connection *conn, char *rsid) {
  if (0 == dao_del_rs(rsid)) {
    mg_printf_data(conn, "");
    return MG_TRUE;
  } else {
    return MG_FALSE;
  }
}

int api_edit_rs(struct mg_connection *conn, char *rsid) {
  char *postdata = conn->content;
  json_error_t error;
  json_t *j_new_rs = json_loadb(postdata, conn->content_len, 0, &error);
  struct resource_server new_rs;
  if (0 == json2resource_server(j_new_rs, &new_rs) &&
      0 == dao_edit_rs(rsid, &new_rs)) {
    mg_printf_data(conn, "");
    return MG_TRUE;
  } else {
    return MG_FALSE;
  }
}


int api_get_tickets(struct mg_connection *conn) {
  LIST_HEAD(all_tickets_list, dcaf_ticket) ticket_list;
  LIST_INIT(&ticket_list);

  if (0 != dao_get_tickets(&ticket_list)) {
    return MG_FALSE;
  }

  json_t *j_all_tickets = json_array();
  struct dcaf_ticket *np;
  LIST_FOREACH(np, &ticket_list, next) {
    json_t *j_ticket;
    if (0 != ticket2json(np, &j_ticket)) {
      return MG_FALSE;
    }
    json_array_append(j_all_tickets, j_ticket);
  }

  char *ticketstxt = json_dumps(j_all_tickets, 0);
  mg_printf_data(conn, "%s", ticketstxt);
  free(ticketstxt);

  return MG_TRUE;
}

int api_get_ticket(struct mg_connection *conn, char *ticketid) {
  json_t *j_ticket;
  struct dcaf_ticket ticket;
  if (0 == dao_get_ticket(ticketid, &ticket) &&
      0 == ticket2json(&ticket, &j_ticket)) {
    char *tickettxt = json_dumps(j_ticket, 0);
    mg_printf_data(conn, "%s", tickettxt);
    free(tickettxt);
    return MG_TRUE;
  } else {
    return MG_FALSE;
  }
}
