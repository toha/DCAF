#include "dao.h"

struct resource_cache cache;

int dao_init() { dao_reload_cache(); }

int dao_reload_cache() {
  // reload subjects
  char *samcfg_txt = NULL;
  read_file("samcfg.json", &samcfg_txt);

  json_error_t error;
  cache.samcfg = json_loads(samcfg_txt, 0, &error);
  free(samcfg_txt);

  // reload subjects
  char *subject_txt = NULL;
  read_file("subjects.json", &subject_txt);

  cache.subjects = json_loads(subject_txt, 0, &error);
  free(subject_txt);

  // reload rules
  char *rules_txt = NULL;
  read_file("rules.json", &rules_txt);

  cache.rules = json_loads(rules_txt, 0, &error);
  free(rules_txt);

  // reload resource_servers
  char *rs_txt = NULL;
  read_file("rs.json", &rs_txt);

  cache.resource_servers = json_loads(rs_txt, 0, &error);
  free(rs_txt);

  // reload tickets
  char *ticket_txt = NULL;
  read_file("tickets.json", &ticket_txt);

  cache.tickets = json_loads(ticket_txt, 0, &error);
  free(ticket_txt);

  // reload tickets
  char *revocations_txt = NULL;
  read_file("revocations.json", &revocations_txt);

  cache.revocations = json_loads(revocations_txt, 0, &error);
  free(revocations_txt);

  return 0;
}

int dao_write_cache() {
  char *samcfgtxt = json_dumps(cache.samcfg, 0);
  write_file("samcfg.json", samcfgtxt);

  char *subjectstxt = json_dumps(cache.subjects, 0);
  write_file("subjects.json", subjectstxt);

  char *rulestxt = json_dumps(cache.rules, 0);
  write_file("rules.json", rulestxt);

  char *rstxt = json_dumps(cache.resource_servers, 0);
  write_file("rs.json", rstxt);

  char *tickettxt = json_dumps(cache.tickets, 0);
  write_file("tickets.json", tickettxt);

  char *revocationstxt = json_dumps(cache.revocations, 0);
  write_file("revocations.json", revocationstxt);

  return 0;
}

int dao_get_samcfg(struct sam_cfg *c) {
  json_t *j_rop_fp = json_object_get(cache.samcfg, "rop_fingerprint");
  json_t *j_lifetime = json_object_get(cache.samcfg, "global_lifetime");
  json_t *j_listen = json_object_get(cache.samcfg, "listen_str");
  if (!j_rop_fp || !j_lifetime || !json_is_string(j_rop_fp) ||
      !json_is_number(j_lifetime) || !j_listen || !json_is_string(j_listen)) {
    return -1;
  }

  c->rop_fingerprint = json_string_value(j_rop_fp);
  c->global_lifetime = json_integer_value(j_lifetime);
  c->listen_str = json_string_value(j_listen);

  return 0;
}

unsigned int dao_get_cfg_lifetime() {
  json_t *j_lifetime = json_object_get(cache.samcfg, "global_lifetime");
  if (!j_lifetime || !json_is_number(j_lifetime)) {
    return 3600;
  }

  return json_integer_value(j_lifetime);
}

char *dao_get_cfg_rop_fingerprint() {
  json_t *j_rop_fp = json_object_get(cache.samcfg, "rop_fingerprint");
  if (!j_rop_fp || !json_is_string(j_rop_fp)) {
    return "invalid";
  }

  return json_string_value(j_rop_fp);
}

char *dao_get_cfg_listen_str() {
  json_t *j_listen = json_object_get(cache.samcfg, "listen_str");
  if (!j_listen || !json_is_string(j_listen)) {
    return "ssl://[aaaa::1]:8080:sam.pem:ca.crt";
  }

  return json_string_value(j_listen);
}

int dao_get_subjects(LIST_HEAD(, subject) * subjects) {
  size_t index;
  json_t *value;
  json_array_foreach(cache.subjects, index, value) {
    struct subject *c = malloc(sizeof(struct subject));
    if (0 != json2subject(value, c)) {
      return 1;
    }
    LIST_INSERT_HEAD(subjects, c, next);
  }
  return 0;
}

int dao_get_subject(char *fingerprint, struct subject *c) {
  json_t *j_subject;
  int i;
  for (i = 0; i < json_array_size(cache.subjects); i++) {
    json_t *subject_obj = json_array_get(cache.subjects, i);
    if (!subject_obj || !json_is_object(subject_obj)) {
      return 2;
    }
    json_t *subjectid_str = json_object_get(subject_obj, "cert_fingerprint");
    const char *subjectname = json_string_value(subjectid_str);
    if (!strcmp(subjectname, fingerprint)) {
      j_subject = subject_obj;
      return json2subject(j_subject, c);
    }
  }

  return 1;
}

int dao_add_subject(struct subject *c) {
  struct subject existing_subject;
  if (0 == dao_get_subject(c->cert_fingerprint, &existing_subject)) {
    printf("subject with this fingerprint already exists\n");
    return 1;
  }

  json_t *j_subject;
  if (0 == subject2json(c, &j_subject) &&
      0 == json_array_append(cache.subjects, j_subject)) {
    return dao_write_cache();
  } else {
    return 1;
  }
}

int dao_del_subject(char *subjectfingerprint) {
  struct subject existing_subject;
  if (0 != dao_get_subject(subjectfingerprint, &existing_subject)) {
    printf("subject not found\n");
    return 1;
  }

  int subjectidx = _dao_get_subject_cache_pos(subjectfingerprint);
  if (0 == json_array_remove(cache.subjects, subjectidx)) {
    return dao_write_cache();
  } else {
    printf("error on removing subject from cache\n");
    return 1;
  }
}

int dao_edit_subject(char *subjectfingerprint, struct subject *new_subject) {
  int subjectidx = _dao_get_subject_cache_pos(subjectfingerprint);
  if (-1 == subjectidx) {
    printf("subject not found\n");
    return 1;
  }

  json_t *j_new_subject;
  if (0 == subject2json(new_subject, &j_new_subject) &&
      0 == json_array_set_new(cache.subjects, subjectidx, j_new_subject)) {
    return dao_write_cache();
  } else {
    return 2;
  }
}


int dao_get_rules(LIST_HEAD(, rule) * rules) {
  size_t index;
  json_t *value;
  json_array_foreach(cache.rules, index, value) {
    struct rule *r = malloc(sizeof(struct rule));
    if (0 != json2rule(value, r)) {
      return 1;
    }
    LIST_INSERT_HEAD(rules, r, next);
  }
  return 0;
}

int dao_get_rule(char *id, struct rule *r) {
  int i;
  for (i = 0; i < json_array_size(cache.rules); i++) {
    json_t *rule_obj = json_array_get(cache.rules, i);
    if (!rule_obj || !json_is_object(rule_obj)) {
      printf("fields missing\n");
      exit(1);
    }
    json_t *ruleid_str = json_object_get(rule_obj, "id");
    const char *ruleid_from_cache = json_string_value(ruleid_str);
    if (!strcmp(ruleid_from_cache, id)) {
      return json2rule(rule_obj, r);
    }
  }

  return 1;
}

int dao_add_rule(struct rule *new_rule) {
  json_t *j_new_rule;
  if (0 == rule2json(new_rule, &j_new_rule) &&
      0 == json_array_append(cache.rules, j_new_rule)) {
    return dao_write_cache();
  } else {
    return 1;
  }
}

int dao_del_rule(char *ruleid) {
  struct rule existing_rule;
  if (0 != dao_get_rule(ruleid, &existing_rule)) {
    printf("rule not found\n");
    return 1;
  }

  int ruleidx = _dao_get_rule_cache_pos(ruleid);
  if (0 == json_array_remove(cache.rules, ruleidx)) {
    return dao_write_cache();
  } else {
    printf("error on removing rule from cache\n");
    return 1;
  }
}

int dao_edit_rule(char *ruleid, struct rule new_rule) {
  int ruleidx = _dao_get_rule_cache_pos(ruleid);
  if (-1 == ruleidx) {
    printf("rule not found\n");
    return 1;
  }

  json_t *j_new_role;
  if (0 == rule2json(&new_rule, &j_new_role) &&
      0 == json_array_set_new(cache.rules, ruleidx, j_new_role)) {
    return dao_write_cache();
  } else {
    return 2;
  }
}


int dao_get_allrs(LIST_HEAD(, resource_server) * allrs) {
  size_t index;
  json_t *value;
  json_array_foreach(cache.resource_servers, index, value) {
    struct resource_server *r = malloc(sizeof(struct resource_server));
    if (0 != json2resource_server(value, r)) {
      return 1;
    }
    LIST_INSERT_HEAD(allrs, r, next);
  }
  return 0;
}

int dao_get_rs(char *id, struct resource_server *rs) {
  int i;
  for (i = 0; i < json_array_size(cache.resource_servers); i++) {
    json_t *rs_obj = json_array_get(cache.resource_servers, i);
    if (!rs_obj || !json_is_object(rs_obj)) {
      exit(1);
    }
    json_t *rsid_str = json_object_get(rs_obj, "id");
    const char *rsid_from_cache = json_string_value(rsid_str);
    if (!strcmp(rsid_from_cache, id)) {
      return json2resource_server(rs_obj, rs);
    }
  }

  return 1;
}

int dao_add_rs(struct resource_server *new_rs) {
  json_t *j_new_rs;
  if (0 == resource_server2json(new_rs, &j_new_rs) &&
      0 == json_array_append(cache.resource_servers, j_new_rs)) {
    return dao_write_cache();
  } else {
    return 1;
  }
}

int dao_del_rs(char *rsid) {
  struct resource_server existing_rs;
  if (0 != dao_get_rs(rsid, &existing_rs)) {
    printf("rs not found\n");
    return 1;
  }

  int rsidx = _dao_get_rs_cache_pos(rsid);
  if (0 == json_array_remove(cache.resource_servers, rsidx)) {
    return dao_write_cache();
  } else {
    printf("error on removing rs from cache\n");
    return 1;
  }
}

int dao_edit_rs(char *rsid, struct resource_server *new_rs) {
  int rsidx = _dao_get_rs_cache_pos(rsid);
  if (-1 == rsidx) {
    printf("rs not found\n");
    return 1;
  }
  json_t *j_new_rs;
  if (0 == resource_server2json(new_rs, &j_new_rs) &&
      0 == json_array_set_new(cache.resource_servers, rsidx, j_new_rs)) {
    return dao_write_cache();

  } else {
    return 2;
  }
}



int dao_get_tickets(LIST_HEAD(, dcaf_ticket) * tickets) {
  size_t index;
  json_t *value;
  json_array_foreach(cache.tickets, index, value) {
    struct dcaf_ticket *t = malloc(sizeof(struct dcaf_ticket));
    if (0 != json2ticket(value, t)) {
      return 1;
    }
    LIST_INSERT_HEAD(tickets, t, next);
  }
  return 0;
}

int dao_get_ticket(char *id, struct dcaf_ticket *t) {
  int i;
  for (i = 0; i < json_array_size(cache.tickets); i++) {
    json_t *ticket_obj = json_array_get(cache.tickets, i);
    if (!ticket_obj || !json_is_object(ticket_obj)) {
      exit(1);
    }
    json_t *ticketid_str = json_object_get(ticket_obj, "id");
    const char *ticketid_from_cache = json_string_value(ticketid_str);
    if (!strcmp(ticketid_from_cache, id)) {
      return json2ticket(ticket_obj, t);
    }
  }

  return 1;
}

int dao_add_ticket(struct dcaf_ticket *new_ticket) {
  json_t *j_new_ticket;
  if (0 == ticket2json(new_ticket, &j_new_ticket) &&
      0 == json_array_append(cache.tickets, j_new_ticket)) {
    return dao_write_cache();
  } else {
    return 1;
  }
}

int dao_del_ticket(char *ticketid) {
  struct dcaf_ticket existing_ticket;
  if (0 != dao_get_ticket(ticketid, &existing_ticket)) {
    printf("ticket not found\n");
    return 1;
  }

  int ticketidx = _dao_get_ticket_cache_pos(ticketid);
  if (0 == json_array_remove(cache.tickets, ticketidx)) {
    return dao_write_cache();
  } else {
    printf("error on removing ticket from cache\n");
    return 1;
  }
}
