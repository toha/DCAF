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
