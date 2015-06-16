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
