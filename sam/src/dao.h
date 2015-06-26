#ifndef _DAO_H_
#define _DAO_H_

#include "common.h"
#include <jansson.h>
#include "models.h"
#include "tickets.h"

struct resource_cache {
  json_t *samcfg;
  json_t *subjects;
  json_t *rules;
  json_t *resource_servers;
  json_t *tickets;
  json_t *revocations;
};

pthread_mutex_t dao_mutex;

int dao_init();
int dao_reload_cache();
int dao_write_cache();

int dao_get_samcfg(struct sam_cfg *c);
unsigned int dao_get_cfg_lifetime();
char *dao_get_cfg_rop_fingerprint();
char *dao_get_cfg_listen_str();
// int dao_get_subjects(LIST_HEAD(, subject) *subjects);
int dao_get_subject(char *id, struct subject *subject);
int dao_add_subject(struct subject *c);
int dao_del_subject(char *subjectid);
int dao_edit_subject(char *subjectid, struct subject *new_subject);

// int dao_get_rules(json_t** rules);
int dao_get_rule(char *id, struct rule *r);
int dao_add_rule(struct rule *new_rule);
int dao_del_rule(char *ruleid);
int dao_edit_rule(char *ruleid, struct rule new_rule);

// int dao_get_allrs(json_t** resource_servers);
int dao_get_rs(char *id, struct resource_server *rs);
int dao_add_rs(struct resource_server *new_rs);
int dao_del_rs(char *rsid);
int dao_edit_rs(char *rsid, struct resource_server *new_rs);

// int dao_get_tickets(LIST_HEAD(, dcaf_ticket) * tickets);
int dao_get_ticket(char *id, struct dcaf_ticket *t);
int dao_add_ticket(struct dcaf_ticket *new_ticket);
int dao_del_ticket(char *ticketid);

// int dao_get_revocations(LIST_HEAD(, dcaf_revocation) * allrevoc);
int dao_add_revocation(struct dcaf_revocation *revocation);
int dao_edit_revocation(char *ticket_id,
                        struct dcaf_revocation *new_revocation);

#endif
