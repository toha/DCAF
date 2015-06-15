#ifndef _MODELS_H_
#define _MODELS_H_

#include "common.h"
#include <jansson.h>
#include <stdint.h>

struct sam_cfg {
  char *rop_fingerprint;
  unsigned int *global_lifetime;
  char *listen_str;
};

struct subject {
  char *cert_fingerprint;
  char *name; // only for representation
  LIST_ENTRY(subject) next;
};

struct rule_resource {
  char *rs;
  char *resource;
  int methods;
  LIST_ENTRY(rule_resource) next;
};

struct rule_condition {
  char *key;
  int data[2];
  LIST_ENTRY(rule_condition) next;
};

struct rule {
  char *id;
  char *subject;
  unsigned int expiration_time;
  int priority;
  LIST_HEAD(rule_res_list, rule_resource) resources;
  LIST_HEAD(rule_cond_list, rule_condition) conditions;
  LIST_ENTRY(rule) next;
};

struct rs_resource {
  char *resource;
  int methods;
  LIST_ENTRY(rs_resource) next;
};

struct resource_server {
  char *id;
  char *secret;
  uint32_t last_seq_nr; // rename next_seq_nr
  uint32_t rs_state_lowest_seq;
  LIST_HEAD(rs_res_list, rs_resource) resources;
  LIST_HEAD(rs_cond_list, rule_condition) conditions;
  LIST_ENTRY(resource_server) next;
};

int json2subject(json_t *j, struct subject *c);
int subject2json(struct subject *c, json_t **j);

int json2rule_resource(json_t *j, struct rule_resource *r);
int rule_resource2json(struct rule_resource *r, json_t **j);
int json2rule_condition(json_t *j, struct rule_condition *r);
int rule_condition2json(struct rule_condition *r, json_t **j);
int json2rule(json_t *j, struct rule *r);
int rule2json(struct rule *r, json_t **j);

int json2rs_resource(json_t *j, struct rs_resource *r);
int rs_resource2json(struct rs_resource *r, json_t **j);
int json2resource_server(json_t *j, struct resource_server *rs);
int resource_server2json(struct resource_server *r, json_t **j);

#endif
