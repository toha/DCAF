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

#endif
