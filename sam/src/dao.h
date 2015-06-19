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

#endif
