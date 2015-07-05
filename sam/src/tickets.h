#ifndef _SAMTICKETS_H_
#define _SAMTICKETS_H_

#include "common.h"
#include <jansson.h>
#include "models.h"
#include "lib/b64/b64.h"
#include <stdint.h>

#define DCAF_MAX_FACE 128    /* Maximum length of a Ticket Face */
#define DCAF_MAX_VERIFIER 16 /* Maximum length of a Ticket Verifier */
#define DCAF_MAX_AIF_LENGTH 5

struct authorization_information {
  char *rs;
  char *resource;
  int methods;
};

struct dcaf_ticket_face {
  uint32_t sequence_number;
  struct authorization_information AIs[DCAF_MAX_AIF_LENGTH];
  size_t ai_length;
  unsigned int timestamp;
  unsigned int lifetime;
  int dtls_psk_gen_method;
  LIST_HEAD(ticket_cond_list, rule_condition) conditions;
};

struct dcaf_ticket {
  char *id;
  struct dcaf_ticket_face face;
  unsigned char verifier[DCAF_MAX_VERIFIER + 1];
  size_t verifier_size;
  LIST_ENTRY(dcaf_ticket) next;
};

struct dcaf_revocation {
  struct dcaf_ticket ticket;
  unsigned int delivery_time;
  unsigned int last_try;
  unsigned int tries;
  LIST_ENTRY(dcaf_revocation) next;
};

int json2ticket(json_t *j, struct dcaf_ticket *t);
int ticket2json(struct dcaf_ticket *t, json_t **j);

int json2revocation(json_t *j, struct dcaf_revocation *r);
int revocation2json(struct dcaf_revocation *r, json_t **j);

#endif
