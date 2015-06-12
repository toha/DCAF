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

#endif
