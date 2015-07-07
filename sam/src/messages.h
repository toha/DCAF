#ifndef _MODEL_MESSAGES_H_
#define _MODEL_MESSAGES_H_

#include "common.h"
#include "models.h"

struct ticket_request_message {
  char *AS;
  struct authorization_information AIs[DCAF_MAX_AIF_LENGTH];
  size_t ai_length;
  int timestamp;
};

#endif
