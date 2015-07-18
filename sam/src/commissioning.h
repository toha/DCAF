#ifndef _COMMISSIONING_H_
#define _COMMISSIONING_H_

#include "common.h"
#include <pthread.h>
#include "dao.h"
#include "lib/riot-cbor/cbor.h"

int try_send_commissioning(json_t *commissioning_msg);

#endif
