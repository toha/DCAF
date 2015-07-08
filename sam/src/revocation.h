#ifndef _REVOCATION_H_
#define _REVOCATION_H_

#include "common.h"
#include <pthread.h>
#include "dao.h"
#include "lib/riot-cbor/cbor.h"

int init_revocation_thread();

#endif
