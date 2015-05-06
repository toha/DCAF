#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "lib/sys/queue.h"
#include <sys/time.h>
#include <uriparser/Uri.h>

unsigned long get_micros();
int get_timestamp_secs();
#endif
