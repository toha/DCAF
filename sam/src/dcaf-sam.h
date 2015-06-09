#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "lib/sys/queue.h"
#include <sys/time.h>
#include <uriparser/Uri.h>
#include "lib/mongoose/mongoose.h"

void print_bits(size_t const size, void const *const ptr);

#endif
