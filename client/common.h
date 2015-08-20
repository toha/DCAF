#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "coap.h"

char *
strndup (const char *s, size_t n);

coap_packet_t *
custom_coap_malloc_packet(void);


#endif
