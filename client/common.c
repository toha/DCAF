#include "common.h"

char *strndup(const char *s, size_t n) {
  char *result;
  size_t len = strlen(s);

  if (n < len)
    len = n;

  result = (char *)malloc(len + 1);
  if (!result)
    return 0;

  result[len] = '\0';
  return (char *)memcpy(result, s, len);
}

coap_packet_t *custom_coap_malloc_packet(void) {
  return (coap_packet_t *)coap_malloc_type(COAP_PACKET, 0);
}
