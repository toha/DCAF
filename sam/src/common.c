#include "common.h"

// assumes little endian
void print_bits(size_t const size, void const *const ptr) {
  unsigned char *b = (unsigned char *)ptr;
  unsigned char byte;
  int i, j;

  for (i = size - 1; i >= 0; i--) {
    for (j = 7; j >= 0; j--) {
      byte = b[i] & (1 << j);
      byte >>= j;
      printf("%u", byte);
    }
  }
  puts("");
}

unsigned long get_micros() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return 1000000 * tv.tv_sec + tv.tv_usec;
}

int get_timestamp_secs() { return (int)time(NULL); }
