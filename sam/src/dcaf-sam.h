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
unsigned long get_micros();
int get_timestamp_secs();
int read_file(char *file_name, char **buffer);
int write_file(char *file_name, char *output_txt);
int parse_uri(char *uri_str, UriUriA *uri);
void hexDump(char *desc, void *addr, int len);
int http_send_error(struct mg_connection *conn, int status_code, char *msg);
int power(int base, unsigned int exp);
#endif
