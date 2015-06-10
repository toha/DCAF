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

int read_file(char *file_name, char **buffer) {
  FILE *fp;
  long lSize;

  fp = fopen(file_name, "rb");
  if (!fp)
    perror(file_name), exit(1);

  fseek(fp, 0L, SEEK_END);
  lSize = ftell(fp);
  rewind(fp);

  /* allocate memory for entire content */
  *buffer = calloc(1, lSize + 1);
  if (!*buffer)
    fclose(fp), fputs("memory alloc fails", stderr), exit(1);

  /* copy the file into the buffer */
  if (1 != fread(*buffer, lSize, 1, fp))
    fclose(fp), free(*buffer), fputs("entire read fails", stderr), exit(1);

  fclose(fp);

  return 0;
}

int write_file(char *file_name, char *output_txt) {
  FILE *outputFile = fopen(file_name, "w");
  fprintf(outputFile, "%s\n", output_txt);
  fclose(outputFile);
  return 0;
}

int parse_uri(char *uri_str, UriUriA *uri) {
  UriParserStateA state;
  state.uri = uri;
  if (uriParseUriA(&state, uri_str) != URI_SUCCESS) {
    /* Failure */
    uriFreeUriMembersA(uri);
    return -1;
  }
  return 0;
}

void hexDump(char *desc, void *addr, int len) {
  int i;
  unsigned char buff[17];
  unsigned char *pc = (unsigned char *)addr;

  // Output description if given.
  if (desc != NULL)
    printf("%s:\n", desc);

  // Process every byte in the data.
  for (i = 0; i < len; i++) {
    // Multiple of 16 means new line (with line offset).

    if ((i % 16) == 0) {
      // Just don't print ASCII for the zeroth line.
      // if (i != 0)
      //    printf ("  %s\n", buff);

      // Output the offset.
      // printf ("  %04x ", i);
    }

    // Now the hex code for the specific character.
    printf(" %02x", pc[i]);

    // And store a printable ASCII character for later.
    if ((pc[i] < 0x20) || (pc[i] > 0x7e))
      buff[i % 16] = '.';
    else
      buff[i % 16] = pc[i];
    buff[(i % 16) + 1] = '\0';
  }

  // Pad out last line if not exactly 16 characters.
  while ((i % 16) != 0) {
    printf("   ");
    i++;
  }

  // And print the final ASCII bit.
  // printf ("  %s\n", buff);
  printf("\n");
}

int http_send_error(struct mg_connection *conn, int status_code, char *msg) {
  mg_send_status(conn, status_code);
  mg_printf_data(conn, msg);
  return MG_TRUE;
}

int power(int base, unsigned int exp) {
  int i, result = 1;
  for (i = 0; i < exp; i++)
    result *= base;
  return result;
}
