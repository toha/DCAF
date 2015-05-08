#include "common.h"

unsigned long get_micros() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return 1000000 * tv.tv_sec + tv.tv_usec;
}

int get_timestamp_secs() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec;
}

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
    printf("Failure\n");
    uriFreeUriMembersA(uri);
    return -1;
  }
  // printf("pathHead: %s\n", (*uri).pathHead->text.first);
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
