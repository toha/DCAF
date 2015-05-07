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
