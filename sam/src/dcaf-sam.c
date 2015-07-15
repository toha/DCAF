#include "dcaf-sam.h"
#include <jansson.h>
#include <pthread.h>
#include "revocation.h"

int main() {
  printf("---------------------------------------------------\n");
  printf("Server Authorization Manager (SAM) - pid: %d\n", getpid());
  printf("---------------------------------------------------\n");

  // start revocation thread
  pthread_t revocation_thread;
  int rc;
  rc = pthread_create(&revocation_thread, NULL, init_revocation_thread, NULL);
  if (rc) {
    printf("ERROR; return code from pthread_create() is %d\n", rc);
    exit(-1);
  }

  dao_init();

  return 0;
}
