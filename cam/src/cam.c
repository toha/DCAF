#include "cam.h"

#define DTLS_PSK_GEN_HMAC_SHA256 0x00

#define CAM_COAP_DEFAULT_PORT 5684 // COAPS_DEFAULT_PORT
#define DCAF_ACCESS_REQUEST_RESOURCE "client-auth"
#define COAP_MEDIATYPE_APPLICATION_DCAF 70
#define CBOR_MAX_STR 255

int init_resource(coap_context_t *);

struct MemoryStruct {
  char *memory;
  size_t size;
};

// Callback for libcurl for getting response from memory
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb,
                                  void *userp) {
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if (mem->memory == NULL) {
    /* out of memory! */
    printf("not enough memory\n");
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

int main(int argc, char **argv) {
  printf("---------------------------------------------------\n");
  printf("Client Authorization Manager (CAM) - pid: %d\n", getpid());
  printf("---------------------------------------------------\n");

  coap_application_t *app;
  coap_endpoint_t *interface;
  coap_address_t listen_addr;
  int result = EXIT_FAILURE;
  coap_set_log_level(LOG_DEBUG);

  app = coap_new_application();
}
