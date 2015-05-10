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

  if (app) {
/* bind interfaces */

#if HAVE_LIBTINYDTLS
    coap_address_init(&listen_addr);

    /* set IPv6 interface address */
    listen_addr.size = sizeof(struct sockaddr_in6);
    listen_addr.addr.sin6.sin6_family = AF_INET6;
    listen_addr.addr.sin6.sin6_port = htons(CAM_COAP_DEFAULT_PORT);


    inet_pton(AF_INET6, "::1", &(listen_addr.addr.sin6.sin6_addr));

    interface = coap_new_endpoint(&listen_addr, COAP_ENDPOINT_DTLS);
    if (!coap_application_attach(app, interface)) {
      coap_log(LOG_CRIT, "failed to create endpoint\n");
      coap_free_endpoint(interface);
      goto cleanup;
    }
#endif

    if (init_resource(app->coap_context)) {
      result = (int)coap_application_run(app); /* main loop */
      coap_free_application(app);
    }
  }

cleanup:
  coap_free_application(app);
  return result;

}
