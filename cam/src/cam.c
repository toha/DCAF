#include "cam.h"

#define DTLS_PSK_GEN_HMAC_SHA256 0x00

#define CAM_COAP_DEFAULT_PORT 5684 // COAPS_DEFAULT_PORT
#define DCAF_ACCESS_REQUEST_RESOURCE "client-auth"
#define COAP_MEDIATYPE_APPLICATION_DCAF 70
#define CBOR_MAX_STR 255


int main(int argc, char **argv) {
  printf("---------------------------------------------------\n");
  printf("Client Authorization Manager (CAM) - pid: %d\n", getpid());
  printf("---------------------------------------------------\n");

}
