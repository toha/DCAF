#include "cam.h"

#include "coap_app.h"

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

    inet_pton(AF_INET6, "aaaa::1", &(listen_addr.addr.sin6.sin6_addr));
    // inet_pton(AF_INET6, "::1", &(listen_addr.addr.sin6.sin6_addr));

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

/* Handler for client access request */
void hnd_access_request(coap_context_t *ctx, struct coap_resource_t *resource,
                        const coap_endpoint_t *local_interface,
                        coap_address_t *peer, coap_pdu_t *request, str *token,
                        coap_pdu_t *response) {
  printf("Got Access Request\n");
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;

  size_t payload_len;
  unsigned char *payload;

  size_t cbor_offset, ar_map_length, ai_arr_length;
  int as_key, ai_key, ai_method;
  char *as_str = (char *)malloc(CBOR_MAX_STR);
  char *rs_str = (char *)malloc(CBOR_MAX_STR);
  UriUriA as_uri;

  coap_get_data(request, &payload_len, &payload);

  // is request payload of type "application/dcaf+cbor" (else 405)?
  option = coap_check_option(request, COAP_OPTION_CONTENT_TYPE, &opt_iter);
  if (!option) {
    printf("No Content Type\n");
    response->hdr->code = COAP_RESPONSE_CODE(405);
    return;
  }

  if (COAP_MEDIATYPE_APPLICATION_DCAF !=
      coap_decode_var_bytes(COAP_OPT_VALUE(option), COAP_OPT_LENGTH(option))) {
    printf("Invalid Content Type\n");
    response->hdr->code = COAP_RESPONSE_CODE(405);
    return;
  }

  if (!coap_get_data(request, &payload_len, &payload) || 0 >= payload_len) {
    printf("No Payload\n");
    response->hdr->code = COAP_RESPONSE_CODE(405);
    return;
  }

  // parse cbor payload
  cbor_stream_t cbor_stream = {payload, payload_len, payload_len};
  // are at least the fields AS and AI included (else 405)?
  cbor_offset = cbor_deserialize_map(&cbor_stream, 0, &ar_map_length);
  if (ar_map_length < 2 || cbor_offset > payload_len) {
    printf("Invalid CBOR data from Client\n");
    response->hdr->code = COAP_RESPONSE_CODE(405);
    return;
  }

  cbor_offset += cbor_deserialize_int(&cbor_stream, cbor_offset, &as_key);
  cbor_offset += cbor_deserialize_unicode_string(&cbor_stream, cbor_offset,
                                                 as_str, CBOR_MAX_STR);
  cbor_offset += cbor_deserialize_int(&cbor_stream, cbor_offset, &ai_key);
  cbor_offset +=
      cbor_deserialize_array(&cbor_stream, cbor_offset, &ai_arr_length);
  cbor_offset += cbor_deserialize_unicode_string(&cbor_stream, cbor_offset,
                                                 rs_str, CBOR_MAX_STR);
  cbor_offset += cbor_deserialize_int(&cbor_stream, cbor_offset, &ai_method);

  // derive as info (host, port, uri) from as field
  if (0 != parse_uri(as_str, &as_uri)) {
    printf("Invalid CBOR data from Client\n");
    response->hdr->code = COAP_RESPONSE_CODE(405);
    return;
  }

  // create http-request for ticket request message
  CURL *curl_handle;
  CURLcode res;
  struct curl_slist *headers = NULL;
  struct MemoryStruct chunk;
  chunk.memory = malloc(1); /* will be grown as needed by the realloc above */
  chunk.size = 0;           /* no data at this point */
  static const char *pCertFile = "cam.cert";
  static const char *pCACertFile = "sam.pem";
  const char *pKeyName;
  const char *pKeyType;
  pKeyName = "cam.pem";
  pKeyType = "PEM";

  curl_global_init(CURL_GLOBAL_DEFAULT);

  curl_handle = curl_easy_init();
  if (!curl_handle) {
    response->hdr->code = COAP_RESPONSE_CODE(405);
    return;
  }
  // libcurl set payload
  curl_easy_setopt(curl_handle, CURLOPT_URL, as_str);
  curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, payload);
  curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, payload_len);

  // libcurl Use Client-Cert
  curl_easy_setopt(curl_handle, CURLOPT_SSLCERTTYPE, "PEM");
  curl_easy_setopt(curl_handle, CURLOPT_SSLCERT, "cam.pem");
  // libcurl verify server cert
  curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
  // Client-Authority-Cert for authenticate SAM
  curl_easy_setopt(curl_handle, CURLOPT_CAINFO, "ca.crt");

  headers = curl_slist_append(headers, "Content-Type: application/dcaf+cbor");
  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
  // Send http request to sam
  res = curl_easy_perform(curl_handle);
  /* Check for errors */
  if (res != CURLE_OK) {
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
    printf("Error while http request\n");
    response->hdr->code = COAP_RESPONSE_CODE(405);
    return;
  }

  /* always cleanup */
  curl_easy_cleanup(curl_handle);
  curl_global_cleanup();

  // send answer to client
  printf("Got ticket - send to client\n");
  unsigned char buf[3]; /* need some storage for option encoding */

  /* set the result code */
  response->hdr->code = COAP_RESPONSE_CODE(205);

  /* add a Content-Type option to describe the returned data */
  coap_add_option(response, COAP_OPTION_CONTENT_TYPE,
                  coap_encode_var_bytes(buf, COAP_MEDIATYPE_APPLICATION_DCAF),
                  buf);

  /* add data */
  coap_add_data(response, chunk.size, (unsigned char *)chunk.memory);

  if (chunk.memory)
    free(chunk.memory);

  free(as_str);
  free(rs_str);
}
