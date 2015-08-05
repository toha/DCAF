#include "http_ticket_api.h"

#define DTLS_PSK_GEN_HMAC_SHA256 0x00
#define DCAF_TYPE_SAM 0x00
#define DCAF_TYPE_SAI 0x01
#define DCAF_TYPE_CAI 0x02
#define DCAF_TYPE_E 0x03
#define DCAF_TYPE_K 0x04
#define DCAF_TYPE_TS 0x05
#define DCAF_TYPE_L 0x06
#define DCAF_TYPE_G 0x07
#define DCAF_TYPE_F 0x08
#define DCAF_TYPE_V 0x09
#define DCAF_TYPE_SQ 0x0A

#define DCAF_MAX_FACE 128    /* Maximum length of a Ticket Face */
#define DCAF_MAX_VERIFIER 16 /* Maximum length of a Ticket Verifier */

#define TRM_STR_MAX_LENGTH 128

int _cbor_parse_ticket_request_message(char *postdata, size_t postdata_len,
                                       struct ticket_request_message *trm) {}
size_t ticket_request_message2cbor(struct ticket_request_message *trm,
                                   cbor_stream_t *stream) {
  cbor_serialize_map(stream, 2);
  cbor_serialize_int(stream, DCAF_TYPE_SAM);
  cbor_serialize_byte_string(stream, trm->AS);
  cbor_serialize_int(stream, DCAF_TYPE_SAI);

  cbor_serialize_array(stream, trm->ai_length);
  int i;
  for (i = 0; i < trm->ai_length; i++) {
    cbor_serialize_array(stream, 2); // new array

    char *ai_rs_resource = (char *)malloc(256);
    ai_rs_resource = "coaps://[";
    char ai_rs_ipv6_closing_bracket[2] = "]";
    strcat(ai_rs_resource, trm->AIs[i].rs);
    strcat(ai_rs_resource, ai_rs_ipv6_closing_bracket);
    strcat(ai_rs_resource, trm->AIs[i].resource);
    cbor_serialize_byte_string(stream, ai_rs_resource);

    cbor_serialize_int(stream, trm->AIs[i].methods);
  }
}

int _cbor2ticket_request_message(char *cbordata, size_t cbordata_len,
                                 struct ticket_request_message *trm) {
  int trm_as_key, trm_d_key, trm_ai_key, trm_timestamp_key;
  size_t trm_map_length, trm_ai_arr_length, trm_ais_length;
  char *trm_as_str = (char *)malloc(TRM_STR_MAX_LENGTH);
  char *trm_ai_rs_res_str = (char *)malloc(TRM_STR_MAX_LENGTH);
  int trm_ai_methods, trm_timestamp;

  cbor_stream_t stream = {cbordata, cbordata_len, cbordata_len};

  size_t offset = cbor_deserialize_map(&stream, 0, &trm_map_length);
  if (trm_map_length < 2 || offset > cbordata_len) {
    return 2;
  }

  offset += cbor_deserialize_int(&stream, offset, &trm_as_key);
  if (DCAF_TYPE_SAM != trm_as_key || offset > cbordata_len) {
    return 3;
  }
  offset += cbor_deserialize_unicode_string(&stream, offset, trm_as_str,
                                            TRM_STR_MAX_LENGTH);

  offset += cbor_deserialize_int(&stream, offset, &trm_ai_key);

  if (DCAF_TYPE_SAI != trm_ai_key || offset > cbordata_len) {
    return 5;
  }

  offset += cbor_deserialize_array(&stream, offset, &trm_ais_length);
  if (offset > cbordata_len) {
    return 6;
  }

  int i;
  for (i = 0; i < trm_ais_length; i++) {
    offset += cbor_deserialize_array(&stream, offset, &trm_ai_arr_length);
    if (trm_ai_arr_length != 2 || offset > cbordata_len) {
      return 7;
    }
    offset += cbor_deserialize_unicode_string(
        &stream, offset, trm_ai_rs_res_str, TRM_STR_MAX_LENGTH);
    if (offset > cbordata_len) {
      return 1;
    }

    offset += cbor_deserialize_int(&stream, offset, &trm_ai_methods);
    if (offset > cbordata_len) {
      return 1;
    }

    trm->AS = trm_as_str;
    trm->AIs[i].methods = trm_ai_methods;

    UriUriA ai_uri;
    if (0 != parse_uri(trm_ai_rs_res_str, &ai_uri)) {
      return 7;
    }
    size_t ai_rs_len = ai_uri.hostText.afterLast - ai_uri.hostText.first;
    char *ai_rs = strndup(ai_uri.hostText.first, ai_rs_len);
    trm->AIs[i].rs = ai_rs;

    trm->AIs[i].resource = strdup(ai_uri.pathHead->text.first);
  }

  trm->ai_length = trm_ais_length;

  offset += cbor_deserialize_int(&stream, offset, &trm_timestamp_key);
  if (DCAF_TYPE_TS == trm_timestamp_key && offset < cbordata_len) {
    offset += cbor_deserialize_int(&stream, offset, &trm_timestamp);
    trm->timestamp = trm_timestamp;
  } else {
  }

  return 0;
}


int trm_find_matching_rule(struct ticket_request_message *trm,
                           struct subject *c, struct rule **rule_result,
                           struct rule_resource **rule_resource_result) {
  // Testen ob es eine Regel gibt die Zugriff für diese Rolle erlaubt
  LIST_HEAD(, rule) rule_list;
  LIST_INIT(&rule_list);
  if (0 != dao_get_rules(&rule_list)) {
    return 2;
  }

  struct rule *rulep;
  LIST_FOREACH(rulep, &rule_list, next) {
    if (strcmp(rulep->subject, c->cert_fingerprint)) {
      continue;
    }

    if (0 != rulep->expiration_time) {
      if (0 > rulep->expiration_time - get_timestamp_secs()) {
        printf("Rule expired\n");
        continue;
      }
    }

    // loop over resources and check if request and methods fits
    struct rule_resource *resourcep;
    LIST_FOREACH(resourcep, &rulep->resources, next) {

      int i;
      int alltrue = 1;
      for (i = 0; i < trm->ai_length; i++) {
        if (strcmp(resourcep->rs, trm->AIs[i].rs)) {
          alltrue = 0;
          continue;
        }

        // for implicite authorization skip resource and method-check
        if (resourcep->resource[0] != '*') {

          if (strcmp(resourcep->resource, trm->AIs[i].resource)) {
            alltrue = 0;
            continue;
          }

          int method_eval = resourcep->methods & trm->AIs[i].methods;
          if (method_eval != trm->AIs[i].methods) {
            alltrue = 0;
            continue;
          }
        }
      }

      if (!alltrue) {
        continue;
      }
      printf("Rule applied!\n");

      *rule_result = rulep;
      *rule_resource_result = resourcep;

      return 0;
    }
  }

  return 1;
}


size_t ticket_face2cbor(struct dcaf_ticket_face *f, cbor_stream_t *stream) {

  // Face structure
  // face map with length 5
  if (1 <= f->ai_length && f->AIs[0].resource[0] != '*') {
    cbor_serialize_map(stream, 5);

    cbor_serialize_int(stream, DCAF_TYPE_SAI);
    cbor_serialize_array(stream, f->ai_length);
    int i;
    for (i = 0; i < f->ai_length; i++) {
      cbor_serialize_array(stream, 2); // write value 1
      cbor_serialize_byte_string(stream,
                                 f->AIs[i].resource); // write array value 1
      cbor_serialize_int(stream, f->AIs[i].methods);  // write array value 2
    }
  } else {
    cbor_serialize_map(stream, 4);
  }

  // Timestamp
  cbor_serialize_int(stream, DCAF_TYPE_TS); // write key face 3
  cbor_serialize_int(stream, f->timestamp);

  // Lifetime
  cbor_serialize_int(stream, DCAF_TYPE_L); // write key face 4
  cbor_serialize_int(stream, f->lifetime); // write value 4

  // PSK-Generation-Method
  cbor_serialize_int(stream, DCAF_TYPE_G);              // write key face 5
  cbor_serialize_int(stream, DTLS_PSK_GEN_HMAC_SHA256); // write value 5

  cbor_serialize_int(stream, DCAF_TYPE_SQ);       // write key face 6
  cbor_serialize_int(stream, f->sequence_number); // write value 6


  return stream->pos;
}

size_t ticket2cbor(struct dcaf_ticket *t, cbor_stream_t *stream) {
  cbor_serialize_map(stream, 2);           // map of length 2 follows
  cbor_serialize_int(stream, DCAF_TYPE_F); // write key 1

  ticket_face2cbor(&t->face, stream);

  cbor_serialize_int(stream, DCAF_TYPE_V); // write key 2
  cbor_serialize_byte_string_len(stream, t->verifier,
                                 t->verifier_size); // write value 2
  return stream->pos;
}
