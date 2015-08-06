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

size_t ticket_create_verifier(char *rs_secretb64, struct dcaf_ticket_face *f,
                              unsigned char *v) {
  // ticket face to cbor for calculation of verifier
  unsigned char face_as_cbor[DCAF_MAX_FACE];
  cbor_stream_t face_cbor_stream;
  cbor_init(&face_cbor_stream, face_as_cbor, sizeof(face_as_cbor));
  ticket_face2cbor(f, &face_cbor_stream);
  size_t face_cbor_size = face_cbor_stream.pos;
  cbor_destroy(&face_cbor_stream);

  // init verifier with 0
  memset(v, 0, sizeof(v));

  dtls_hmac_context_t *hmac_ctx;
  unsigned char key[64];

  size_t rs_secret_size = 0;
  unsigned char *rs_secret =
      base64_decode(rs_secretb64, strlen(rs_secretb64), &rs_secret_size);

  hmac_ctx = dtls_hmac_new(rs_secret, rs_secret_size);
  dtls_hmac_update(hmac_ctx, face_as_cbor, face_cbor_size);
  size_t keylength = dtls_hmac_finalize(hmac_ctx, &key);

  size_t verifier_size = keylength;
  if (verifier_size > DCAF_MAX_VERIFIER) {
    verifier_size = DCAF_MAX_VERIFIER;
  }

  memcpy(v, &key, verifier_size);
  return verifier_size;
}

int handle_ticket_request_message(struct mg_connection *conn,
                                  enum mg_event ev) {

  // check content-type
  if (strcmp(mg_get_header(conn, "Content-Type"), "application/dcaf+cbor")) {
    return http_send_error(conn, 400, "invalid content-type");
  }

  struct ticket_request_message trm;
  int parse_result =
      _cbor2ticket_request_message(conn->content, conn->content_len, &trm);

  switch (parse_result) {
  case 1:
    return http_send_error(conn, 400, "invalid POST data");
  case 2:
    return http_send_error(conn, 400,
                           "one or more required fields are missing");
  case 3:
    return http_send_error(conn, 400, "one or more fields are invalid");
  case 4:
    return http_send_error(conn, 400, "invalid authorization information");
  case 5:
    return http_send_error(conn, 400, "invalid AI uri");
  default:
    break;
  }

  char *b64_fingerprint = get_client_cert_b64_fingerprint(conn);
  struct subject c;
  if (0 != dao_get_subject(b64_fingerprint, &c)) {
    return http_send_error(conn, 400, "subject not found");
  }
  struct rule *rulep = NULL;
  struct rule_resource *rule_resourcep = NULL;
  int rule_result = trm_find_matching_rule(&trm, &c, &rulep, &rule_resourcep);
  switch (rule_result) {
  case 1:
    printf("No Rule applied!\n");
    // No rule applied. Empty success response
    return http_send_error(conn, 200, "");
  case 2:
    return http_send_error(conn, 500, "error with rule list");
  default:
    break;
  }
  if (!rulep || !rule_resourcep) {
    // strange error - rule applied but pointers not set
    return http_send_error(conn, 500, "internal server error");
  }

  struct resource_server rs;
  if (0 != dao_get_rs(rule_resourcep->rs, &rs)) {
    return http_send_error(conn, 500, "resource server not found");
  }
  struct dcaf_ticket ticket;
  // face
  // auth infos - implicit?
  if (rule_resourcep->resource[0] == '*') {
    ticket.face.ai_length = 1;
    ticket.face.AIs[0].rs = rule_resourcep->rs;
    ticket.face.AIs[0].resource = "*";
    ticket.face.AIs[0].methods = 15;
  } else {
    int j;
    for (j = 0; j < trm.ai_length; j++) {
      ticket.face.AIs[j] = trm.AIs[j];
    }
    ticket.face.ai_length = trm.ai_length;
  }

  // Timestamp from request or from sam time
  if (0 != trm.timestamp) {
    ticket.face.timestamp = trm.timestamp;
  } else {
    ticket.face.timestamp = get_timestamp_secs();
  }

  // Lifetime in Regel?
  if (0 != rulep->expiration_time) {
    unsigned int sec_remaining = rulep->expiration_time - get_timestamp_secs();
    if (0 > sec_remaining) {
      ticket.face.lifetime = dao_get_cfg_lifetime();
    } else {
      // verbleibende sekunden als lifetime
      ticket.face.lifetime = sec_remaining;
    }
  } else {
    ticket.face.lifetime = dao_get_cfg_lifetime();
  }

  // Copy local conditions to ticket
  LIST_INIT(&ticket.face.conditions);
  struct rule_condition *condp;
  LIST_FOREACH(condp, &rulep->conditions, next) {
    struct rule_condition *newcondp = malloc(sizeof(struct rule_condition));
    newcondp->data[0] = condp->data[0];
    newcondp->data[1] = condp->data[1];
    newcondp->key = (char *)malloc(sizeof(char) * strlen(condp->key));
    strcpy(newcondp->key, condp->key);

    LIST_INSERT_HEAD(&ticket.face.conditions, newcondp, next);
  }

  ticket.face.dtls_psk_gen_method = DTLS_PSK_GEN_HMAC_SHA256;
  ticket.face.sequence_number = rs.last_seq_nr;
  rs.last_seq_nr++;

  return MG_TRUE;
}
