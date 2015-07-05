#include "tickets.h"

int json2ticket(json_t *j, struct dcaf_ticket *t) {
  if (!json_is_object(j)) {
    printf("a1\n");
    return 1;
  }

  json_t *j_id = json_object_get(j, "id");
  json_t *j_face = json_object_get(j, "face");
  json_t *j_verifier = json_object_get(j, "verifier");
  json_t *j_verifier_size = json_object_get(j, "verifier_size");

  if (!j_id || !j_face || !j_verifier || !j_verifier_size ||
      !json_is_string(j_id) || !json_is_object(j_face) ||
      !json_is_string(j_verifier) || !json_is_number(j_verifier_size)) {
    return 2;
  }

  t->id = json_string_value(j_id);
  t->verifier_size = json_integer_value(j_verifier_size);

  char *verifier_b64 = json_string_value(j_verifier);
  size_t verifier_size = 0;
  unsigned char *verifier_str =
      base64_decode(verifier_b64, strlen(verifier_b64), &verifier_size);
  memcpy(t->verifier, verifier_str, t->verifier_size);
  // base64_cleanup(); muss raus, sonst funzt das nächste base64 nicht
  free(verifier_str);
  // free(verifier_b64);

  json_t *j_face_ai = json_object_get(j_face, "AI");

  json_t *j_face_seq_nr = json_object_get(j_face, "sequence_number");
  json_t *j_face_timestamp = json_object_get(j_face, "timestamp");
  json_t *j_face_lifetime = json_object_get(j_face, "lifetime");
  json_t *j_face_dtls_psk_gen_method =
      json_object_get(j_face, "dtls_psk_gen_method");
  json_t *j_conditions = json_object_get(j_face, "conditions");

  if (!j_face_ai || !j_face_seq_nr || !j_face_timestamp || !j_face_lifetime ||
      !j_face_dtls_psk_gen_method || !j_conditions ||
      !json_is_array(j_face_ai) || !json_is_number(j_face_seq_nr) ||
      !json_is_number(j_face_timestamp) || !json_is_number(j_face_lifetime) ||
      !json_is_number(j_face_dtls_psk_gen_method) ||
      !json_is_array(j_conditions)) {
    return 3;
  }

  t->face.sequence_number = json_integer_value(j_face_seq_nr);
  t->face.timestamp = json_integer_value(j_face_timestamp);
  t->face.lifetime = json_integer_value(j_face_lifetime);
  t->face.dtls_psk_gen_method = json_integer_value(j_face_dtls_psk_gen_method);

  size_t index;
  json_t *j_face_ai_el;
  json_array_foreach(j_face_ai, index, j_face_ai_el) {
    json_t *j_face_ai_rs = json_object_get(j_face_ai_el, "rs");
    json_t *j_face_ai_resource = json_object_get(j_face_ai_el, "resource");
    json_t *j_face_ai_methods = json_object_get(j_face_ai_el, "methods");

    if (!j_face_ai_rs || !j_face_ai_resource || !j_face_ai_methods ||
        !json_is_string(j_face_ai_rs) || !json_is_string(j_face_ai_resource) ||
        !json_is_number(j_face_ai_methods)) {
      return 4;
    }

    t->face.AIs[index].rs = json_string_value(j_face_ai_rs);
    t->face.AIs[index].resource = json_string_value(j_face_ai_resource);
    t->face.AIs[index].methods = json_integer_value(j_face_ai_methods);
  }

  t->face.ai_length = json_array_size(j_face_ai);

  return 0;
}

int ticket2json(struct dcaf_ticket *t, json_t **j) {
  *j = json_object();
  json_object_set(*j, "id", json_string(t->id));

  json_object_set(*j, "face", json_object());

  size_t b64_length = 0;
  char *b64_verifier =
      base64_encode(t->verifier, t->verifier_size, &b64_length);

  json_object_set(*j, "verifier", json_stringn(b64_verifier, b64_length));

  json_object_set(*j, "verifier_size", json_integer(t->verifier_size));

  json_t *face = json_object_get(*j, "face");
  json_t *j_face_ais_arr = json_array();

  int i;
  for (i = 0; i < t->face.ai_length; i++) {
    json_t *face_ai_obj = json_object();
    json_object_set(face_ai_obj, "rs", json_string(t->face.AIs[i].rs));
    json_object_set(face_ai_obj, "resource",
                    json_string(t->face.AIs[i].resource));
    json_object_set(face_ai_obj, "methods",
                    json_integer(t->face.AIs[i].methods));
    json_array_append(j_face_ais_arr, face_ai_obj);
  }
  json_object_set(face, "AI", j_face_ais_arr);

  json_object_set(face, "sequence_number",
                  json_integer(t->face.sequence_number));
  json_object_set(face, "timestamp", json_integer(t->face.timestamp));
  json_object_set(face, "lifetime", json_integer(t->face.lifetime));
  json_object_set(face, "dtls_psk_gen_method",
                  json_integer(t->face.dtls_psk_gen_method));


  json_t *j_conditions = json_array();
  /*struct rule_condition *condp;
  LIST_FOREACH(condp, &t->face.conditions, next) {
    json_t *j_cond;
    rule_condition2json(condp, &j_cond);
    json_array_append(j_conditions, j_cond);
  }*/
  json_object_set(face, "conditions", j_conditions);

  return 0;
}


int json2revocation(json_t *j, struct dcaf_revocation *r) {
  if (!json_is_object(j)) {
    return 1;
  }

  json_t *j_ticket = json_object_get(j, "ticket");
  json_t *j_delivery_time = json_object_get(j, "delivery_time");
  json_t *j_last_try = json_object_get(j, "last_try");
  json_t *j_tries = json_object_get(j, "tries");

  if (!j_ticket || !j_delivery_time || !j_last_try || !j_tries ||
      !json_is_object(j_ticket) || !json_is_number(j_delivery_time) ||
      !json_is_number(j_last_try) || !json_is_number(j_tries)) {
    return 2;
  }

  if (0 != json2ticket(j_ticket, &r->ticket)) {
    return 3;
  }

  r->delivery_time = json_integer_value(j_delivery_time);
  r->last_try = json_integer_value(j_last_try);
  r->tries = json_integer_value(j_tries);

  return 0;
}

int revocation2json(struct dcaf_revocation *r, json_t **j) {
  *j = json_object();
  json_t *j_ticket;
  if (0 != ticket2json(&r->ticket, &j_ticket)) {
    return 1;
  }
  json_object_set(*j, "id", json_string(r->ticket.id));
  json_object_set(*j, "ticket", j_ticket);
  json_object_set(*j, "delivery_time", json_integer(r->delivery_time));
  json_object_set(*j, "last_try", json_integer(r->last_try));
  json_object_set(*j, "tries", json_integer(r->tries));

  return 0;
}
