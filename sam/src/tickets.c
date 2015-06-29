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

