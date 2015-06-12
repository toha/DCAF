#include "models.h"

int json2subject(json_t *j, struct subject *c) {
  if (!json_is_object(j)) {
    return 1;
  }

  json_t *cid = json_object_get(j, "name");
  json_t *cert_fingerprint = json_object_get(j, "cert_fingerprint");
  if (!cid || !cert_fingerprint || !json_is_string(cid) ||
      !json_is_string(cert_fingerprint)) {
    return 2;
  }

  c->name = json_string_value(cid);
  c->cert_fingerprint = json_string_value(cert_fingerprint);

  return 0;
}

int subject2json(struct subject *c, json_t **j) {
  *j = json_object();
  json_object_set(*j, "name", json_string(c->name));
  json_object_set(*j, "cert_fingerprint", json_string(c->cert_fingerprint));

  return 0;
}
