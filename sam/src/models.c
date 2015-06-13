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

int json2rule_resource(json_t *j, struct rule_resource *r) {
  if (!json_is_object(j)) {
    return 1;
  }

  json_t *j_rs = json_object_get(j, "rs");
  json_t *j_resource = json_object_get(j, "resource");
  json_t *j_methods = json_object_get(j, "methods");
  if (!j_rs || !j_resource || !j_methods || !json_is_string(j_rs) ||
      !json_is_string(j_resource) || !json_is_number(j_methods)) {
    return 2;
  }

  r->rs = json_string_value(j_rs);
  r->resource = json_string_value(j_resource);
  r->methods = json_integer_value(j_methods);

  return 0;
}

int rule_resource2json(struct rule_resource *r, json_t **j) {
  *j = json_object();
  json_object_set(*j, "rs", json_string(r->rs));
  json_object_set(*j, "resource", json_string(r->resource));
  json_object_set(*j, "methods", json_integer(r->methods));
  return 0;
}
