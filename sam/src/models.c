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

int json2rule_condition(json_t *j, struct rule_condition *r) {
  if (!json_is_object(j)) {
    return 1;
  }

  json_t *j_key = json_object_get(j, "key");
  json_t *j_data = json_object_get(j, "data");
  if (!j_key || !json_is_string(j_key)) {
    return 2;
  }

  r->key = json_string_value(j_key);

  if (j_data && json_is_array(j_data)) {
    size_t index;
    json_t *value;
    json_array_foreach(j_data, index, value) {
      r->data[index] = json_integer_value(value);
    }
  }

  return 0;
}

int rule_condition2json(struct rule_condition *r, json_t **j) {
  *j = json_object();
  json_object_set(*j, "key", json_string(r->key));
  json_t *j_timeframe = json_array();
  json_array_append(j_timeframe, json_integer(r->data[0]));
  json_array_append(j_timeframe, json_integer(r->data[1]));
  json_object_set(*j, "data", j_timeframe);
  return 0;
}

int json2rule(json_t *j, struct rule *r) {
  if (!json_is_object(j)) {
    return 1;
  }

  json_t *j_id = json_object_get(j, "id");
  json_t *j_subject = json_object_get(j, "subject");
  json_t *j_resources = json_object_get(j, "resources");
  json_t *j_expiration_time = json_object_get(j, "expiration_time");
  json_t *j_priority = json_object_get(j, "priority");
  json_t *j_conditions = json_object_get(j, "conditions");
  if (!j_id || !j_subject || !j_priority || !json_is_string(j_id) ||
      !json_is_string(j_subject) || !json_is_number(j_expiration_time) ||
      !json_is_number(j_priority)) {
    return 2;
  }

  if (!json_is_array(j_resources) || json_array_size(j_resources) == 0 ||
      !json_is_array(j_conditions)) {
    return 3;
  }

  r->id = json_string_value(j_id);
  r->subject = json_string_value(j_subject);
  r->priority = json_integer_value(j_priority);
  r->expiration_time = json_integer_value(j_expiration_time);
  LIST_INIT(&r->resources);
  LIST_INIT(&r->conditions);

  size_t index;
  json_t *value;
  json_array_foreach(j_resources, index, value) {
    struct rule_resource *rr = malloc(sizeof(struct rule_resource));
    if (0 != json2rule_resource(value, rr)) {
      return 4;
    }
    LIST_INSERT_HEAD(&r->resources, rr, next);
  }

  size_t index2;
  json_t *value2;
  json_array_foreach(j_conditions, index2, value2) {
    struct rule_condition *rc = malloc(sizeof(struct rule_condition));
    if (0 != json2rule_condition(value2, rc)) {
      return 5;
    }
    LIST_INSERT_HEAD(&r->conditions, rc, next);
  }
  return 0;
}

int rule2json(struct rule *r, json_t **j) {
  *j = json_object();
  json_object_set(*j, "id", json_string(r->id));
  json_object_set(*j, "subject", json_string(r->subject));
  json_object_set(*j, "expiration_time", json_integer(r->expiration_time));
  json_object_set(*j, "priority", json_integer(r->priority));
  json_object_set(*j, "resources", json_array());
  json_object_set(*j, "conditions", json_array());

  json_t *j_resources_arr = json_object_get(*j, "resources");
  json_t *j_conditions_arr = json_object_get(*j, "conditions");

  struct rule_resource *np;
  LIST_FOREACH(np, &r->resources, next) {
    json_t *j_rule_resource;
    rule_resource2json(np, &j_rule_resource);
    json_array_append(j_resources_arr, j_rule_resource);
  }

  struct rule_condition *np2;
  LIST_FOREACH(np2, &r->conditions, next) {
    json_t *j_rule_condition;
    rule_condition2json(np2, &j_rule_condition);
    json_array_append(j_conditions_arr, j_rule_condition);
  }

  return 0;
}

int json2rs_resource(json_t *j, struct rs_resource *r) {
  if (!json_is_object(j)) {
    return 1;
  }

  json_t *j_resource = json_object_get(j, "resource");
  json_t *j_methods = json_object_get(j, "methods");
  if (!j_resource || !j_methods || !json_is_string(j_resource) ||
      !json_is_number(j_methods)) {
    return 2;
  }

  r->resource = json_string_value(j_resource);
  r->methods = json_integer_value(j_methods);

  return 0;
}

int rs_resource2json(struct rs_resource *r, json_t **j) {
  *j = json_object();
  json_object_set(*j, "resource", json_string(r->resource));
  json_object_set(*j, "methods", json_integer(r->methods));
  return 0;
}

int json2resource_server(json_t *j, struct resource_server *rs) {
  if (!json_is_object(j)) {
    return 1;
  }
  json_t *j_id = json_object_get(j, "id");
  json_t *j_secret = json_object_get(j, "secret");
  json_t *j_last_seq_nr = json_object_get(j, "last_seq_nr");
  json_t *j_rs_state_lowest_seq = json_object_get(j, "rs_state_lowest_seq");
  json_t *j_conditions = json_object_get(j, "conditions");
  json_t *j_resources = json_object_get(j, "resources");
  if (!j_id || !j_secret || !j_conditions || !j_resources || !j_last_seq_nr ||
      !j_rs_state_lowest_seq || !json_is_string(j_id) ||
      !json_is_string(j_secret) || !json_is_array(j_conditions) ||
      !json_is_array(j_resources) || !json_is_number(j_last_seq_nr) ||
      !json_is_number(j_rs_state_lowest_seq)) {
    return 2;
  }

  rs->id = json_string_value(j_id);
  rs->secret = json_string_value(j_secret);
  rs->last_seq_nr = json_integer_value(j_last_seq_nr);
  rs->rs_state_lowest_seq = json_integer_value(j_rs_state_lowest_seq);

  LIST_INIT(&rs->resources);
  LIST_INIT(&rs->conditions);
  size_t index;
  json_t *value;
  json_array_foreach(j_resources, index, value) {
    struct rs_resource *rsr = malloc(sizeof(struct rs_resource));
    if (0 != json2rs_resource(value, rsr)) {
      return 4;
    }
    LIST_INSERT_HEAD(&rs->resources, rsr, next);
  }
  /*size_t index2;
  json_t *value2;
  json_array_foreach(j_conditions, index2, value2) {
      struct rule_condition *rc = malloc(sizeof(struct rule_condition));
      if (0 != json2rule_condition(value2, rc)) {
          return 5;
      }
      LIST_INSERT_HEAD(&rs->conditions, rc, next);
  }*/

  return 0;
}

int resource_server2json(struct resource_server *r, json_t **j) {
  *j = json_object();
  json_object_set(*j, "id", json_string(r->id));
  json_object_set(*j, "secret", json_string(r->secret));
  json_object_set(*j, "last_seq_nr", json_integer(r->last_seq_nr));
  json_object_set(*j, "rs_state_lowest_seq",
                  json_integer(r->rs_state_lowest_seq));
  json_object_set(*j, "resources", json_array());
  json_object_set(*j, "conditions", json_array());

  json_t *j_resources_arr = json_object_get(*j, "resources");
  json_t *j_conditions_arr = json_object_get(*j, "conditions");

  struct rs_resource *np;
  LIST_FOREACH(np, &r->resources, next) {
    json_t *j_rs_resource;
    rs_resource2json(np, &j_rs_resource);
    json_array_append(j_resources_arr, j_rs_resource);
  }

  struct rule_condition *np2;
  LIST_FOREACH(np2, &r->conditions, next) {
    json_t *j_rs_cond;
    rule_condition2json(np2, &j_rs_cond);
    json_array_append(j_conditions_arr, j_rs_cond);
  }

  return 0;
}
