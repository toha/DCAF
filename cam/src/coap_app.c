/* app.c -- CoAP application
 *
 * Copyright (C) 2010--2013 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap_app.h"

#include <tinydtls/tinydtls.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct network_data_item {
  struct network_data_item *next;

  coap_address_t remote; /**< remote address */
  size_t data_length;    /**< length of data */
  unsigned char data[];
};

struct list_ep_t {
  struct list_ep_t *next;
  coap_endpoint_t *ep;

  LIST_STRUCT(sendqueue);
};

#if HAVE_LIBTINYDTLS
/* This function is called from libcoap to send data on the given
 * local interface to the remote peer. */
ssize_t send_to_peer(struct coap_context_t *coap_context,
                     const coap_endpoint_t *local_interface,
                     const coap_address_t *remote, unsigned char *data,
                     size_t len);

int dtls_application_data(struct dtls_context_t *dtls_context,
                          session_t *session, uint8 *data, size_t len) {
  /* FIXME: set small_ctx from ctx->app_data */
  coap_application_t *app = dtls_get_app_data(dtls_context);

  struct list_ep_t *ep_item;
  coap_endpoint_t *local_interface = NULL;

  fprintf(stderr, "####### received application data...\n");
  for (ep_item = list_head(app->endpoints); ep_item;
       ep_item = list_item_next(ep_item)) {
    if (session->ifindex == ep_item->ep->handle) {
      local_interface = ep_item->ep;
      fprintf(stderr, "####### found local interface\n");
      break;
    }
  }

  if (!local_interface) {
    fprintf(stderr, "dtls_send_to_peer: cannot find local interface\n");
    return -3;
  }

  fprintf(stderr, "####### now pass to coap_handle_message\n");
  return coap_handle_message(app->coap_context, local_interface,
                             (coap_address_t *)session, (unsigned char *)data,
                             len);
}

int dtls_send_to_peer(struct dtls_context_t *dtls_context, session_t *session,
                      uint8 *data, size_t len) {
  coap_application_t *app = dtls_get_app_data(dtls_context);
  struct list_ep_t *ep_item;
  coap_endpoint_t *local_interface = NULL;

  /* get local interface from handle */
  for (ep_item = list_head(app->endpoints); ep_item;
       ep_item = list_item_next(ep_item)) {
    if (session->ifindex == ep_item->ep->handle) {
      local_interface = ep_item->ep;
      break;
    }
  }

  if (!local_interface) {
    fprintf(stderr, "dtls_send_to_peer: cannot find local interface\n");
    return -3;
  }

  return coap_network_send(app->coap_context, local_interface,
                           (coap_address_t *)session, data, len);
}

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
int get_psk_key(struct dtls_context_t *ctx, const session_t *session,
                const unsigned char *id, size_t id_len,
                const dtls_psk_key_t **result) {
  static const dtls_psk_key_t psk = {.id = (unsigned char *)"Client_identity",
                                     .id_length = 15,
                                     .key = (unsigned char *)"secretPSK",
                                     .key_length = 9};

  *result = &psk;
  return 0;
}

static int dtls_event(struct dtls_context_t *ctx, session_t *session,
                      dtls_alert_level_t level, unsigned short code) {
  debug("got event %x\n", code);
  return 0;
}

static dtls_handler_t cb = {.write = dtls_send_to_peer,
                            .read = dtls_application_data,
                            .event = dtls_event,
                            .get_psk_key = get_psk_key,
#ifdef WITH_ECC
                            .get_ecdsa_key = NULL,
                            .verify_ecdsa_key = NULL
#endif
};

#endif /*  HAVE_LIBTINYDTLS */

static inline int is_secure(const coap_endpoint_t *interface) {
  return interface && (interface->flags & COAP_ENDPOINT_DTLS);
}

ssize_t send_to_peer(struct coap_context_t *coap_context,
                     const coap_endpoint_t *local_interface,
                     const coap_address_t *remote, unsigned char *data,
                     size_t len) {
  coap_application_t *app = coap_get_app_data(coap_context);
  int res = -2;

#if HAVE_LIBTINYDTLS
  if (is_secure(local_interface)) {
    session_t session;

    /* create tinydtls session object from remote address and local
     * endpoint handle */
    dtls_session_init(&session);
    session.size = remote->size;
    session.addr.st = remote->addr.st;
    session.ifindex = local_interface->handle;

    debug("call dtls_write\n");
    res = dtls_write(app->dtls_context, &session, (uint8 *)data, len);
  } else {
    debug("call coap_network_send\n");
    res = coap_network_send(coap_context, local_interface, remote, data, len);
  }
#else  /* HAVE_LIBTINYDTLS */
  /* we cannot send secure messages without tinydtls */
  if (!is_secure(local_interface)) {
    res = coap_network_send(coap_context, local_interface, remote, data, len);
  }
#endif /* HAVE_LIBTINYDTLS */

  return res;
}

static void handle_read(coap_application_t *app, coap_endpoint_t *local) {
  static unsigned char buf[COAP_MAX_PDU_SIZE];
  ssize_t bytes_read = -1;
  coap_address_t remote;

  coap_address_init(&remote);

  bytes_read = coap_network_read(local, &remote, buf, sizeof(buf));

  if (bytes_read < 0) {
    fprintf(stderr, "handle_read: recvfrom");
  } else {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
    unsigned char addr[INET6_ADDRSTRLEN + 8];

/*if (coap_print_addr(&remote, addr, INET6_ADDRSTRLEN+8)) {
  printf("received %d bytes from %s on local interface ",
         (int)bytes_read, addr);
  if (coap_print_addr(&local->addr, addr, INET6_ADDRSTRLEN+8))
    printf("%s", addr);
  printf("\n");
}*/

#if HAVE_LIBTINYDTLS
    if (is_secure(local)) {
      session_t session;

      /* create tinydtls session object from remote address and local
       * endpoint handle */
      dtls_session_init(&session);
      session.size = remote.size;
      session.addr.st = remote.addr.st;
      session.ifindex = local->handle;

      dtls_handle_message(app->dtls_context, &session, (uint8 *)buf,
                          bytes_read);
    } else {
      coap_handle_message(app->coap_context, local, &remote, buf,
                          (size_t)bytes_read);
    }
#else
    coap_handle_message(app->coap_context, local, &remote, buf,
                        (size_t)bytes_read);
#endif
  }
}

#define COAP_MAX_TOKEN 8
typedef struct coap_application_req_t {
  struct coap_application_req_t *next;

  /* coap_tick_t timeout; */
  coap_address_t remote;
  coap_response_handler_t response_handler;

  size_t tokenlen;
  unsigned char token[COAP_MAX_TOKEN];
} coap_application_req_t;

static coap_application_req_t r;

static void message_handler(struct coap_context_t *ctx,
                            const coap_endpoint_t *local_interface,
                            const coap_address_t *remote, coap_pdu_t *sent,
                            coap_pdu_t *received, const coap_tid_t id) {
  coap_application_t *application;

  application = coap_get_app_data(ctx);
  assert(application);

  if (coap_address_equals(remote, &r.remote) &&
      received->hdr->token_length == r.tokenlen &&
      (r.tokenlen == 0 ||
       memcmp(received->hdr->token, r.token, r.tokenlen) == 0)) {
    if (r.response_handler) {
      r.response_handler(ctx, local_interface, remote, sent, received, id);
    }
  }
}

coap_application_t *coap_new_application() {
  coap_application_t *app = COAP_MALLOC_TYPE(application);

  if (!app) {
    coap_log(LOG_CRIT, "cannot allocate application object\n");
    return NULL;
  }

  memset(app, 0, sizeof(coap_application_t));

  /* initialize list of recognized endpoints */
  LIST_STRUCT_INIT(app, endpoints);

#if HAVE_LIBTINYDTLS
  /* create dtls_context with application object as application data
   * so we can use it in callback functions */
  app->dtls_context = dtls_new_context(app);
  if (!app->dtls_context) {
    coap_log(LOG_CRIT, "cannot allocate DTLS context\n");
    goto cleanup;
  }

  dtls_set_handler(app->dtls_context, &cb);
#endif

  /* create coap_context */
  app->coap_context = coap_new_context();
  if (!app->coap_context) {
    coap_log(LOG_CRIT, "cannot allocate DTLS context\n");
    goto cleanup;
  }

  /* set application object as application data in coap_context so we
   * can use it in callback functions */
  coap_set_app_data(app->coap_context, app);

  /* register callback function to send data over secure channel */
  coap_set_cb(app->coap_context, send_to_peer, write);

  coap_register_response_handler(app->coap_context, message_handler);

  return app;

cleanup:
  coap_free_application(app);
  return NULL;
}

void coap_free_application(coap_application_t *app) {
  coap_endpoint_t *ep;

  if (app) {
#if HAVE_LIBTINYDTLS
    if (app->dtls_context) {
      dtls_free_context(app->dtls_context);
    }
#endif
    if (app->coap_context) {
      coap_free_context(app->coap_context);
    }

    while ((ep = list_pop(app->endpoints)) != NULL) {
      coap_free_endpoint(ep);
    }

    COAP_FREE_TYPE(application, app);
  }
}

static struct list_ep_t *find_ep_item(coap_application_t *application,
                                      int handle) {
  struct list_ep_t *ep_item;

  ep_item = list_head(application->endpoints);
  while (ep_item && ep_item->ep->handle != handle) {
    ep_item = list_item_next(ep_item);
  }

  return ep_item;
}

coap_endpoint_t *coap_application_find_endpoint(coap_application_t *application,
                                                int handle) {
  struct list_ep_t *ep_item;

  ep_item = find_ep_item(application, handle);
  return ep_item ? ep_item->ep : NULL;
}

static int coap_application_push_data_item(coap_application_t *application,
                                           int ep_handle, unsigned char *data,
                                           size_t data_len) {
  struct list_ep_t *ep_item;
  int result = 0;

  assert(application);

  ep_item = find_ep_item(application, ep_handle);
  if (ep_item) {
    struct network_data_item *data_item;

    /* allocate storage space for management structure and data */
    data_item = (struct network_data_item *)coap_malloc(
        sizeof(struct network_data_item) + data_len);

    if (data_item) {
      /* initialize data item and add to endpoint's sendqueue */
      data_item->next = NULL;
      memcpy(&data_item->remote, &ep_item->ep->addr, sizeof(coap_address_t));
      data_item->data_length = data_len;
      memcpy(data_item->data, data, data_len);

      list_add(ep_item->sendqueue, data_item);
      result = 1;
    }
  }

  return result;
}

int coap_application_attach(coap_application_t *application,
                            coap_endpoint_t *endpoint) {
  struct list_ep_t *ep_item;

  if (!endpoint)
    return 0;

  if (coap_application_find_endpoint(application, endpoint->handle))
    return 1;

  ep_item = (struct list_ep_t *)coap_malloc(sizeof(struct list_ep_t));

  if (ep_item) {
    memset(ep_item, 0, sizeof(struct list_ep_t));
    ep_item->ep = endpoint;
    LIST_STRUCT_INIT(ep_item, sendqueue);
    list_add(application->endpoints, ep_item);
  }

  return ep_item != NULL;
}

void coap_application_detach(coap_application_t *application,
                             coap_endpoint_t *endpoint) {
  struct list_ep_t *ep_item;

  if (!endpoint)
    return;

  for (ep_item = list_head(application->endpoints); ep_item;
       ep_item = list_item_next(ep_item)) {
    if (ep_item->ep == endpoint) {
      struct network_data_item *data_item;

      /* Release storage that has been allocated for outstanding
       * data.
       * FIXME: is it ok to discard all outstanding data messages
       * at this point?
       */
      while ((data_item = list_pop(ep_item->sendqueue)) != NULL) {
        coap_free(data_item);
      }
      /* TODO: remove outstanding messages for this endpoint
       * from application->coap_context->sendqueue */
      list_remove(application->endpoints, ep_item);
      coap_free_endpoint(ep_item->ep);
      coap_free(ep_item);
      break;
    }
  }
}

static void coap_check_retransmit(coap_context_t *context, coap_tick_t *next) {
  coap_tick_t now;
  coap_queue_t *nextpdu;

  nextpdu = coap_peek_next(context);

  coap_ticks(&now);
  while (nextpdu && nextpdu->t <= now) {
    coap_log(LOG_DEBUG, "call retransmit\n");
    coap_retransmit(context, coap_pop_next(context));
    nextpdu = coap_peek_next(context);
  }

  if (next && nextpdu) {
    coap_log(LOG_DEBUG, "coap_check_retransmit: nextpdu->t is %u\n",
             nextpdu->t);
    *next = nextpdu->t;
  }
}

static inline void timeval_from_ticks(coap_tick_t ticks, struct timeval *tv) {
  tv->tv_usec =
      (ticks % COAP_TICKS_PER_SECOND) * 1000000 / COAP_TICKS_PER_SECOND;
  tv->tv_sec = ticks / COAP_TICKS_PER_SECOND;
}

coap_err_t coap_application_run(coap_application_t *application) {
  fd_set readfds;
  struct timeval tv, *timeout;
  int result;
  coap_tick_t now, next_coap = 0, next_dtls = 0;
  struct list_ep_t *ep_item;

  assert(application);

  coap_ticks(&now);
  while (1) {
    FD_ZERO(&readfds);

    for (ep_item = list_head(application->endpoints); ep_item;
         ep_item = list_item_next(ep_item)) {
      FD_SET(ep_item->ep->handle, &readfds);
    }

#if HAVE_LIBTINYDTLS
    dtls_check_retransmit(application->dtls_context, &next_dtls);
#endif
    coap_check_retransmit(application->coap_context, &next_coap);

    coap_log(LOG_DEBUG, "next_dtls = %u\n", next_dtls);
    coap_log(LOG_DEBUG, "next_coap = %u\n", next_coap);
    if (next_coap && (!next_dtls || next_coap < next_dtls)) {
      timeval_from_ticks(next_coap - now, &tv);
      timeout = &tv;
      coap_log(LOG_DEBUG, "coap timeout: %u\n", next_coap - now);
    } else if (next_dtls) {
      timeval_from_ticks(next_dtls - now, &tv);
      timeout = &tv;
      coap_log(LOG_DEBUG, "dtls timeout: %u\n", next_dtls - now);
    } else {
      timeout = NULL; /* FIXME: pass timeout as parameter */
      coap_log(LOG_DEBUG, "no timeout\n");
    }

    /* wait until something happens */
    result = select(FD_SETSIZE, &readfds, 0, 0, timeout);

    if (result < 0) { /* error */
      if (errno != EINTR)
        perror("select");
      break;                 /* leave main loop */
    } else if (result > 0) { /* read from socket */
      for (ep_item = list_head(application->endpoints); ep_item;
           ep_item = list_item_next(ep_item)) {
        if (FD_ISSET(ep_item->ep->handle, &readfds)) {
          handle_read(application, ep_item->ep); /* read received data */
        }
      }
    } else { /* timeout */
             /* there is no need to do anything here as the retransmission
              * are triggered next in the main loop */
    }
  }
  return 0;
}

ssize_t coap_application_sendmsg(coap_application_t *application,
                                 coap_endpoint_t *local_interface,
                                 coap_address_t *dst, coap_pdu_t *pdu,
                                 int flags) {
  struct network_data_item *data_item;
  struct list_ep_t *ep_item =
      find_ep_item(application, local_interface->handle);
  ssize_t bytes_written;

  if (!ep_item) {
    debug("coap_application_sendmsg: endpoint not attached\n");
    return -1;
  }

  /* transmit outstanding data from local_interface destined for the
   * same peer */
  data_item = list_head(ep_item->sendqueue);
  while (data_item) {
    if (coap_address_equals(&data_item->remote, dst)) {
#ifndef NDEBUG
      if (LOG_DEBUG <= coap_get_log_level()) {
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 40
#endif
        unsigned char addr[INET6_ADDRSTRLEN + 8];

        if (coap_print_addr(dst, addr, INET6_ADDRSTRLEN + 8)) {
          debug("transmit outstanding %d bytes to %s\n", data_item->data_length,
                addr);
        }
      }
#endif

      bytes_written =
          send_to_peer(application->coap_context, local_interface, dst,
                       data_item->data, data_item->data_length);

      /* FIXME: handle bytes_written < 0 (maybe throw away everything?)
       *        handle 0 <= bytes_written < data_item->data_length
       *            --> this case possibly means that data is memmoved and
       *                we leave the loop
       */
      if (bytes_written < 0 ||
          (unsigned int)bytes_written == data_item->data_length) {
        struct network_data_item *tmp;
        tmp = data_item;
        data_item = data_item->next;
        list_remove(ep_item->sendqueue, tmp);
        coap_free(tmp);
      } else {
        memmove(&data_item->data, data_item->data + bytes_written,
                data_item->data_length - bytes_written);
        /* short write; need to stop here
         * FIXME: what to do with pdu when it is CON? */
        break;
      }

    } else {
      data_item = list_item_next(data_item);
    }
  }

  /* FIXME: need to replace coap_send*() */
  if (pdu->hdr->type == COAP_MESSAGE_CON) {
    if (coap_send_confirmed(application->coap_context, local_interface, dst,
                            pdu) == COAP_INVALID_TID) {
      debug("coap_application_sendmsg: cannot send confirmable message\n");
      coap_delete_pdu(pdu);
    }
  } else {
    if (coap_send(application->coap_context, local_interface, dst, pdu) ==
        COAP_INVALID_TID) {
      debug("coap_application_sendmsg: cannot send message\n");
      coap_delete_pdu(pdu);
    }
  }

  return 0; /* FIXME: pdu length */
}

ssize_t coap_application_send_request(coap_application_t *application,
                                      coap_endpoint_t *local_interface,
                                      coap_address_t *dst, coap_pdu_t *request,
                                      coap_response_handler_t r_hnd,
                                      int flags) {
  /* store: (dst, token, timeout) */
  memcpy(&r.remote, dst, sizeof(coap_address_t));
  r.response_handler = r_hnd;
  r.tokenlen = request->hdr->token_length;
  if (r.tokenlen)
    memcpy(&r.token, request->hdr->token, r.tokenlen);

  /* TODO: avoid storage duplication with retransmission queue */

  return coap_application_sendmsg(application, local_interface, dst, request,
                                  flags);
}
