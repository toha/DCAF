/* app.h -- CoAP application
 *
 * Copyright (C) 2010--2013 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#ifndef _COAP_APP_H_
#define _COAP_APP_H_


#include <libcoap/coap.h>

#if HAVE_LIBTINYDTLS
#define HAVE_STR
#define WITH_SHA256
#include <tinydtls/dtls.h>
#endif

#ifdef HAVE_ASSERT_H
#include <assert.h>
#else
#ifndef assert
#warning "assertions are disabled"
#  define assert(x)
#endif
#endif

typedef struct coap_application_t {
  coap_context_t *coap_context;
#if HAVE_LIBTINYDTLS
  dtls_context_t *dtls_context;
#endif
  LIST_STRUCT(endpoints);
  void *app;			/**< application-specific data */
} coap_application_t;

typedef int coap_err_t;

/**
 * Creates a new CoAP application object. This function returns a
 * pointer to a new coap_application_t object or @c NULL on error.
 * The storage allocated by this object must be released by
 * coap_free_application().
 */
coap_application_t *coap_new_application();

/**
 * Deletes a CoAP application object that was created using
 * coap_new_application().  The The storage allocated by @p
 * application is released.
 *
 * @param application The application object to delete.
 */
void coap_free_application(coap_application_t *application);

#define coap_application_set_app_data(APP,DATA) ((APP)->app = (DATA))
#define coap_application_get_app_data(APP) ((APP)->app)

/**
 * Attaches the specified endpoint object to application. This
 * function returns @c 1 if the endpoint was attached successfully,
 * @c 0 otherwise. On success, the storage allocated for endpoint
 * is released automatically by coap_application_detach().
 *
 * @param application The application context
 * @param endpoint    The endpoint object to register with @p application
 * @return @c 1 on success, @c 0 otherwise
 */
int coap_application_attach(coap_application_t *application,
			    coap_endpoint_t *endpoint);

/**
 * Removes the given endpoint from application's endpoint list. If
 * found, the storage allocated for @p endpoint is released.
 *
 * @param application The application context
 * @param endpoint    The endpoint object to detach
 */
void coap_application_detach(coap_application_t *application,
			     coap_endpoint_t *endpoint);

/**
 * Starts the given CoAP application.
 *
 * @param application The application to run
 * @return @c 0 if exited normally. A return value less than zero indicates
 *  an error condition.
 */
coap_err_t coap_application_run(coap_application_t *application);

/**
 * Sends given @p pdu on @p local_interface to @p dst.
 */
ssize_t coap_application_sendmsg(coap_application_t *application,
				 coap_endpoint_t *local_interface,
				 coap_address_t *dst, coap_pdu_t *pdu,
				 int flags);

/**
 * Sends the request given in @p request on @p local_interface to @p
 * dst.  If @p r_hnd is not NULL, an incoming response to @p request
 * is delivered to @p r_hnd.
 *
 * @todo: add timeout
 */
ssize_t coap_application_send_request(coap_application_t *application,
				      coap_endpoint_t *local_interface,
				      coap_address_t *dst, coap_pdu_t *request,
				      coap_response_handler_t r_hnd,
				      int flags);

#endif /* _COAP_APP_H_ */
