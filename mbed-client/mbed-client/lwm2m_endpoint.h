/*
 * Copyright (c) 2017 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LWM2M_ENDPOINT_H
#define LWM2M_ENDPOINT_H

#include "include/nsdllinker.h"
#include "lwm2m_registry.h"
#include "lwm2m_notifier.h"
#include "lwm2m_send_queue.h"
#include "eventOS_event.h"
#include "protoman.h"

/** \file lwm2m_endpoint.h
 *  \brief Client Lite internal LwM2M and Device Management endpoint logic API.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define ENDPOINT_EVENT_ID               39 ///< ID for all endpoint events.
#define ENDPOINT_EVENT_BOOTSTRAP_SENT   30 ///< Bootstrap message acknowledged.
#define ENDPOINT_EVENT_BOOTSTRAP_READY  31 ///< Bootstrap done.
#define ENDPOINT_EVENT_REGISTERED       32 ///< Registration done.
#define ENDPOINT_EVENT_DEREGISTERED     33 ///< Deregistration done.
#define ENDPOINT_EVENT_REREGISTERED     34 ///< Update registration done.
#define ENDPOINT_EVENT_ERROR_BOOTSTRAP  36 ///< Bootstrap failed.
#define ENDPOINT_EVENT_ERROR_REGISTER   37 ///< Registration failed.
#define ENDPOINT_EVENT_ERROR_DEREGISTER 38 ///< Deregistration failed.
#define ENDPOINT_EVENT_ERROR_REREGISTER 39 ///< Update registration failed.
#define ENDPOINT_EVENT_ERROR_TIMEOUT    40 ///< Generic message sending timeout.

#define ENDPOINT_EVENT_STATUS_OK                   0 ///< No errors.
#define ENDPOINT_EVENT_STATUS_NO_MEMORY            1 ///< Memory allocation failed.
#define ENDPOINT_EVENT_STATUS_TIMEOUT              2 ///< Message sending timeout.
#define ENDPOINT_EVENT_STATUS_CONNECTION_ERROR     3 ///< Generic connection error.
#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
#define ENDPOINT_EVENT_STATUS_RESPONSE_FORBIDDEN   4 ///< Forbidden response to register message
#define ENDPOINT_EVENT_STATUS_RESPONSE_BAD_REQUEST 5 ///< bad request response to register message
#endif //MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE

#define ENDPOINT_MSG_UNDEFINED   0 ///< No message.
#define ENDPOINT_MSG_REGISTER    1 ///< Registration message.
#define ENDPOINT_MSG_UNREGISTER  2 ///< Unregistration message.
#define ENDPOINT_MSG_UPDATE      3 ///< Update registration message.
#define ENDPOINT_MSG_BOOTSTRAP   4 ///< Bootstrap message.

#define ENDPOINT_STATUS_OK 0 ///< Returned on successful call.
#define ENDPOINT_STATUS_ERROR (-1) ///< Returned on generic errors.
                                   ///< \note This value is expected to be smaller than 0.
#define ENDPOINT_STATUS_ERROR_MEMORY_FAILED (-2) ///< Returned on memory failure cases.
                                                 ///< \note This value is expected to be smaller than 0.

#define strlens(s) (s==NULL?0:strlen(s)) /// < Macro for calling `strlen` if the pointer is not NULL. \param s Pointer to string.

/**
 *  \brief Enumeration describing the transport mode.
 */
typedef enum oma_lwm2m_binding_and_mode_e {
    BINDING_MODE_NOT_SET = 0,    ///< Binding mode not set.
    BINDING_MODE_U = 0x01,       ///< UDP.
    BINDING_MODE_Q = 0x02,       ///< UDP with queue mode.
    BINDING_MODE_S = 0x04,       ///< SMS.
    BINDING_MODE_T = 0x09,       ///< TCP.
                                 ///< \note Not a real value, spec does not have one!
                                 ///< \note This has nsdl binding mode bit UDP set. */
    BINDING_MODE_T_Q = 0x0b      ///< TCP with queue mode.
                                 ///< \note Not a real value, spec does not have one!
                                 ///< \note This has nsdl binding mode bits, UDP and UDP_QUEUE set
} oma_lwm2m_binding_and_mode_t;

/**
 *  \brief Structure for keeping track of an ongoing confirmable CoAP response.
 */
typedef struct endpoint_confirmable_response_s {

    uint8_t token[8]; ///< Token data.
    uint8_t token_length; ///< Length of the token data.
    sn_coap_msg_code_e msg_code; ///< Response code.
    uint16_t msg_id; ///< Message ID for the response.
    registry_path_t path; ///< Path to the resource this response is associated with.

    // These were packed into bitfield, but it caused ROM increase by 64B while saving 1 byte of RAM.
    bool notify_result; ///< True if the resource expects to be notified when response is received.
    bool pending; ///< True if a response is pending to be sent.

} endpoint_confirmable_response_t;

#ifdef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
typedef struct object_handler_s object_handler_t;
#endif

/**
 *  \brief Main data structure for Client Lite LwM2M endpoint.
 */
typedef struct endpoint_s {

    // even though this is a bit large, this is good to keep here, as it is used a lot
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    registry_t registry; ///< Data allocated for registry.
#endif
    int8_t event_handler_id; ///< ID of the event handler for the endpoint events.

    // These next small variables were tightly packed into bitfield, which saved ~3 bytes of RAM. But
    // it came with expense of 128 bytes of ROM in Cotrex M0. So this version trades off the RAM to ROM.

    uint8_t message_type; ///< Type of the currently processed message.
    uint8_t last_message_type; ///< Type of the last endpoint message sent.
    oma_lwm2m_binding_and_mode_t mode; ///< Binding mode.
    bool free_parameters; ///< If != 0, `name`, `type` and `domain` will be passed to `lwm2m_free` when `endpoint_destroy` is called.
    bool registered; ///< Flag used for checking if the endpoint is currently registered to the server.
#if defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP) || defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE)
    bool coap_ping_request; ///< CoAP ping request is pending.
#endif
    uint16_t tick_remainder; ///< tick-rate is EVENTOS_EVENT_TIMER_HZ/s, use it to update coap_time in case of starvation.
    send_queue_t send_queue; ///< Data allocated for send queue.

    struct connection_s *connection; ///< Pointer to connection.
    struct coap_s *coap; ///< Pointer to the CoAP library.
    const char *type; ///< Endpoint type, a null-terminated string or NULL.
    char *location; ///< Server location read from response message, a null-terminated string or NULL.
    char *custom_uri_query_params; ///< Custom URI query parameters, a null-terminated string or NULL.
    void *event_data; ///< The value of this pointer is set to `event_data` field of outgoing events.
    timeout_t *coap_timeout; ///< Timer, used for running the CoAP protocol module.
    uint32_t coap_time; ///< Counter counting seconds, used for timing the CoAP protocol module.
    uint32_t message_token; ///< Used for storing the token of the last sent endpoint message.
#if defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP) || defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE)
    uint32_t next_coap_ping_send_time; ///< In seconds, new time is calculated after packet sending.
    uint16_t coap_ping_id; ///< Message ID of the last CoAP ping.
#endif


#ifdef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    object_handler_t *object_handlers; //Object owners
#if MBED_CLIENT_ENABLE_AUTO_OBSERVATION
    uint16_t auto_obs_token; ///< For internal use only, MUST NOT be accessed from application.
#endif
    uint32_t lifetime;
    uint8_t security_mode;
    char *server_uri;
#endif

    notifier_t notifier; ///< Data allocated for notifier.

    endpoint_confirmable_response_t confirmable_response; ///< Data allocated for storing a response.
    uint32_t old_tick; ///< save value of eventOS_event_timer_ticks, at beetween endpoint_get_coap_time calls.

} endpoint_t;

#ifdef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
typedef struct register_resource_s register_resource_t;

struct register_resource_s {
    const char *full_res_id; // in form "/1/0/1" - the buffer pointed to must exist for the lifetime of the struct instance
    uint16_t aobs_id;

#if MBED_CLIENT_ENABLE_PUBLISH_RESOURCE_VALUE_IN_REG_MSG
    uint8_t *value; //NOTE: Use lwm2m_alloc!
    uint16_t value_len;
#endif
    register_resource_t *next;
};

// Allocate and populate list of resources. Ownership will be transferred to caller, who must free the resources when done.
typedef int (get_resources_cb)(endpoint_t *endpoint, register_resource_t **resources);
typedef sn_coap_hdr_s *(coap_req_cb)(const registry_path_t* path,
                                     endpoint_t *endpoint,
                                     const sn_coap_hdr_s *request,
                                     sn_nsdl_addr_s *src_addr,
                                     sn_coap_hdr_s *response,
                                     int *acked);

struct object_handler_s {
    uint16_t object_id;
    get_resources_cb *res_cb;
    coap_req_cb *req_cb;
    registry_callback_t obj_cb;
    object_handler_t *next;
};
#endif

/**
 * \brief Initialize the endpoint structure.
 *
 * \note The endpoint must be allocated from memory before calling this function
 *       and the memory allocation must stay valid until the endpoint is destroyed.
 * \note This function must be called before calling any other endpoint functions.
 *
 * \param endpoint Pointer to the endpoint to be used.
 * \param connection Pointer to the connection structure to be used with this endpoint.
 * \param event_data Pointer to data that will be set to `event_data` field inside
 *                   the events sent by the endpoint to event handler. The ID of the event handler is
 *                   later given as parameter `event_handler_id` to function `endpoint_setup`.
 * \param mode Binding mode for this endpoint.
 * \param free_parameters If != 0, `endpoint->name`, `endpoint->type`, `endpoint->domain` will be passed to
 *                        `lwm2m_free` when `endpoint_destroy` is called.
 */
void endpoint_init(endpoint_t *endpoint, struct connection_s *connection,
                  void *event_data, const oma_lwm2m_binding_and_mode_t mode, const uint8_t free_parameters);

/**
 * \brief Set up the endpoint that has been initialized `using endpoint_init`.
 *
 * \note This function MUST NOT be called before calling `endpoint_init`.
 *
 * \param endpoint Pointer to the endpoint to be used.
 * \param event_handler_id Event handler ID registered using `eventOS_event_handler_create()`
 *                         for receiving endpoint related events.
 *
 * \return ENDPOINT_STATUS_OK Endpoint setup complete.
 * \return ENDPOINT_STATUS_ERROR Setup failed, endpoint MUST NOT be used.
 *
 */
int endpoint_setup(endpoint_t *endpoint, int8_t event_handler_id);

/**
 * \brief Stop the endpoint temporarily.
 *        While the endpoint is stopped it will not send or receive any packets.
 *
 * \param endpoint Pointer to the endpoint to be stopped.
 */
void endpoint_stop(endpoint_t *endpoint);

/**
 * \brief Destroy the endpoint.
 *
 * \note After calling this function, the endpoint stucture passed to this function
 *       must not be used, unless `endpoint_init` and `endpoint_setup` are called again.
 *
 * \param endpoint Pointer to the endpoint to be destroyed.
 */
void endpoint_destroy(endpoint_t *endpoint);

/**
 * \brief Set endpoint parameters.
 *
 * \note The optimal way of using this function would be to give all the available parameters with one call.
 *
 * \param endpoint Pointer to the endpoint to which the parameters are set.
 * \param type Endpoint type, a null-terminated string or NULL.
 * \param life_time Lifetime of the endpoint in seconds or 0.
 *
 * \return true Parameters set successfully.
 * \return false Parameter setting failed.
 *
 */
bool endpoint_set_parameters(endpoint_t *endpoint, const char *type, int32_t life_time);

/**
 * \brief Send a pending endpoint related message.
 *
 * \note This function should only be called by the message queue after
 *       the endpoint has requested a message sending time from message queue.
 *
 * \param endpoint Pointer to the endpoint structure.
 */
void endpoint_send_message(endpoint_t *endpoint);

/**
 * \brief Start the registration process for the endpoint.
 *
 * \note Required parameters must be set before calling this function.
 * \note This function only triggers the registration process, the
 *       status is delivered using the endpoint event.
 *
 * \param endpoint Pointer to the endpoint to be registered.
 *
 * \return ENDPOINT_STATUS_OK Registration successfully started.
 * \return ENDPOINT_STATUS_ERROR Other endpoint operation already ongoing.
 */
int endpoint_register(endpoint_t *endpoint);

#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
/**
 * \brief Start the bootstrap process for the endpoint.
 *
 * \note Required parameters MUST be set before calling this function.
 * \note This function only triggers the bootstrap process, the
 *       status is delivered using the endpoint event.
 *
 * \param endpoint Pointer to the endpoint to be bootstrapped.
 *
 * \return ENDPOINT_STATUS_OK Bootstrap successfully started.
 * \return ENDPOINT_STATUS_ERROR Other endpoint operation already ongoing.
 */
int endpoint_bootstrap(endpoint_t *endpoint);
#endif

/**
 * \brief Start the update registration process for the endpoint.
 *
 * \note The endpoint should be registered before calling this function.
 * \note This function only triggers the update registration, the
 *       status is delivered using the endpoint event.
 *
 * \param endpoint Pointer to the endpoint that has its registration updated.
 *
 * \return ENDPOINT_STATUS_OK Update registration process successfully started.
 * \return ENDPOINT_STATUS_ERROR Other endpoint operation already ongoing.
 */
int endpoint_update_registration(endpoint_t *endpoint);

/**
 * \brief Start the unregister process for the endpoint.
 *
 *  \note The endpoint should be registered before calling this function.
 *  \note This function only triggers the unregister process, the
 *        status is delivered using the endpoint event.
 *
 * \param endpoint Pointer to the endpoint to be unregistered.
 *
 * \return ENDPOINT_STATUS_OK Unregistration process successfully started.
 * \return ENDPOINT_STATUS_ERROR Other endpoint operation already ongoing.
 */
int endpoint_unregister(endpoint_t *endpoint);

/**
 * \brief Send endpoint related statuses.
 *
 * \param endpoint Pointer to the endpoint the status is related to.
 * \param type Endpoint event type.
 * \param coap_msg_status CoAP status from related CoAP message.
 *
 * \return ENDPOINT_STATUS_OK Event sent successfully.
 * \return ENDPOINT_STATUS_ERROR Event allocation failed, nothing is sent.
 */
int endpoint_send_event(endpoint_t *endpoint, uint8_t type, uint32_t coap_msg_status);

/**
 * \brief Pass a packet received from the connection that is linked to this endpoint.
 *
 * \param endpoint Pointer to the endpoint that the data is addressed to.
 * \param packet_ptr Pointer to the raw data.
 * \param packet_len Length of the data pointed by `packet_ptr`.
 * \param src_ptr Pointer to the source address structure.
 *
 * \return ENDPOINT_STATUS_OK Data processed.
 * \return ENDPOINT_STATUS_ERROR Data processing failed.
 */
int endpoint_process_coap(endpoint_t *endpoint, uint8_t *packet_ptr, uint16_t packet_len, sn_nsdl_addr_s *src_ptr);

/**
 * \brief Build and send a CoAP packet using the connection that is linked to this endpoint.
 *
 * \param endpoint Pointer to the endpoint that is used.
 * \param address_ptr Pointer to a destination address structure.
 * \param coap_hdr_ptr Pointer to a CoAP structure that is used for building the actual CoAP message.
 *
 * \return ENDPOINT_STATUS_OK Message sent.
 * \return ENDPOINT_STATUS_ERROR Message sending failed.
 * \return ENDPOINT_STATUS_ERROR_MEMORY_FAILED Memory allocation failed, message not sent.
 */
int endpoint_send_coap_message(endpoint_t *endpoint, sn_nsdl_addr_s *address_ptr, sn_coap_hdr_s *coap_hdr_ptr);

/**
 * \brief Return the message type of the last endpoint registration related message sent.
 *
 * \note This status does not tell whether the message was successfully delivered.
 *
 * \param endpoint Pointer to the endpoint.
 *
 * \return ENDPOINT_MSG_UNDEFINED No endpoint messages sent yet.
 * \return ENDPOINT_MSG_REGISTER Register message is the latest message sent.
 * \return ENDPOINT_MSG_UNREGISTER Unregister message is the latest message sent.
 * \return ENDPOINT_MSG_UPDATE Update Register message is the latest message sent.
 * \return ENDPOINT_MSG_BOOTSTRAP Bootstrap message is the latest message sent.
 */
unsigned int endpoint_last_message_sent(const endpoint_t *endpoint);

/**
 * \brief Set new lifetime for endpoint registration. The value is set to lifetime Resource (/1/0/1).
 *
 * \note The new lifetime will become effective after next (update) registration.
 *
 * \param endpoint Pointer to the endpoint to be configured.
 * \param lifetime New lifetime value to be set.
 *
 * \note IF `lifetime` != 0 && `lifetime` < `MINIMUM_REGISTRATION_TIME` the
 *       `lifetime` is set as `MINIMUM_REGISTRATION_TIME`.
 *
 * \return ENDPOINT_STATUS_OK Lifetime set successfully.
 * \return ENDPOINT_STATUS_ERROR Setting lifetime value failed.
 */
int endpoint_set_lifetime(endpoint_t *endpoint, uint32_t lifetime);

/**
 * \brief Get current lifetime for endpoint registration from lifetime Resource.
 *
 * \param endpoint Pointer to the endpoint structure.
 * \param lifetime MUST be a valid valid pointer to `uint32_t` where the lifetime is written to
 *                 after a successful call.
 *
 * \return ENDPOINT_STATUS_OK Lifetime set successfully to lifetime parameter.
 * \return ENDPOINT_STATUS_ERROR Getting lifetime value failed.
 */
int endpoint_get_lifetime(const endpoint_t *endpoint, uint32_t *lifetime);

/**
 * \brief Add custom URI query parameters that will be added to bootstrap and register message
 *        if they are sent after this call.
 *
 * \param endpoint Pointer to the endpoint to be configured.
 * \param uri_query_params One or more URI query parameters, in null-terminated string format.
 *
 * \return true Parameter successfully added.
 * \return false Failed to add parameter.
 */
bool endpoint_set_uri_query_parameters(endpoint_t *endpoint, const char *uri_query_params);

/**
 * \brief Stop the CoAP protocol timed functions.
 *
 * \param endpoint Pointer to the endpoint to be configured.
 */
void endpoint_stop_coap_exec_timer(endpoint_t *endpoint);

/**
 * \brief Start the CoAP protocol timed functions.
 *
 * \note Starting the timer may fail, but it is not reported to
 *       the caller of this function.
 *
 * \param endpoint Pointer to the endpoint to be configured.
 */
void endpoint_start_coap_exec_timer(endpoint_t *endpoint);

#if defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP) || defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE)
void endpoint_send_coap_ping(endpoint_t *endpoint);
#endif

#ifdef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
/**
 * @brief Register object handler
 *
 *  Register object handlers allocated with `endpoint_allocate_object_handler`.
 *
 * \note When registering multiple handlers from a single source they can be passed in as a list,
 *       and in this case only one needs to set the res_cb pointer. One res_cb instance
 *       can iterate through all needed resources.
 *
 * @param endpoint Pointer to the endpoint.
 * @param owner A list of objects owned. Ownership is transferred.
 */
void endpoint_register_object_handler(endpoint_t *endpoint, object_handler_t *handler);

/**
 * @brief Deallocate registered object handlers
 *
 *  Deallocate object handlers allocated with `endpoint_allocate_object_handler` and
 *  registered with `endpoint_register_object_handler`.
 *
 * \note Called automatically on PDMC deinit.
 *
 * @param endpoint Pointer to the endpoint.
 */
void endpoint_deallocate_object_handlers(endpoint_t *endpoint);

/**
 * @brief Allocate object handler
 *
 * @param object_id ID of the object.
 * @param res_cb Resource list getter callback.
 * @param req_cb Coap request handler callback.
 * @param obj_cb Object callback.
 * @return pointer to object_handler or NULL if no memory
 */
object_handler_t *endpoint_allocate_object_handler(uint16_t object_id, get_resources_cb *res_cb,
                                                   coap_req_cb *req_cb, registry_callback_t obj_cb);

register_resource_t *endpoint_create_register_resource_str(endpoint_t *endpoint, const char *id,
                                                           bool auto_obs, const uint8_t *value,
                                                           uint16_t len);

register_resource_t *endpoint_create_register_resource_int(endpoint_t *endpoint, const char *id,
                                                           bool auto_obs, int64_t val);

register_resource_t *endpoint_create_register_resource_opaque(endpoint_t *endpoint, const char *id,
                                                              bool auto_obs, const uint8_t *value,
                                                              uint16_t len);

register_resource_t *endpoint_create_register_resource(endpoint_t *endpoint, const char *id,
                                                       bool auto_obs);

coap_req_cb *endpoint_get_coap_request_callback(endpoint_t *endpoint, uint16_t object_id);

registry_callback_t endpoint_get_object_callback(endpoint_t *endpoint, uint16_t object_id);

int endpoint_send_notification_int(endpoint_t *endpoint, registry_path_t *path, uint16_t aobs_id, int64_t value);

#endif

#ifdef __cplusplus
}
#endif

#endif //LWM2M_ENDPOINT_H
