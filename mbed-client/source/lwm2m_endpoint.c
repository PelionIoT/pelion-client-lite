/*
 * Copyright (c) 2017-2021 Pelion. All rights reserved.
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

#include "include/uriqueryparser.h"
#include "mbed-client/lwm2m_callback_handler.h"
#include "mbed-client/lwm2m_config.h"
#include "mbed-client/lwm2m_connection.h"
#include "mbed-client/lwm2m_constants.h"
#include "mbed-client/lwm2m_endpoint.h"
#include "mbed-client/lwm2m_req_handler.h"
#include "mbed-client/lwm2m_heap.h"
#include "mbed-client/lwm2m_notifier.h"
#include "mbed-client/lwm2m_registry.h"
#include "device-management-client/lwm2m_registry_handler.h"
#include "mbed-client/lwm2m_registry_meta.h"
#include "mbed-client/lwm2m_storage.h"
#include "randLIB.h"
#include "mbed-trace/mbed_trace.h"
#include "token_generator.h"
#include "common_functions.h"
#include "mbed-coap/sn_coap_protocol.h"
#ifdef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
#include "sn_coap_protocol_internal.h"
#endif
#include "mbedtls/base64.h"

#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h> // snprintf

#define TRACE_GROUP "lwEP"

static const char MCC_VERSION[] = "mccv=1.4.0-lite";
#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
static const char iep_name_parameter[] ="iep="; /* Internal endpoint name*/
#endif //MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
static const char ep_name_parameter[]  = "ep="; /* Endpoint name. A unique name for the registering node in a domain.  */
static const uint8_t resource_path[] = {'r', 'd'}; /* For resource directory */
#ifdef MBED_CONF_MBED_CLIENT_REGISTER_RESOURCE_NAME
static const char resource_type_parameter[] = {'r', 't', '='}; /* Resource type. Only once for registration */
#endif
#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
static const uint8_t bs_uri[] = {'b', 's'};
static const char bs_ep_name[] = "ep="; // same as normal ep-name?!
#endif
static const char ep_lifetime_parameter[] = "lt="; /* Lifetime. Number of seconds that this registration will be valid for. Must be updated within this time, or will be removed. */
static const char et_parameter[] = "et="; /* Endpoint type */
static const char bs_queue_mode[] = "b=";
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
static const char obs_parameter[] = {'o', 'b', 's'}; /* Observable */
#endif
#if MBED_CLIENT_ENABLE_AUTO_OBSERVATION
static const char auto_obs_parameter[] = {'a', 'o', 'b', 's', '='}; /* Auto observable */
#endif
#if MBED_CLIENT_ENABLE_PUBLISH_RESOURCE_VALUE_IN_REG_MSG
static const char resource_value[] = {'v', '='}; /* Resource value */
#endif

static int endpoint_register_endpoint(endpoint_t *endpoint, sn_nsdl_addr_s *address, const char *uri_query_parameters);
static int endpoint_update_or_unregister_endpoint(endpoint_t *endpoint, sn_nsdl_addr_s *address, uint8_t message_type);
static int endpoint_oma_bootstrap(endpoint_t *endpoint, sn_nsdl_addr_s *bootstrap_address_ptr, const char *uri_query_parameters);
static int endpoint_send_pending_message(endpoint_t *endpoint);
static int endpoint_internal_coap_send(endpoint_t *endpoint, sn_coap_hdr_s *coap_header_ptr, sn_nsdl_addr_s *dst_addr_ptr, uint8_t message_description);

// if bootstrap server has not set the transport binding, we set the default value through this function
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
static int endpoint_reset_binding_mode(registry_t *registry, const oma_lwm2m_binding_and_mode_t mode);
#endif

#ifndef SN_COAP_DISABLE_RESENDINGS
static int endpoint_set_retransmission_parameters(endpoint_t *endpoint);
#endif

static uint8_t* write_char(uint8_t *data, const char character, int32_t *len);
static uint8_t* write_int(uint8_t *data, uint32_t value, int32_t *len);
static uint8_t* write_data(uint8_t *to, const char *from, uint16_t len, int32_t *packet_len);
#ifdef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
static uint8_t *write_resource(uint8_t *data, register_resource_t *iter, int32_t *len);
#endif
static uint8_t *write_string(uint8_t *to, const char *from, int32_t *packet_len);
static uint8_t *write_string_pair(uint8_t *to, const char *from1, const char *from2, int32_t *packet_len);
static uint8_t *write_parameter(uint8_t *packet, const char *parameter, uint8_t parameter_len, const char *value, uint16_t value_len, uint8_t no_value, int32_t *packet_len);
#if MBED_CLIENT_ENABLE_PUBLISH_RESOURCE_VALUE_IN_REG_MSG
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
static uint8_t *write_resource_value(uint8_t *packet, const registry_path_t *path, int32_t *packet_len, const endpoint_t *endpoint);
#endif
#endif
#ifdef MBED_CONF_MBED_CLIENT_REGISTER_RESOURCE_NAME
static uint8_t *write_resource_name(uint8_t *packet, const registry_path_t *path, int32_t *packet_len);
#endif
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
static uint8_t *write_path(uint8_t *packet, const registry_path_t *path, int32_t *packet_len);
#endif
static uint8_t *write_query_parameters(uint8_t *dest, const char *uri_query_parameters, int32_t *packet_len);
static uint8_t *write_uri_query_options(uint8_t *temp_ptr, const endpoint_t *endpoint,
                                     bool update,
                                     const char *uri_query,
                                     int32_t *buffer_left);
#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
static uint8_t *write_bs_uri_query_options(uint8_t *temp_ptr, const endpoint_t *endpoint,
                                     const char *uri_query,
                                     int32_t *buffer_left);
#endif

static int endpoint_build_registration_body(endpoint_t *endpoint, sn_coap_hdr_s *message_ptr, uint8_t updating_registeration, int32_t *len);
static int endpoint_fill_uri_query_options(endpoint_t *endpoint, sn_coap_hdr_s *source_msg_ptr, bool update, const char *uri_query);
static void endpoint_print_coap_data(const sn_coap_hdr_s *coap_header_ptr, bool outgoing);
static void endpoint_handle_response(endpoint_t *endpoint, sn_coap_hdr_s *coap_header);
static int endpoint_handle_registration_response(endpoint_t *endpoint, const sn_coap_hdr_s *coap_header);

#if defined(FEA_TRACE_SUPPORT) || MBED_CONF_MBED_TRACE_ENABLE || YOTTA_CFG_MBED_TRACE || (defined(YOTTA_CFG) && !defined(NDEBUG))
static const char *endpoint_coap_status_description(sn_coap_status_e status);
static const char *endpoint_coap_message_code_desc(int msg_code);
static const char *endpoint_coap_message_type_desc(int msg_type);
#endif

static bool validate_parameters(const endpoint_t *endpoint);
static bool validate(const char* ptr, char illegalChar);
static bool is_empty(const char* ptr);

static uint8_t coap_tx_callback(uint8_t *data_ptr, uint16_t data_len, sn_nsdl_addr_s *address_ptr, void *param);
static int8_t endpoint_rx_function(sn_coap_hdr_s *coap_packet_ptr, sn_nsdl_addr_s *address_ptr, void* param);

static void* lwm2m_alloc_uint16(uint16_t size);

static uint32_t endpoint_get_coap_time(endpoint_t *ep);
static void endpoint_coap_timer(void *ep);

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
static size_t endpoint_itoa_len(uint32_t value);
static uint8_t *endpoint_itoa(uint8_t *ptr, uint32_t value);
#else
static size_t endpoint_itoa_len(int64_t value);
static uint8_t *endpoint_itoa(uint8_t *ptr, int64_t value);
#endif
static int get_nsdl_address(const endpoint_t *endpoint, sn_nsdl_addr_s *address);
#if defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP) || defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE)
static void endpoint_request_coap_ping(endpoint_t *endpoint);
static void calculate_new_coap_ping_send_time(endpoint_t *endpoint);
#endif

static bool endpoint_command(endpoint_t *endpoint, unsigned message_type);

static uint32_t endpoint_get_coap_time(endpoint_t *ep)
{
    uint32_t old_tick = ep->old_tick; // initialized to value of eventOS_event_timer_ticks()
    uint_fast16_t remainder = ep->tick_remainder; // initialized to 50
    uint32_t current_tick = eventOS_event_timer_ticks();
    remainder += current_tick - old_tick;
    // If multiple seconds has passed between calls this loop will fast-forward to catch up.
    // nanostack-eventloop tick-rate is EVENTOS_EVENT_TIMER_HZ/s, so EVENTOS_EVENT_TIMER_HZ ticks elapsed == 1 second elapsed.
    while (remainder >= EVENTOS_EVENT_TIMER_HZ) {
        remainder -= EVENTOS_EVENT_TIMER_HZ;
        ep->coap_time++;
    }
    ep->old_tick = current_tick;
    ep->tick_remainder = remainder;

    return ep->coap_time;
}

static void endpoint_coap_timer(void *ep)
{
    endpoint_t *endpoint = ep;
    sn_coap_protocol_exec(endpoint->coap, endpoint_get_coap_time(endpoint));
#if defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP) || defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE)
    endpoint_request_coap_ping(endpoint);
#endif
}

void endpoint_init(endpoint_t *endpoint, connection_t *connection,
                     void *event_data, const oma_lwm2m_binding_and_mode_t mode, const uint8_t free_parameters)
{
    assert(endpoint);
    assert(connection);

    endpoint->coap = NULL;
    endpoint->coap_time = 0;
    endpoint->coap_timeout = 0;

    endpoint->connection = connection;
    endpoint->free_parameters = free_parameters;
    endpoint->registered = false;
    endpoint->mode = mode;

    endpoint->event_data = event_data;
    endpoint->event_handler_id = -1;

    endpoint->type = NULL;
    endpoint->location = NULL; //TODO: Check if this information could be read from other fields.
    endpoint->custom_uri_query_params = NULL;

#if defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP) || defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE)
    endpoint->coap_ping_id = 0;
    endpoint->coap_ping_request = false;
    endpoint->next_coap_ping_send_time = 0;
#endif

#ifdef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    endpoint->object_handlers = NULL;
    endpoint->auto_obs_token = 0;
    endpoint->lifetime = 0;
    endpoint->security_mode = 0;
    endpoint->server_uri = NULL;
#endif

    endpoint->message_type = ENDPOINT_MSG_UNDEFINED;
    endpoint->last_message_type = ENDPOINT_MSG_UNDEFINED;

    endpoint->confirmable_response = (endpoint_confirmable_response_t) {{0}};

    send_queue_init(&endpoint->send_queue);
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    registry_init(&endpoint->registry, &endpoint->notifier);
    notifier_init(&endpoint->notifier, endpoint);
#endif
}

int endpoint_setup(endpoint_t *endpoint, int8_t event_handler_id)
{
    assert(endpoint);

    randLIB_seed_random();

    endpoint->coap = sn_coap_protocol_init(&lwm2m_alloc_uint16, &lwm2m_free, &coap_tx_callback, &endpoint_rx_function);
    if (!endpoint->coap) {
        return ENDPOINT_STATUS_ERROR;
    }

    endpoint->event_handler_id = event_handler_id;

    endpoint->old_tick = eventOS_event_timer_ticks();
    // To reduce the effect of jitter remainder is originally initialized to 50.
    // Time is incremented if remainder is in range 50-150, i.e. "in the middle of a second".
    // This allows up to 0.5s jitter before gaps or clumping in the tick values coap library sees.
    endpoint->tick_remainder = 50;

    endpoint->coap_time = 0;

    endpoint->coap_timeout = eventOS_timeout_every_ms(&endpoint_coap_timer, 1000, endpoint);
    if (!endpoint->coap_timeout) {
        return ENDPOINT_STATUS_ERROR;
    }

#ifndef SN_COAP_DISABLE_RESENDINGS
    sn_coap_protocol_set_retransmission_parameters(endpoint->coap, MBED_CLIENT_RECONNECTION_COUNT, MBED_CLIENT_RECONNECTION_INTERVAL);
#endif

    // TODO: rename this to a setup and make it return status
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    callback_handler_init(&endpoint->registry);

    if (ENDPOINT_STATUS_OK != endpoint_reset_binding_mode(&endpoint->registry, endpoint->mode)) {
        sn_coap_protocol_destroy(endpoint->coap);
        return ENDPOINT_STATUS_ERROR;
    }
#else
    callback_handler_init(endpoint);
#endif

    if (ENDPOINT_STATUS_OK != endpoint_set_lifetime(endpoint, 0)) {
        sn_coap_protocol_destroy(endpoint->coap);
        return ENDPOINT_STATUS_ERROR;
    }

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    if (notifier_setup(&endpoint->notifier) == false) {
        sn_coap_protocol_destroy(endpoint->coap);
        return ENDPOINT_STATUS_ERROR;
    }
#endif

    return ENDPOINT_STATUS_OK;
}


void endpoint_stop(endpoint_t *endpoint)
{
    // Clear CoAP queues.
    sn_coap_protocol_clear_sent_blockwise_messages(endpoint->coap);
    sn_coap_protocol_clear_retransmission_buffer(endpoint->coap);

    send_queue_stop(endpoint);

    // Clear endpoint sending states.
    endpoint->message_type = ENDPOINT_MSG_UNDEFINED;
    endpoint->registered = false;
    endpoint->confirmable_response.pending = false;
    endpoint->confirmable_response.msg_id = 0;

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    // This clears notifier states and continues after reconnection.
    notifier_continue(&endpoint->notifier);
#endif

    // Set resend flag to GET requests
    req_handler_set_resend_status();

    // Request runtime for GET handler to continue later if required.
    send_queue_request(endpoint, SEND_QUEUE_REQUEST);
}

void endpoint_destroy(endpoint_t *endpoint)
{
    if (!endpoint) {
        // calling a destroy for NULL is ok
        return;
    }

    send_queue_stop(endpoint);

    eventOS_timeout_cancel(endpoint->coap_timeout);

    endpoint->coap_timeout = NULL;

    sn_coap_protocol_destroy(endpoint->coap);

    endpoint->coap = NULL;

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    notifier_stop(&endpoint->notifier);
#endif

    req_handler_destroy();

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    registry_destroy(&endpoint->registry);
#endif

    lwm2m_free(endpoint->location);

    endpoint->location = NULL;

    lwm2m_free(endpoint->custom_uri_query_params);

    endpoint->custom_uri_query_params = NULL;

    if (!endpoint->free_parameters) {
        return;
    }

#ifdef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    while (endpoint->object_handlers) {
        object_handler_t *rest = endpoint->object_handlers->next;
        lwm2m_free(endpoint->object_handlers);
        endpoint->object_handlers = rest;
    }

    lwm2m_free(endpoint->server_uri);
#endif

    lwm2m_free((void*)endpoint->type);
}

// XXX: this code is a bit questionable, as it is more space efficient and more clear codewise
// for the caller just edit the one field of the struct instead of passing 5 default values.
bool endpoint_set_parameters(endpoint_t *endpoint, const char *type, int32_t life_time)
{
    assert(endpoint);

    if (type) {
        if (!is_empty(type)) {
            endpoint->type = type;
        } else {
            return false;
        }
    }

    if (life_time > 0) {
        if (ENDPOINT_STATUS_OK != endpoint_set_lifetime(endpoint, life_time)) {
            return false;
        }
    }

    return validate_parameters(endpoint);
}

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
int endpoint_reset_binding_mode(registry_t *registry, const oma_lwm2m_binding_and_mode_t mode) {

    registry_path_t binding_path;
    registry_set_path(&binding_path, M2M_SERVER_ID, 0, SERVER_BINDING, 0, REGISTRY_PATH_RESOURCE);
    bool empty;
    registry_status_t status = registry_is_value_empty(registry, &binding_path, &empty);

    if (status != REGISTRY_STATUS_OK && status != REGISTRY_STATUS_NO_DATA) {
        tr_error("reset_binding_mode() could not check resource emptyness from registry");
        return ENDPOINT_STATUS_ERROR;
    }

    if (status == REGISTRY_STATUS_NO_DATA || empty) {
        // set the default binding mode to first server object (we only support one)
        const char *binding_mode;

        switch (mode) {
            case BINDING_MODE_U:
#if defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP) || defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE)
            case BINDING_MODE_T:
#endif
                binding_mode = BINDING_MODE_UDP;
                break;
            case BINDING_MODE_Q:
#if defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP) || defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE)
            case BINDING_MODE_T_Q:
#endif
                binding_mode = BINDING_MODE_UDP_QUEUE;
                break;
            case BINDING_MODE_S:
                binding_mode = BINDING_MODE_SMS;
                break;
            case BINDING_MODE_NOT_SET:
            default:
                binding_mode = "";
                break;
        }

        if (registry_set_value_string(registry, &binding_path, (char*)binding_mode, 0) != REGISTRY_STATUS_OK) {
            tr_error("set_binding_mode() setting mode to registry failed");
            return ENDPOINT_STATUS_ERROR;
        }
    }

    return ENDPOINT_STATUS_OK;
}
#endif

static int get_nsdl_address(const endpoint_t *endpoint, sn_nsdl_addr_s *address)
{
    if (CONNECTION_STATUS_OK != connection_get_server_address(endpoint->connection, &address->addr_ptr, &address->addr_len, &address->port)) {
        return ENDPOINT_STATUS_ERROR;
    }

    if (address->addr_len == 4) {
        address->type = SN_NSDL_ADDRESS_TYPE_IPV4;
    } else {
        address->type = SN_NSDL_ADDRESS_TYPE_IPV6;
    }

    return ENDPOINT_STATUS_OK;
}

static void read_query_parameters(const endpoint_t *endpoint, char *address_copy, char* uri_query_params)
{
    char* query;
    query = query_string(address_copy);
#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    int32_t iep_size = 0;
    if (endpoint->message_type == ENDPOINT_MSG_BOOTSTRAP) {
        storage_read_internal_endpoint_name(NULL, &iep_size, true);
    }
#endif // MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE

    if (query != NULL) {
        size_t query_len = 1 + strlen(query) + 1 + strlen(MCC_VERSION) + 1;
        if (endpoint->custom_uri_query_params) {
            query_len += 1 + strlen(endpoint->custom_uri_query_params);
        }
#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
        if (iep_size > 0) {
            query_len += 1 + strlen(iep_name_parameter) + iep_size;
        }
#endif // MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
        if (query_len <= MAX_URI_QUERY_LEN) {
            strcpy(uri_query_params, "&");
            strcat(uri_query_params, query);
#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
            if (iep_size > 0) {
                char iep[MAX_VALUE_LENGTH];
                strcat(uri_query_params, "&");
                strcat(uri_query_params, iep_name_parameter);
                iep[iep_size] = '\0'; //strcat need null char
                if (NULL !=storage_read_internal_endpoint_name(iep, &iep_size, true)){
                    strcat(uri_query_params, iep);
                }
            }
#endif // MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
            strcat(uri_query_params, "&");
            strcat(uri_query_params, MCC_VERSION);
            if (endpoint->custom_uri_query_params) {
                strcat(uri_query_params, "&");
                strcat(uri_query_params, endpoint->custom_uri_query_params);
            }
        }
    }
}

static int endpoint_send_pending_message(endpoint_t *endpoint)
{
    int32_t address_len = MAX_VALUE_LENGTH - 1;
    char address_copy[MAX_VALUE_LENGTH];
    char *address_copy_end;
    char uri_query_params[MAX_URI_QUERY_LEN];
    sn_nsdl_addr_s address;

    // Set array to zero since read_query_parameters() can leave array to unintialized state.
    // This can happen if server address does not contain any uri-params.

    if (endpoint->message_type == ENDPOINT_MSG_REGISTER || endpoint->message_type == ENDPOINT_MSG_BOOTSTRAP) {

        address_copy_end = storage_read_uri(address_copy, &address_len, (endpoint->message_type == ENDPOINT_MSG_BOOTSTRAP));

        uri_query_params[0] = '\0';

        if (address_copy_end) {
            *address_copy_end = '\0';
            read_query_parameters(endpoint, address_copy, uri_query_params);
        } else {
            *address_copy = '\0';
        }

        tr_info("Server address: %s", address_copy);

        tr_debug("read_query_parameters params %s", uri_query_params);

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
        if (ENDPOINT_STATUS_OK != endpoint_reset_binding_mode(&endpoint->registry, endpoint->mode)) {
            return ENDPOINT_STATUS_ERROR;
        }
#endif
    }

    if (ENDPOINT_STATUS_OK != get_nsdl_address(endpoint, &address)) {
        return ENDPOINT_STATUS_ERROR;
    }

    if (endpoint->message_type == ENDPOINT_MSG_UPDATE) {
        if (ENDPOINT_STATUS_OK != endpoint_update_or_unregister_endpoint(endpoint, &address, endpoint->message_type)) {
            return ENDPOINT_STATUS_ERROR;
        }
    } else if (endpoint->message_type == ENDPOINT_MSG_REGISTER) {
        if (ENDPOINT_STATUS_OK != endpoint_register_endpoint(endpoint, &address, uri_query_params)) {
            return ENDPOINT_STATUS_ERROR;
        }
    } else if (endpoint->message_type == ENDPOINT_MSG_BOOTSTRAP) {

        if (ENDPOINT_STATUS_OK != endpoint_oma_bootstrap(endpoint, &address, uri_query_params)) {
            return ENDPOINT_STATUS_ERROR;
        }
    } else if (endpoint->message_type == ENDPOINT_MSG_UNREGISTER) {

        if (ENDPOINT_STATUS_OK != endpoint_update_or_unregister_endpoint(endpoint, &address, endpoint->message_type)) {
            return ENDPOINT_STATUS_ERROR;
        }
    } else if (endpoint->message_type == ENDPOINT_MSG_UNDEFINED) {
        return ENDPOINT_STATUS_ERROR;
    }

    return ENDPOINT_STATUS_OK;
}

void endpoint_send_message(endpoint_t *endpoint)
{
    // Retain the registered state if we are performing register update.
    if (endpoint->message_type != ENDPOINT_MSG_UPDATE) {
        endpoint->registered = false;
    }

    tr_info("send_message, type: %d", endpoint->message_type);

    if (ENDPOINT_STATUS_OK == endpoint_send_pending_message(endpoint)) {
        endpoint->last_message_type = endpoint->message_type;
        return;
    }
    // Handling error cases from this point forward.

    send_queue_sent(endpoint, true);

    switch (endpoint->message_type) {

        case ENDPOINT_MSG_UPDATE:
            endpoint->registered = false;
            endpoint_send_event(endpoint, ENDPOINT_EVENT_ERROR_REREGISTER, ENDPOINT_EVENT_STATUS_NO_MEMORY);
            break;

        case ENDPOINT_MSG_REGISTER:
            endpoint_send_event(endpoint, ENDPOINT_EVENT_ERROR_REGISTER, ENDPOINT_EVENT_STATUS_NO_MEMORY);
            break;

        case ENDPOINT_MSG_BOOTSTRAP:
            endpoint_send_event(endpoint, ENDPOINT_EVENT_ERROR_BOOTSTRAP, ENDPOINT_EVENT_STATUS_NO_MEMORY);
            break;

        case ENDPOINT_MSG_UNREGISTER:
            endpoint_send_event(endpoint, ENDPOINT_EVENT_ERROR_DEREGISTER, ENDPOINT_EVENT_STATUS_NO_MEMORY);
            break;

        default:
            break;
    }

    endpoint->message_type = ENDPOINT_MSG_UNDEFINED;

}

int endpoint_register(endpoint_t *endpoint)
{
    return endpoint_command(endpoint, ENDPOINT_MSG_REGISTER);
}

int endpoint_bootstrap(endpoint_t *endpoint)
{
    return endpoint_command(endpoint, ENDPOINT_MSG_BOOTSTRAP);
}

int endpoint_update_registration(endpoint_t *endpoint)
{
    return endpoint_command(endpoint, ENDPOINT_MSG_UPDATE);
}

int endpoint_unregister(endpoint_t *endpoint)
{
    return endpoint_command(endpoint, ENDPOINT_MSG_UNREGISTER);
}

int endpoint_send_event(endpoint_t *endpoint, uint8_t type, uint32_t coap_msg_status)
{
    arm_event_t event;

    event.data_ptr = endpoint->event_data;
    event.event_data = coap_msg_status;
    event.event_id = ENDPOINT_EVENT_ID;
    event.event_type = type;
    event.priority = ARM_LIB_LOW_PRIORITY_EVENT;
    event.receiver = endpoint->event_handler_id;
    event.sender = 0;

    if (0 > eventOS_event_send(&event)) {
        tr_error("eventOS_event_send failed");
        return ENDPOINT_STATUS_ERROR;
    }

    if (event.event_type == ENDPOINT_EVENT_BOOTSTRAP_READY && endpoint->message_type == ENDPOINT_MSG_BOOTSTRAP) {
        /* message_type is used for checking if bootstrap is in progress, so set it as ENDPOINT_MSG_UNDEFINED
         * when bootstrap is ready.  */
        endpoint->message_type = ENDPOINT_MSG_UNDEFINED;
    }

    return ENDPOINT_STATUS_OK;
}

// provide a type safe version for mbed-coap allocator, which is actually using a uint16_t as size param
// TODO: COAP should be actually changed to use the size_t as we no-longer have an allocator that is using uint16_t?
static void *lwm2m_alloc_uint16(uint16_t size)
{
    return lwm2m_alloc(size);
}

static uint8_t coap_tx_callback(uint8_t *data_ptr, uint16_t data_len, sn_nsdl_addr_s *address_ptr, void *param)
{
    endpoint_t *endpoint = (endpoint_t *)param;

    if (endpoint == NULL) {
        return 0;
    }

    // Timer needs to be started again only in queue mode
    if (endpoint->mode & BINDING_MODE_Q) {
        endpoint_start_coap_exec_timer(endpoint);
    }

#if defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP) || defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE)
    calculate_new_coap_ping_send_time(endpoint);
#endif

#if MBED_CONF_MBED_TRACE_ENABLE
    coap_version_e version = COAP_VERSION_UNKNOWN;
    sn_coap_hdr_s *header = sn_coap_parser(endpoint->coap, data_len, data_ptr, &version);
    endpoint_print_coap_data(header, true);
    sn_coap_parser_release_allocated_coap_msg_mem(endpoint->coap, header);
#endif

    if (CONNECTION_STATUS_OK == connection_send_data(endpoint->connection, data_ptr, data_len, false)) {
        return 1;
    }
    return 0;
}

static int8_t endpoint_rx_function(sn_coap_hdr_s *coap_packet_ptr, sn_nsdl_addr_s *address_ptr, void* param)
{
    endpoint_t *endpoint = (endpoint_t *)param;

    if ((endpoint == NULL) || (coap_packet_ptr == 0)) {
        return ENDPOINT_STATUS_ERROR;
    }

    endpoint_print_coap_data(coap_packet_ptr, false);

    endpoint_handle_response(endpoint, coap_packet_ptr);

    return ENDPOINT_STATUS_OK;
}

int endpoint_process_coap(endpoint_t *endpoint, uint8_t *packet_ptr, uint16_t packet_len, sn_nsdl_addr_s *src_ptr)
{
    sn_coap_hdr_s *coap_packet_ptr = NULL;
    sn_coap_hdr_s *coap_response_ptr = NULL;

    /* Check parameters */
    if (endpoint == NULL) {
        return ENDPOINT_STATUS_ERROR;
    }

    /* Parse CoAP packet */
    coap_packet_ptr = sn_coap_protocol_parse(endpoint->coap, src_ptr, packet_len, packet_ptr, (void *)endpoint);

    /* Check if parsing was successful */
    if (coap_packet_ptr == NULL) {
        return ENDPOINT_STATUS_ERROR;
    }

    endpoint_print_coap_data(coap_packet_ptr, false);

#if SN_COAP_DUPLICATION_MAX_MSGS_COUNT
    if (coap_packet_ptr->coap_status == COAP_STATUS_PARSER_DUPLICATED_MSG) {
        tr_info("process_coap, received duplicate message, ignore");
        sn_coap_parser_release_allocated_coap_msg_mem(endpoint->coap, coap_packet_ptr);
        return ENDPOINT_STATUS_OK;
    }
#endif

    /* If proxy options added, return not supported */
    if (coap_packet_ptr->options_list_ptr) {
        if (coap_packet_ptr->options_list_ptr->proxy_uri_len) {

            tr_warn("process_coap, proxy option found, not supported");

            coap_response_ptr = sn_coap_build_response(endpoint->coap, coap_packet_ptr, COAP_MSG_CODE_RESPONSE_PROXYING_NOT_SUPPORTED);

            // scrap the request, not needed anymore
            sn_coap_parser_release_allocated_coap_msg_mem(endpoint->coap, coap_packet_ptr);

            if (coap_response_ptr) {
                endpoint_send_coap_message(endpoint, src_ptr, coap_response_ptr);
                sn_coap_parser_release_allocated_coap_msg_mem(endpoint->coap, coap_response_ptr);
                return ENDPOINT_STATUS_OK;
            } else {
                return ENDPOINT_STATUS_ERROR;
            }
        }
    }

    if ((coap_packet_ptr->msg_code > COAP_MSG_CODE_REQUEST_DELETE) ||
         (coap_packet_ptr->msg_type >= COAP_MSG_TYPE_ACKNOWLEDGEMENT)) {

        //Response message, call RX callback
        endpoint_handle_response(endpoint, coap_packet_ptr);

    } else {

        //Handle requests.
        handle_coap_request(endpoint, coap_packet_ptr, src_ptr);
    }

    //Free data and exit.
#if SN_COAP_REDUCE_BLOCKWISE_HEAP_FOOTPRINT
    if (coap_packet_ptr->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED) {
        sn_coap_protocol_block_remove(endpoint->coap, src_ptr, packet_len, packet_ptr);
    }
#else
    if (coap_packet_ptr->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED && coap_packet_ptr->payload_ptr) {
        endpoint->coap->sn_coap_protocol_free(coap_packet_ptr->payload_ptr);
        coap_packet_ptr->payload_ptr = 0;
    }
#endif // SN_COAP_REDUCE_BLOCKWISE_HEAP_FOOTPRINT

    sn_coap_parser_release_allocated_coap_msg_mem(endpoint->coap, coap_packet_ptr);
    return ENDPOINT_STATUS_OK;
}

int endpoint_send_coap_message(endpoint_t *endpoint, sn_nsdl_addr_s *address_ptr, sn_coap_hdr_s *coap_hdr_ptr)
{

    sn_nsdl_addr_s address;
    uint8_t     *message_ptr;
    uint16_t    message_len;
    int     ret_val;

    /* Check parameters */
    if (endpoint == NULL) {
        return ENDPOINT_STATUS_ERROR;
    }

    if (!address_ptr) {
        if (get_nsdl_address(endpoint, &address) != ENDPOINT_STATUS_OK) {
            tr_error("send_coap_message get_nsdl_address failed");
            return ENDPOINT_STATUS_ERROR;
        }
        address_ptr = &address;
    }

#if SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE /* If Message blockwising is not used at all, this part of code will not be compiled */
    ret_val = prepare_blockwise_message(endpoint->coap, coap_hdr_ptr);
    if (0 != ret_val) {
        tr_error("send_coap_message prepare_blockwise failed err: %d", ret_val);
        return ENDPOINT_STATUS_ERROR_MEMORY_FAILED;
    }
#endif

    /* Calculate message length */
    message_len = sn_coap_builder_calc_needed_packet_data_size_2(coap_hdr_ptr, endpoint->coap->sn_coap_block_data_size);
    tr_debug("send_coap_message - msg len after calc: [%d]", message_len);
    tr_debug("send_coap_message - msg id: [%d]", coap_hdr_ptr->msg_id);


    /* Allocate memory for message and check was allocating successfully */
    message_ptr = lwm2m_alloc(message_len);
    if (message_ptr == NULL) {
        tr_error("send_coap_message lwm2m_alloc(%d) failed", message_len);
        return ENDPOINT_STATUS_ERROR_MEMORY_FAILED;
    }

    /* Build CoAP message */
    endpoint->coap->system_time = endpoint_get_coap_time(endpoint);
    int coap_length = sn_coap_protocol_build(endpoint->coap, address_ptr, message_ptr, coap_hdr_ptr, (void *)endpoint);
    int return_value = ENDPOINT_STATUS_ERROR;
    if (coap_length == -2) {
        return_value = ENDPOINT_STATUS_ERROR_MEMORY_FAILED;
    }
    if ( coap_length < 0) {
        lwm2m_free(message_ptr);
        message_ptr = 0;
        tr_error("send_coap_message protocol_build err: %d", return_value);
        return return_value;
    }

    endpoint_print_coap_data(coap_hdr_ptr, true);

    /* Call tx callback function to send message */
    // Timer needs to be started again only in queue mode
    if (endpoint->mode & BINDING_MODE_Q) {
        endpoint_start_coap_exec_timer((endpoint_t*)endpoint);
    }

#ifdef FULL_PACKAGE_PRINT
    tr_debug("PRINTING FULL PACKAGE");
    for (int i = 0; i<message_len; i++)
    {
        if(i%16 == 0){
           printf( "\n%06x ", i );
        }
        printf( "%02x ", message_ptr[i] );
    }
    printf("\n");
#endif

    ret_val = connection_send_data(endpoint->connection, message_ptr, coap_length, true);
    if (ret_val == CONNECTION_STATUS_WOULD_BLOCK) {
        tr_warn("send_coap_message send_data, would block");
    } else if (ret_val != CONNECTION_STATUS_OK) {
        tr_err("send_coap_message send_data failed, err: %d", ret_val);
    }
    // No need to fail the call at this point as the CoAP library takes care of re-sending if needed now.

#if defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP) || defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE)
    calculate_new_coap_ping_send_time(endpoint);
#endif

    tr_info("send_coap_message send_data OK");
    return ENDPOINT_STATUS_OK;
}

static int endpoint_register_endpoint(endpoint_t *endpoint, sn_nsdl_addr_s *address, const char *uri_query_parameters)
{
    /* Local variables */
    sn_coap_hdr_s *register_message_ptr;
    int status;

    if (endpoint == NULL) {
        return ENDPOINT_STATUS_ERROR;
    }

    /*** Build endpoint register message ***/

    /* Allocate memory for header struct */
    register_message_ptr = sn_coap_parser_alloc_message(endpoint->coap);
    if (register_message_ptr == NULL) {
        return ENDPOINT_STATUS_ERROR;
    }

    /* Fill message fields -> confirmable post to specified NSP path */
    register_message_ptr->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    register_message_ptr->msg_code = COAP_MSG_CODE_REQUEST_POST;

    /* Allocate memory for the extended options list */
    if (sn_coap_parser_alloc_options(endpoint->coap, register_message_ptr) == NULL) {
        sn_coap_parser_release_allocated_coap_msg_mem(endpoint->coap, register_message_ptr);
        register_message_ptr = 0;
        return ENDPOINT_STATUS_ERROR;
    }

    register_message_ptr->uri_path_len = sizeof(resource_path);
    register_message_ptr->uri_path_ptr = (uint8_t*)resource_path;

    /* Fill Uri-query options */
    if (ENDPOINT_STATUS_ERROR == endpoint_fill_uri_query_options(endpoint,
                                                                register_message_ptr,
                                                                0,
                                                                uri_query_parameters)) {

        register_message_ptr->uri_path_ptr = NULL;
        sn_coap_parser_release_allocated_coap_msg_mem(endpoint->coap, register_message_ptr);
        return ENDPOINT_STATUS_ERROR;
    }

    /* Build body for message */
    if (endpoint_build_registration_body(endpoint, register_message_ptr, 0, NULL) == ENDPOINT_STATUS_ERROR) {
        status = ENDPOINT_STATUS_ERROR;
    } else {
#ifdef MBED_CLIENT_PRINT_COAP_PAYLOAD
        tr_info("REGISTER MESSAGE %.*s", register_message_ptr->payload_len, register_message_ptr->payload_ptr);
#endif // MBED_CLIENT_PRINT_COAP_PAYLOAD


        /* Build and send coap message to NSP */
        status = endpoint_internal_coap_send(endpoint, register_message_ptr, address, ENDPOINT_MSG_REGISTER);
    }

    lwm2m_free(register_message_ptr->payload_ptr);
    register_message_ptr->payload_ptr = NULL;

    register_message_ptr->uri_path_ptr = NULL;
    register_message_ptr->options_list_ptr->uri_host_ptr = NULL;

    sn_coap_parser_release_allocated_coap_msg_mem(endpoint->coap, register_message_ptr);

    return status;
}

static int endpoint_update_or_unregister_endpoint(endpoint_t *endpoint, sn_nsdl_addr_s *address, uint8_t message_type)
{
    /* Local variables */
    sn_coap_hdr_s *message_ptr;
    int status;

    /* Allocate memory for header struct */
    message_ptr = sn_coap_parser_alloc_message(endpoint->coap);
    if (message_ptr == NULL) {
        return ENDPOINT_STATUS_ERROR;
    }

    /* Fill message fields -> confirmable post to specified NSP path */
    message_ptr->msg_type = COAP_MSG_TYPE_CONFIRMABLE;

    if (message_type == ENDPOINT_MSG_UPDATE) {
        /*** Build endpoint register update message ***/
        message_ptr->msg_code = COAP_MSG_CODE_REQUEST_POST;

        /* Allocate memory for the extended options list */
        if (sn_coap_parser_alloc_options(endpoint->coap, message_ptr) == NULL) {
            sn_coap_parser_release_allocated_coap_msg_mem(endpoint->coap, message_ptr);
            return 0;
        }

        /* Fill Uri-query options */
        endpoint_fill_uri_query_options(endpoint, message_ptr, true, NULL);

#ifdef MBED_CLIENT_ENABLE_DYNAMIC_CREATION
        /* Build payload */
        if (endpoint_build_registration_body(endpoint, message_ptr, 1, NULL) == ENDPOINT_STATUS_ERROR) {
            sn_coap_parser_release_allocated_coap_msg_mem(endpoint->coap, message_ptr);
            return ENDPOINT_STATUS_ERROR;
        }
#endif

    } else {
        /*** Build endpoint unregister message ***/
        message_ptr->msg_code = COAP_MSG_CODE_REQUEST_DELETE;
    }

    if (endpoint->location) {

        message_ptr->uri_path_len = strlen(endpoint->location);
        message_ptr->uri_path_ptr = (uint8_t*)endpoint->location;
        /*NOTE: uri_path_ptr MUST be set as NULL before sn_coap_parser_release_allocated_coap_msg_mem,
         *      as we do not want to free endpoint->location. */

        /* Send message */
        status = endpoint_internal_coap_send(endpoint, message_ptr, address, message_type);

        message_ptr->uri_path_ptr = NULL;

    } else {
        // According to OMA LWM2M spec 8.2.3, the server MUST return the location on register,
        // so this branch is not necessarily even needed.
        tr_error("update_endpoint_registration: location not specified");
        status = ENDPOINT_STATUS_ERROR;
    }

    /* Free memory */
#ifdef MBED_CLIENT_ENABLE_DYNAMIC_CREATION
    lwm2m_free(message_ptr->payload_ptr);
#endif
    sn_coap_parser_release_allocated_coap_msg_mem(endpoint->coap, message_ptr);

    return status;
}

static int endpoint_oma_bootstrap(endpoint_t *endpoint, sn_nsdl_addr_s *bootstrap_address_ptr, const char *uri_query_parameters)
{
#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    /* Local variables */
    sn_coap_hdr_s bootstrap_coap_header;
    uint8_t *uri_query_tmp_ptr;
    int status;
    int32_t bytes_needed = 0;

    /* Check parameters */
    if (!bootstrap_address_ptr || !endpoint) {
        return ENDPOINT_STATUS_ERROR;
    }

    // double-check, that the parameters are correct (there should not be any way to bypass the checks)
    assert(validate_parameters(endpoint));

    /* XXX FIX -- Init CoAP header struct */
    sn_coap_parser_init_message(&bootstrap_coap_header);

    if (!sn_coap_parser_alloc_options(endpoint->coap, &bootstrap_coap_header)) {
        return ENDPOINT_STATUS_ERROR;
    }

    /* Build bootstrap start message */
    bootstrap_coap_header.msg_code = COAP_MSG_CODE_REQUEST_POST;
    bootstrap_coap_header.msg_type = COAP_MSG_TYPE_CONFIRMABLE;

    bootstrap_coap_header.uri_path_ptr = (uint8_t*)bs_uri;
    bootstrap_coap_header.uri_path_len = sizeof(bs_uri);

    // First we use the query filling code with NULL buffer, which makes it to just calculate
    // the amount of buffer needed.
    write_bs_uri_query_options(NULL, endpoint,
                                uri_query_parameters,
                                 &bytes_needed);

    uri_query_tmp_ptr = lwm2m_alloc(bytes_needed);
    if (!uri_query_tmp_ptr) {
        lwm2m_free(bootstrap_coap_header.options_list_ptr);
        return ENDPOINT_STATUS_ERROR;
    }

    bootstrap_coap_header.options_list_ptr->uri_query_len = bytes_needed;
    bootstrap_coap_header.options_list_ptr->uri_query_ptr = uri_query_tmp_ptr;

    // then write the query into the buffer
    int32_t buffer_left = bytes_needed;

    uri_query_tmp_ptr = write_bs_uri_query_options(uri_query_tmp_ptr, endpoint,
                                                    uri_query_parameters,
                                                     &buffer_left);

    assert(uri_query_tmp_ptr);
    assert(buffer_left == 0);

    /* Send message */
    status = endpoint_internal_coap_send(endpoint, &bootstrap_coap_header, bootstrap_address_ptr, ENDPOINT_MSG_BOOTSTRAP);

    /* Free allocated memory */
    lwm2m_free(bootstrap_coap_header.options_list_ptr->uri_query_ptr);
    lwm2m_free(bootstrap_coap_header.options_list_ptr);

    return status;
#else
    return ENDPOINT_STATUS_ERROR;
#endif //MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE

}

#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
// this has slightly different naming as other write_X functions, but it keeps diff smaller
static uint8_t *write_bs_uri_query_options(uint8_t *temp_ptr, const endpoint_t *endpoint,
                                     const char *uri_query,
                                     int32_t *buffer_left)
{
    // start filling the query with uri and the parameters
    temp_ptr = write_string(temp_ptr, bs_ep_name, buffer_left);

    temp_ptr = (uint8_t*) storage_read_endpoint_name((char*)temp_ptr, buffer_left, true);

    // Add optional parameters, parsed from the server URL.
    if (uri_query) {
        temp_ptr = write_query_parameters(temp_ptr, uri_query, buffer_left);
    }
    return temp_ptr;
}
#endif

static int endpoint_internal_coap_send(endpoint_t *endpoint, sn_coap_hdr_s *coap_header_ptr, sn_nsdl_addr_s *dst_addr_ptr, uint8_t message_description)
{

    int status;

    tr_debug("internal_coap_send");

    endpoint->message_type = message_description;
    endpoint->message_token = generate_token();

    coap_header_ptr->token_ptr = (uint8_t*)&endpoint->message_token;
    coap_header_ptr->token_len = sizeof(endpoint->message_token);

    status = endpoint_send_coap_message(endpoint, dst_addr_ptr, coap_header_ptr);

    coap_header_ptr->token_ptr = NULL;
    coap_header_ptr->token_len = 0;

    return status;

}

static bool endpoint_handle_endpoint_response(endpoint_t *endpoint, sn_coap_hdr_s *coap_header)
{
    uint32_t error_status = ENDPOINT_EVENT_STATUS_CONNECTION_ERROR;

    if (coap_header->token_len != sizeof(endpoint->message_token) ||
        memcmp(coap_header->token_ptr, &endpoint->message_token, sizeof(endpoint->message_token))) {
        return false;
    }

    if (coap_header->msg_code == COAP_MSG_CODE_RESPONSE_CONTINUE) {
        return true;
    }

    if (coap_header->coap_status == COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED ||
        coap_header->coap_status == COAP_STATUS_BUILDER_BLOCK_SENDING_FAILED) {
        error_status = ENDPOINT_EVENT_STATUS_TIMEOUT;
    }

    if (coap_header->msg_type == COAP_MSG_TYPE_RESET ||
        coap_header->coap_status != COAP_STATUS_OK ||
        COAP_MSG_CODE_RESPONSE_CHANGED < coap_header->msg_code) {
        switch (endpoint->message_type) {
            case ENDPOINT_MSG_UPDATE:
                endpoint_send_event(endpoint, ENDPOINT_EVENT_ERROR_REREGISTER, error_status);
                break;

            case ENDPOINT_MSG_REGISTER:
#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
                if (COAP_MSG_CODE_RESPONSE_BAD_REQUEST == coap_header->msg_code) {
                    error_status = ENDPOINT_EVENT_STATUS_RESPONSE_BAD_REQUEST;
                } else if (COAP_MSG_CODE_RESPONSE_FORBIDDEN == coap_header->msg_code) {
                    error_status = ENDPOINT_EVENT_STATUS_RESPONSE_FORBIDDEN;
                }
#endif // MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
                endpoint_send_event(endpoint, ENDPOINT_EVENT_ERROR_REGISTER, error_status);
                break;

#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
            case ENDPOINT_MSG_BOOTSTRAP:
                endpoint_send_event(endpoint, ENDPOINT_EVENT_ERROR_BOOTSTRAP, error_status);
                break;
#endif

            case ENDPOINT_MSG_UNREGISTER:
                endpoint_send_event(endpoint, ENDPOINT_EVENT_ERROR_DEREGISTER, error_status);
                break;

            case ENDPOINT_MSG_UNDEFINED:
                tr_warn("handle_response() unhandled CoAP error");
                return true;
        }
    } else {

        switch (endpoint->message_type) {

            case ENDPOINT_MSG_UPDATE:
                endpoint_send_event(endpoint, ENDPOINT_EVENT_REREGISTERED, ENDPOINT_EVENT_STATUS_OK);
                endpoint->registered = true;
                break;

            case ENDPOINT_MSG_REGISTER:
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
                notifier_clear_notifications(&endpoint->notifier);
#endif
                endpoint_handle_registration_response(endpoint, coap_header);
                endpoint->registered = true;
                endpoint_send_event(endpoint, ENDPOINT_EVENT_REGISTERED, ENDPOINT_EVENT_STATUS_OK);
                break;

#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
            case ENDPOINT_MSG_BOOTSTRAP:
                endpoint_send_event(endpoint, ENDPOINT_EVENT_BOOTSTRAP_SENT, ENDPOINT_EVENT_STATUS_OK);
                break;
#endif
            case ENDPOINT_MSG_UNREGISTER:
                endpoint_send_event(endpoint, ENDPOINT_EVENT_DEREGISTERED, ENDPOINT_EVENT_STATUS_OK);
                break;

            case ENDPOINT_MSG_UNDEFINED:
                tr_warn("handle_response() unhandled CoAP response");
                return true;

        }
    }

    endpoint->message_type = ENDPOINT_MSG_UNDEFINED;

    send_queue_sent(endpoint, true);

    return true;
}

static void endpoint_handle_response(endpoint_t *endpoint, sn_coap_hdr_s *coap_header)
{

    if (coap_header->msg_id == 0) {
        // This is a response to a CoAP ping, no need to do any handling for it.
        return;
    }

#if defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP) || defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE)
    if (coap_header->msg_id == endpoint->coap_ping_id) {

        endpoint->coap_ping_id = 0;
        send_queue_sent(endpoint, true);

        if (coap_header->coap_status == COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED ||
         coap_header->coap_status == COAP_STATUS_BUILDER_BLOCK_SENDING_FAILED) {

            // Give an error to the endpoint and wait for it to reconnect.
            endpoint_send_event(endpoint, ENDPOINT_EVENT_ERROR_REREGISTER, coap_header->coap_status);
            endpoint->registered = false;
        }
        return;
    }
#endif

    if (req_handler_handle_response(endpoint, coap_header) || handle_coap_response(endpoint, coap_header) ) {
        // Response was handled.
        if (coap_header->coap_status == COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED ||
            coap_header->coap_status == COAP_STATUS_BUILDER_BLOCK_SENDING_FAILED) {
            tr_warn("handle_response CoAP message sending failed status: %d", coap_header->coap_status);
            endpoint->registered = false;
        }
    }

    endpoint_handle_endpoint_response(endpoint, coap_header);

}

static int endpoint_handle_registration_response(endpoint_t *endpoint, const sn_coap_hdr_s *coap_header)
{

    if (coap_header->options_list_ptr && coap_header->options_list_ptr->location_path_ptr) {

        lwm2m_free(endpoint->location);

        //Copy location and make it null terminated string
        endpoint->location = lwm2m_alloc_string_copy(coap_header->options_list_ptr->location_path_ptr,
                                                        coap_header->options_list_ptr->location_path_len);

        if (!endpoint->location) {
            return ENDPOINT_STATUS_ERROR;
        }

        uint32_t max_time = coap_header->options_list_ptr->max_age;

        // If a sufficiently-large Max-Age option is present, we interpret it as registration lifetime;
        // mbed server (mDS) reports lifetime this way as a non-standard extension. Other servers
        // would likely not include an explicit Max-Age option, in which case we'd see the default 60 seconds.
        if (max_time >= MINIMUM_REGISTRATION_TIME) {

            tr_debug("handle_registration_response() setting lifetime from registration response: %"PRId32, max_time);

            return endpoint_set_lifetime(endpoint, max_time);
        }

    }

    return ENDPOINT_STATUS_OK;
}

#ifndef SN_COAP_DISABLE_RESENDINGS
int endpoint_set_retransmission_parameters(endpoint_t *endpoint) {

    // in UDP mode, reconnection attempts must be scaled down so that last attempt does not slip
    // past the client lifetime. the last attempt needs to end before 75% of client lifetime has passed.
    uint32_t lifetime = 0;
    if (ENDPOINT_STATUS_OK != endpoint_get_lifetime(endpoint, &lifetime)) {
        tr_error("set_retransmission_parameters() could not read endpoint lifetime");
        return ENDPOINT_STATUS_ERROR;
    }

    // Resend time window is 75% of the total lifetime value.
    uint32_t resend_window = (lifetime >> 2);
    uint32_t reconnection_count = MBED_CLIENT_RECONNECTION_COUNT;

    // Total reconnection time is combination of initial reconnection time + (polynomial of (reconnection time*1) + (reconnection_time*2) +...+(reconnection_time*reconnection_count) )
    uint32_t reconnection_total_time = MBED_CLIENT_RECONNECTION_INTERVAL + (MBED_CLIENT_RECONNECTION_INTERVAL * (reconnection_count * (reconnection_count + 1)));

    // We need to take into account that CoAP specification mentions that each retransmission
    // has to have a random multiplying factor between 1 - 1.5 , max of which can be 1.5
    reconnection_total_time += MAXIMUM_RECONNECTION_TIME_INTERVAL;

    while (reconnection_count > 1 && reconnection_total_time > resend_window) {
        reconnection_count--;
        reconnection_total_time = MBED_CLIENT_RECONNECTION_INTERVAL + (MBED_CLIENT_RECONNECTION_INTERVAL * (reconnection_count * (reconnection_count + 1)));
        reconnection_total_time += MAXIMUM_RECONNECTION_TIME_INTERVAL;
    }
    tr_debug("set_retransmission_parameters() setting max resend count to %"PRIu32 " with total time: %"PRIu32, reconnection_count, reconnection_total_time);

    if (sn_coap_protocol_set_retransmission_parameters(endpoint->coap, reconnection_count, MBED_CLIENT_RECONNECTION_INTERVAL) < 0) {
        return ENDPOINT_STATUS_ERROR;
    }
    return ENDPOINT_STATUS_OK;
}
#endif //SN_COAP_DISABLE_RESENDINGS


int endpoint_set_lifetime(endpoint_t *endpoint, uint32_t lifetime)
{
    tr_debug("set_lifetime() lifetime: %"PRIu32, lifetime);

    // doing some gatekeeping here
    if (lifetime > 0 && lifetime < MINIMUM_REGISTRATION_TIME) {
        lifetime = MINIMUM_REGISTRATION_TIME;
        tr_debug("set_lifetime() setting default value (minimum): %"PRIu32, lifetime);
    }

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    registry_path_t path;
    registry_set_path(&path, M2M_SERVER_ID, 0, SERVER_LIFETIME, 0, REGISTRY_PATH_RESOURCE);
    if (registry_set_value_int(&endpoint->registry, &path, lifetime) != REGISTRY_STATUS_OK) {
        return ENDPOINT_STATUS_ERROR;
    }
#else
    endpoint->lifetime = lifetime;
#endif

#ifndef SN_COAP_DISABLE_RESENDINGS
    // If the mode is UDP or Queue mode then reconfigure the retransmission count to avoid full registration cycle.
    if ((endpoint->mode & BINDING_MODE_U) || (endpoint->mode & BINDING_MODE_Q)) {
        if (endpoint_set_retransmission_parameters(endpoint) != ENDPOINT_STATUS_OK) {
            return ENDPOINT_STATUS_ERROR;
        }
    }
#endif //SN_COAP_DISABLE_RESENDINGS

    return ENDPOINT_STATUS_OK;
}

int endpoint_get_lifetime(const endpoint_t *endpoint, uint32_t *lifetime) {

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    registry_path_t path;
    int64_t tmp_lifetime = 0;
#endif

    if (!lifetime || !endpoint) {
        tr_error("get_lifetime() invalid params");
        assert(0);
        return ENDPOINT_STATUS_ERROR;
    }

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    registry_set_path(&path, M2M_SERVER_ID, 0, SERVER_LIFETIME, 0, REGISTRY_PATH_RESOURCE);
    if (registry_get_value_int(&endpoint->registry, &path, &tmp_lifetime) != REGISTRY_STATUS_OK) {
        tr_error("get_lifetime() reading from registry failed");
        return ENDPOINT_STATUS_ERROR;
    }
    *lifetime = (uint32_t) tmp_lifetime;
#else
    *lifetime = endpoint->lifetime;
#endif

    return ENDPOINT_STATUS_OK;
}

static uint8_t* write_char(uint8_t *data, const char character, int32_t *len)
{
    if (!data) {
        if(*len >= 0){
            (*len)++;
        }
        return NULL;
    }
    if (*len > 0) {
        *data++ = character;
        (*len)--;
    } else {
        *len = (-1);
    }
    return data;
}

static uint8_t* write_int(uint8_t *data, uint32_t value, int32_t *len)
{
    // XXX: remove this pointless double-conversion, as they can be at one pass
    uint8_t itoa_len = endpoint_itoa_len(value);
    if (!data) {
        if(*len >= 0){
            (*len) += itoa_len;
        }
        return NULL;
    }
    if (*len >= itoa_len) {
         data = endpoint_itoa(data, value);
        (*len) -= itoa_len;
    } else {
        *len = (-1);
    }
    return data;
}

static uint8_t* write_data(uint8_t *to, const char *from, uint16_t len, int32_t *packet_len)
{
    if (!to) {
        if(*packet_len >= 0){
            (*packet_len) += len;
        }
        return NULL;
    }
    if (*packet_len >= len) {
        memcpy(to, from, len);
        to += len;
        (*packet_len) -= len;
    } else {
        *packet_len = (-1);
    }
    return to;
}

#ifdef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
static uint8_t* write_resource(uint8_t *data, register_resource_t *iter, int32_t *len)
{
    data = write_char(data, '<', len);
    data = write_string(data, iter->full_res_id, len);
    data = write_char(data, '>', len);
#if MBED_CLIENT_ENABLE_AUTO_OBSERVATION
    if (iter->aobs_id > 0) {
        size_t token_len = endpoint_itoa_len(iter->aobs_id);
        // Token is between 1 - 1023
        uint8_t temp_ptr[5] = {0};
        endpoint_itoa((uint8_t*)&temp_ptr, iter->aobs_id);
        data = write_parameter(data, auto_obs_parameter, sizeof(auto_obs_parameter),
                               (char*)temp_ptr, token_len, 0, len);
    }
#endif
#if MBED_CLIENT_ENABLE_PUBLISH_RESOURCE_VALUE_IN_REG_MSG
    if (iter->value && iter->value_len) {
        data = write_parameter(data, resource_value, sizeof(resource_value),
                               (char*)iter->value, iter->value_len, 0, len);
    }
#endif
    return data;
}
#endif

static uint8_t *write_string(uint8_t *to, const char *from, int32_t *packet_len)
{
    return write_data(to, from, strlen(from), packet_len);
}

static uint8_t *write_string_pair(uint8_t *to, const char *from1, const char *from2, int32_t *packet_len)
{
    to = write_string(to, from1, packet_len);
    to = write_string(to, from2, packet_len);
    return to;
}

static uint8_t *write_parameter(uint8_t *packet, const char *parameter, uint8_t parameter_len, const char *value, uint16_t value_len, uint8_t no_value, int32_t *packet_len)
{
    packet = write_char(packet, ';', packet_len);
    packet = write_data(packet, parameter, parameter_len, packet_len);
    if (no_value) {
        return packet;
    }

    packet = write_char(packet, '"', packet_len);
    if (value) {
        packet = write_data(packet, value, value_len, packet_len);
    } else {
        packet = write_int(packet, value_len, packet_len);
    }
    packet = write_char(packet, '"', packet_len);

    return packet;
}

#if MBED_CONF_MBED_CLIENT_REGISTER_RESOURCE_NAME
static uint8_t *write_resource_name(uint8_t *packet, const registry_path_t *path, int32_t *packet_len)
{
    const char *name;
    size_t name_len;

    name = NULL;

    if (path->path_type == REGISTRY_PATH_OBJECT) {
        const lwm2m_object_meta_definition_t* object_def;
        if (REGISTRY_STATUS_OK != registry_meta_get_object_definition(path->object_id, &object_def)) {
            return packet;
        }
        name = object_def->name;
    } else if (path->path_type == REGISTRY_PATH_RESOURCE){
        const lwm2m_resource_meta_definition_t* resource_def;
        if (REGISTRY_STATUS_OK != registry_meta_get_resource_definition(path->object_id, path->resource_id, &resource_def)) {
            return packet;
        }
        name = resource_def->name;
    }

    if (!name) {
        return packet;
    }

    name_len = strlen(name);

    if (name_len > 0xFFFF) {
        return packet;
    }

    packet = write_parameter(packet, resource_type_parameter, sizeof(resource_type_parameter), name, name_len, 0, packet_len);

    return packet;
}
#endif

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
static uint8_t *write_path(uint8_t *packet, const registry_path_t *path, int32_t *packet_len)
{
    packet = write_char(packet, '<', packet_len);
    packet = write_char(packet, '/', packet_len);

    packet = write_int(packet, path->object_id, packet_len);

    if (path->path_type > REGISTRY_PATH_OBJECT) {
        packet = write_char(packet, '/', packet_len);
        packet = write_int(packet, path->object_instance_id, packet_len);
    }

    if (path->path_type > REGISTRY_PATH_OBJECT_INSTANCE) {
        packet = write_char(packet, '/', packet_len);
        packet = write_int(packet, path->resource_id, packet_len);
    }

    if (path->path_type > REGISTRY_PATH_RESOURCE) {
        packet = write_char(packet, '/', packet_len);
        packet = write_int(packet, path->resource_instance_id, packet_len);
    }

    packet = write_char(packet, '>', packet_len);
    return packet;
}
#endif


static uint8_t *write_query_parameters(uint8_t *dest, const char *uri_query_parameters, int32_t *packet_len)
{
    dest = write_string(dest, uri_query_parameters, packet_len);
    return dest;
}

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
static bool is_observable(const registry_path_t *path)
{

    const lwm2m_resource_meta_definition_t* resource_def;

    if (path->path_type < REGISTRY_PATH_RESOURCE) {
        return true;
    }

    if (REGISTRY_STATUS_OK != registry_meta_get_resource_definition(path->object_id, path->resource_id, &resource_def)) {
        assert(0);
        return false;
    }

    return registry_meta_is_resource_observable(resource_def);
}
#endif

static int endpoint_build_registration_body(endpoint_t *endpoint, sn_coap_hdr_s *message_ptr, uint8_t updating_registeration, int32_t *len)
{
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    tr_debug("build_registration_body");
    /* Local variables */
    uint8_t *data;
    int32_t data_len;
    registry_listing_t listing;
    uint8_t first_resource = 1;

    /* Calculate needed memory and allocate */

    if (message_ptr) {

        data_len = 0;
        len = &data_len;

        endpoint_build_registration_body(endpoint, NULL, updating_registeration, len);

        message_ptr->payload_len = *len;

        if (!message_ptr->payload_len) {
            return ENDPOINT_STATUS_OK;
        }

        if (*len < 0 || *len > UINT16_MAX) {
            return ENDPOINT_STATUS_ERROR;
        }

        tr_debug("build_registration_body - body size: [%d]", message_ptr->payload_len);
        message_ptr->payload_ptr = lwm2m_alloc(message_ptr->payload_len);
        if (!message_ptr->payload_ptr) {
            return ENDPOINT_STATUS_ERROR;
        }

        /* Build message */
        data = message_ptr->payload_ptr;
        listing.set_registered = 1;

    } else {

        data = NULL;
        listing.set_registered = 0;
    }

    listing.listing_type = REGISTRY_LISTING_ALL;

    /* Loop through all resources */
    while (REGISTRY_STATUS_OK == registry_get_objects(&endpoint->registry, &listing, NULL, NULL)) {
        if ((updating_registeration && listing.registered) ||
            (MBED_CLIENT_LWM2M_STRICT_MODE && listing.path.path_type > REGISTRY_PATH_OBJECT_INSTANCE) ||
            (listing.path.object_id == 0)) {
            /* Skip this resource */
            continue;
        }

#if MBED_CLIENT_ENABLE_AUTO_OBSERVATION
        else if (!MBED_CLIENT_LWM2M_STRICT_MODE && listing.path.path_type < REGISTRY_PATH_RESOURCE &&
                   !registry_is_auto_observable(&endpoint->registry, &listing.path))
#else
        else if (!MBED_CLIENT_LWM2M_STRICT_MODE && listing.path.path_type < REGISTRY_PATH_RESOURCE)
#endif // MBED_CLIENT_ENABLE_AUTO_OBSERVATION
        {
            /* Skip publishing Object and Object Instances*/
            /* ignore object only if it really has resource under it. */
            if(listing.path.path_type == REGISTRY_PATH_OBJECT)  //
            {
                uint32_t count = registry_object_count_resources(&endpoint->registry, &listing.path);
                if(count > 0)
                {
                    continue;
                }
            }else
            {
                continue;
            }
        }

        if (!first_resource) {
            data = write_char(data, ',', len);
        } else {
            first_resource = 0;
        }

        data = write_path(data, &listing.path, len);

#if MBED_CONF_MBED_CLIENT_REGISTER_RESOURCE_NAME
        data = write_resource_name(data, &listing.path, len);
#endif

#if MBED_CLIENT_ENABLE_PUBLISH_RESOURCE_VALUE_IN_REG_MSG
        // Add "v" tag only for resources
        if (registry_publish_resource_value_in_reg_msg(&endpoint->registry, &listing.path)) {
            data = write_resource_value(data, &listing.path, len, endpoint);
        }
#endif

        if (!MBED_CLIENT_LWM2M_STRICT_MODE && is_observable(&listing.path)) {
            //TODO: Check if some of the resources cannot be observed.
#if MBED_CLIENT_ENABLE_AUTO_OBSERVATION
            if (registry_is_auto_observable(&endpoint->registry, &listing.path)) {

                registry_observation_parameters_t obs_params;
                registry_status_t status = registry_get_observation_parameters(&endpoint->registry,
                                                                               &listing.path,
                                                                               &obs_params);

                if (REGISTRY_STATUS_OK == status) {
                    uint16_t temp = common_read_16_bit((uint8_t*)obs_params.token);
                    size_t token_len = endpoint_itoa_len(temp);
                    // Token is between 1 - 1023
                    uint8_t temp_ptr[5] = {0};
                    endpoint_itoa((uint8_t*)&temp_ptr, temp);

                    data = write_parameter(data,
                                           auto_obs_parameter,
                                           sizeof(auto_obs_parameter),
                                           (char*)temp_ptr,
                                           token_len,
                                           0,
                                           len);
                }
            } else
#endif // MBED_CLIENT_ENABLE_AUTO_OBSERVATION
            {
                data = write_parameter(data, obs_parameter, sizeof(obs_parameter), NULL, 0, 1, len);
            }
        }

        if (*len < 0) {
            return ENDPOINT_STATUS_ERROR;
        }

    }
#else
    if (!message_ptr) {
        return ENDPOINT_STATUS_ERROR;
    }
    if (updating_registeration) {
        message_ptr->payload_len = 0;
        return ENDPOINT_STATUS_OK;
    }

    int ret = 0;
    register_resource_t *all = NULL;
    object_handler_t *temp = endpoint->object_handlers;
    while (temp) {
        if (temp->res_cb) {
            register_resource_t *resources;
            ret = temp->res_cb(endpoint, &resources);
            if (!all) {
                all = resources;
            } else {
                register_resource_t *t = all;
                while (t->next) {
                    t = t->next;
                }
                t->next = resources;
            }
            if (ret) {
                tr_error("build_registration_body - out of memory");
                break;
            }
        }
        temp = temp->next;
    }

    register_resource_t *iter;
    register_resource_t *rest;
    if (ret) {
        // allocating resources failed - release what was allocated and exit with error
        iter = all;
        while (iter) {
            rest = iter->next;
            lwm2m_free(iter->value);
            lwm2m_free(iter);
            iter = rest;
        }
        return ENDPOINT_STATUS_ERROR;
    }

    // calculate registration message length
    int32_t leng = 0;
    iter = all;

    write_resource(NULL, iter, &leng);
    iter = iter->next;
    while (iter) {
        write_char(NULL, ',', &leng);
        write_resource(NULL, iter, &leng);
        iter = iter->next;
    }

    message_ptr->payload_len = leng;
    if (!message_ptr->payload_len) {
        return ENDPOINT_STATUS_OK;
    }

    if (leng < 0 || leng > UINT16_MAX) {
        return ENDPOINT_STATUS_ERROR;
    }
    tr_debug("build_registration_body - body size: [%d]", message_ptr->payload_len);
    message_ptr->payload_ptr = lwm2m_alloc(message_ptr->payload_len);
    if (!message_ptr->payload_ptr) {
        return ENDPOINT_STATUS_ERROR;
    }

    /* Build message */
    uint8_t *data = message_ptr->payload_ptr;

    iter = all;
    data = write_resource(data, iter, &leng);
    rest = iter->next;
    lwm2m_free(iter->value);
    lwm2m_free(iter);
    iter = rest;
    while (iter) {
        data = write_char(data, ',', &leng);
        data = write_resource(data, iter, &leng);
        rest = iter->next;
        lwm2m_free(iter->value);
        lwm2m_free(iter);
        iter = rest;
    }

    if (leng < 0) {
        return ENDPOINT_STATUS_ERROR;
    }
#endif

    return ENDPOINT_STATUS_OK;
}

static int endpoint_fill_uri_query_options(endpoint_t *endpoint,
                                             sn_coap_hdr_s *source_msg_ptr,
                                             bool update,
                                             const char *uri_query)
{
    uint8_t *temp_ptr;
    int32_t bytes_needed = 0;

    if( !validate_parameters(endpoint) ){
        return ENDPOINT_STATUS_ERROR;
    }

    // First we use the query filling code with NULL buffer, which makes it to just calculate
    // the amount of buffer needed.
    write_uri_query_options(NULL, endpoint, update,
                             uri_query,
                             &bytes_needed);

    if (bytes_needed < 0) {
        return ENDPOINT_STATUS_ERROR;
    }

    temp_ptr = lwm2m_alloc(bytes_needed);

    // intialize the query variable even when allocation fails, as callee will free it unconditionally
    source_msg_ptr->options_list_ptr->uri_query_len = bytes_needed;
    source_msg_ptr->options_list_ptr->uri_query_ptr = temp_ptr;

    if (temp_ptr == NULL) {
        return ENDPOINT_STATUS_ERROR;
    }

    // then write the query into the buffer
    int32_t buffer_left = bytes_needed;

    temp_ptr = write_uri_query_options(temp_ptr, endpoint, update,
                                         uri_query,
                                         &buffer_left);

    assert(temp_ptr);
    assert(buffer_left == 0);

    return ENDPOINT_STATUS_OK;
}

// this has slightly different naming as other write_X functions, but it keeps diff smaller
static uint8_t *write_uri_query_options(uint8_t *temp_ptr, const endpoint_t *endpoint,
                                     bool update,
                                     const char *uri_query,
                                     int32_t *buffer_left)
{

    bool first_param = true;

    /***************************************************************/
    /* If (internal)endpoint name is configured, fill needed field */
    /***************************************************************/
    if (!update) {

        /* fill endpoint name, first ?ep=, then endpoint name */
        temp_ptr = write_string(temp_ptr, ep_name_parameter, buffer_left);
        first_param = false;

#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
        temp_ptr = (uint8_t*)storage_read_internal_endpoint_name((char*)temp_ptr, buffer_left, false);
#else
        temp_ptr = (uint8_t*)storage_read_endpoint_name((char*)temp_ptr, buffer_left, false);
#endif
    }

    /******************************************************/
    /* If endpoint type is configured, fill needed fields */
    /******************************************************/

    if ((endpoint->type != NULL) && !update) {
        if (!first_param) {
            temp_ptr = write_char(temp_ptr, '&', buffer_left);
        }
        first_param = false;

        temp_ptr = write_string_pair(temp_ptr, et_parameter, endpoint->type, buffer_left);
    }

    /******************************************************/
    /* If lifetime is configured, fill needed fields */
    /******************************************************/
    uint32_t lifetime = 0;
    if (ENDPOINT_STATUS_OK == endpoint_get_lifetime(endpoint, &lifetime) &&
        (lifetime > 0)) {
        if (!first_param) {
            temp_ptr = write_char(temp_ptr, '&', buffer_left);
        }
        first_param = false;

        temp_ptr = write_string(temp_ptr, ep_lifetime_parameter, buffer_left);
        temp_ptr = write_int(temp_ptr, lifetime, buffer_left);
    }

    /******************************************************/
    /* If queue-mode is configured, fill needed fields    */
    /******************************************************/

    if (((endpoint->mode & BINDING_MODE_U) || (endpoint->mode & BINDING_MODE_Q)
#if defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP) || defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE)
         || (endpoint->mode & BINDING_MODE_T)
#endif
        ) && !update) {
        if (!first_param) {
            temp_ptr = write_char(temp_ptr, '&', buffer_left);
        }
        first_param = false;

        temp_ptr = write_string(temp_ptr, bs_queue_mode, buffer_left);

        if (endpoint->mode & BINDING_MODE_U
#if defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP) || defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE)
            || endpoint->mode & BINDING_MODE_T
#endif
           ) {
            temp_ptr = write_char(temp_ptr, 'U', buffer_left);
        } else if (endpoint->mode & BINDING_MODE_Q
#if defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP) || defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE)
            || endpoint->mode & BINDING_MODE_T_Q
#endif
           ) {
            temp_ptr = write_char(temp_ptr, 'U', buffer_left);
            temp_ptr = write_char(temp_ptr, 'Q', buffer_left);
        }
    }

    // Add optional parameters, parsed from the server URL.
    if (uri_query) {
        temp_ptr = write_query_parameters(temp_ptr, uri_query, buffer_left);
    }

    return temp_ptr;
}

static void endpoint_print_coap_data(const sn_coap_hdr_s *coap_header_ptr, bool outgoing)
{
#if defined(FEA_TRACE_SUPPORT) || MBED_CONF_MBED_TRACE_ENABLE || YOTTA_CFG_MBED_TRACE || (defined(YOTTA_CFG) && !defined(NDEBUG))
    if (!coap_header_ptr) {
        return;
    }

    tr_info("======== %sing CoAP package ========", (outgoing ? "Outgo" : "Incom"));

    if (coap_header_ptr->uri_path_len > 0 && coap_header_ptr->uri_path_ptr) {
        tr_info("Uri-Path:\t\t%.*s", coap_header_ptr->uri_path_len, coap_header_ptr->uri_path_ptr);
    }
    tr_info("Status:\t\tCOAP_STATUS_%s", endpoint_coap_status_description(coap_header_ptr->coap_status));
    tr_info("Code:\t\tCOAP_MSG_CODE_%s", endpoint_coap_message_code_desc(coap_header_ptr->msg_code));
    tr_info("Type:\t\tCOAP_MSG_TYPE_%s", endpoint_coap_message_type_desc(coap_header_ptr->msg_type));
    tr_info("Id:\t\t%d", coap_header_ptr->msg_id);
    if (coap_header_ptr->token_ptr && coap_header_ptr->token_len > 0) {
        tr_info("Token:\t\t%s", tr_array(coap_header_ptr->token_ptr, coap_header_ptr->token_len));
    }
    if (coap_header_ptr->content_format != -1) {
        tr_info("Content-type:\t%d", coap_header_ptr->content_format);
    }
    tr_info("Payload len:\t%d", coap_header_ptr->payload_len);
#ifdef MBED_CLIENT_PRINT_COAP_PAYLOAD
    if (coap_header_ptr->payload_ptr && coap_header_ptr->payload_len > 0) {
        int i = 0;
        int row_len = 32;
        int max_length = 2048;
        while (i < coap_header_ptr->payload_len && i < max_length) {
            if (i + row_len > coap_header_ptr->payload_len) {
                row_len = coap_header_ptr->payload_len - i;
            }
            tr_info("PL:\t\t%s", tr_array( coap_header_ptr->payload_ptr + i, row_len));
            i += row_len;
        }
        if (i >= max_length) {
            tr_info("PL:\t\t...");
        }
    }
#endif

    if (coap_header_ptr->options_list_ptr) {
        if (coap_header_ptr->options_list_ptr->etag_ptr && coap_header_ptr->options_list_ptr->etag_len > 0) {
            tr_info("E-tag:\t%s", tr_array(coap_header_ptr->options_list_ptr->etag_ptr, coap_header_ptr->options_list_ptr->etag_len));
        }
        if (coap_header_ptr->options_list_ptr->proxy_uri_ptr && coap_header_ptr->options_list_ptr->proxy_uri_len > 0) {
            tr_info("Proxy uri:\t%.*s", coap_header_ptr->options_list_ptr->proxy_uri_len, coap_header_ptr->options_list_ptr->proxy_uri_ptr);
        }

        if (coap_header_ptr->options_list_ptr->uri_host_ptr && coap_header_ptr->options_list_ptr->uri_host_len > 0) {
            tr_info("Uri host:\t%.*s", coap_header_ptr->options_list_ptr->uri_host_len, coap_header_ptr->options_list_ptr->uri_host_ptr);
        }

        if (coap_header_ptr->options_list_ptr->location_path_ptr && coap_header_ptr->options_list_ptr->location_path_len > 0) {
            tr_info("Location path:\t%.*s", coap_header_ptr->options_list_ptr->location_path_len, coap_header_ptr->options_list_ptr->location_path_ptr);
        }

        if (coap_header_ptr->options_list_ptr->location_query_ptr && coap_header_ptr->options_list_ptr->location_query_len > 0) {
            tr_info("Location query:\t%.*s", coap_header_ptr->options_list_ptr->location_query_len, coap_header_ptr->options_list_ptr->location_query_ptr);
        }

        if (coap_header_ptr->options_list_ptr->uri_query_ptr && coap_header_ptr->options_list_ptr->uri_query_len > 0) {
            tr_info("Uri query:\t%.*s", coap_header_ptr->options_list_ptr->uri_query_len, coap_header_ptr->options_list_ptr->uri_query_ptr);
        }

        tr_info("Max-age:\t\t%" PRIu32"", coap_header_ptr->options_list_ptr->max_age);
        if (coap_header_ptr->options_list_ptr->use_size1) {
            tr_info("Size 1:\t\t%" PRIu32"", coap_header_ptr->options_list_ptr->size1);
        }
        if (coap_header_ptr->options_list_ptr->use_size2) {
            tr_info("Size 2:\t\t%" PRIu32"", coap_header_ptr->options_list_ptr->size2);
        }
        if (coap_header_ptr->options_list_ptr->accept != -1) {
            tr_info("Accept:\t\t%d", coap_header_ptr->options_list_ptr->accept);
        }
        if (coap_header_ptr->options_list_ptr->uri_port != -1) {
            tr_info("Uri port:\t%" PRId32"", coap_header_ptr->options_list_ptr->uri_port);
        }
        if (coap_header_ptr->options_list_ptr->observe != -1) {
            tr_info("Observe:\t\t%" PRId32"", coap_header_ptr->options_list_ptr->observe);
        }
        if (coap_header_ptr->options_list_ptr->block1 != -1) {
            tr_info("Block1 number:\t%" PRId32"", coap_header_ptr->options_list_ptr->block1 >> 4);
            uint8_t temp = (coap_header_ptr->options_list_ptr->block1 & 0x07);
            uint16_t block_size = 1u << (temp + 4);
            tr_info("Block1 size:\t%d", block_size);
            tr_info("Block1 more:\t%d", (coap_header_ptr->options_list_ptr->block1) & 0x08 ? true : false);
        }
        if (coap_header_ptr->options_list_ptr->block2 != -1) {
            tr_info("Block2 number:\t%" PRId32"", coap_header_ptr->options_list_ptr->block2 >> 4);
            uint8_t temp = (coap_header_ptr->options_list_ptr->block2 & 0x07);
            uint16_t block_size = 1u << (temp + 4);
            tr_info("Block2 size:\t%d", block_size);
            tr_info("Block2 more:\t%d", (coap_header_ptr->options_list_ptr->block2) & 0x08 ? true : false);
        }
    }
    tr_info("======== End of CoAP package ========");
#else
    (void) coap_header_ptr;
    (void) outgoing;
#endif
}

#if defined(FEA_TRACE_SUPPORT) || MBED_CONF_MBED_TRACE_ENABLE || YOTTA_CFG_MBED_TRACE || (defined(YOTTA_CFG) && !defined(NDEBUG))
// return human readable mapping of status to sn_coap_status_e, without "COAP_STATUS_" prefix
static const char *endpoint_coap_status_description(sn_coap_status_e status)
{
    switch(status) {
        case COAP_STATUS_OK:
            return "OK";
        case COAP_STATUS_PARSER_ERROR_IN_HEADER:
            return "PARSER_ERROR_IN_HEADER";
        case COAP_STATUS_PARSER_DUPLICATED_MSG:
            return "PARSER_DUPLICATED_MSG";
        case COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVING:
            return "PARSER_BLOCKWISE_MSG_RECEIVING";
        case COAP_STATUS_PARSER_BLOCKWISE_ACK:
            return "PARSER_BLOCKWISE_ACK";
        case COAP_STATUS_PARSER_BLOCKWISE_MSG_REJECTED:
            return "PARSER_BLOCKWISE_MSG_REJECTED";
        case COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED:
            return "PARSER_BLOCKWISE_MSG_RECEIVED";
        case COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED:
            return "BUILDER_MESSAGE_SENDING_FAILED";
        default:
            return "UNKNOWN";
    }
}

// return human readable mapping of msg_code to sn_coap_msg_code_e, without "COAP_MSG_CODE_" prefix
static const char *endpoint_coap_message_code_desc(int msg_code)
{
    switch(msg_code) {
        case COAP_MSG_CODE_EMPTY:
            return "EMPTY";
        case COAP_MSG_CODE_REQUEST_GET:
            return "REQUEST_GET";
        case COAP_MSG_CODE_REQUEST_POST:
            return "REQUEST_POST";
        case COAP_MSG_CODE_REQUEST_PUT:
            return "REQUEST_PUT";
        case COAP_MSG_CODE_REQUEST_DELETE:
            return "REQUEST_DELETE";
        case COAP_MSG_CODE_RESPONSE_CREATED:
            return "RESPONSE_CREATED";
        case COAP_MSG_CODE_RESPONSE_DELETED:
            return "RESPONSE_DELETED";
        case COAP_MSG_CODE_RESPONSE_VALID:
            return "RESPONSE_VALID";
        case COAP_MSG_CODE_RESPONSE_CHANGED:
            return "RESPONSE_CHANGED";
        case COAP_MSG_CODE_RESPONSE_CONTENT:
            return "RESPONSE_CONTENT";
        case COAP_MSG_CODE_RESPONSE_CONTINUE:
            return "RESPONSE_CONTINUE";
        case COAP_MSG_CODE_RESPONSE_BAD_REQUEST:
            return "RESPONSE_BAD_REQUEST";
        case COAP_MSG_CODE_RESPONSE_UNAUTHORIZED:
            return "RESPONSE_UNAUTHORIZED";
        case COAP_MSG_CODE_RESPONSE_BAD_OPTION:
            return "RESPONSE_BAD_OPTION";
        case COAP_MSG_CODE_RESPONSE_FORBIDDEN:
            return "RESPONSE_FORBIDDEN";
        case COAP_MSG_CODE_RESPONSE_NOT_FOUND:
            return "RESPONSE_NOT_FOUND";
        case COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED:
            return "RESPONSE_METHOD_NOT_ALLOWED";
        case COAP_MSG_CODE_RESPONSE_NOT_ACCEPTABLE:
            return "RESPONSE_NOT_ACCEPTABLE";
        case COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_INCOMPLETE:
            return "RESPONSE_REQUEST_ENTITY_INCOMPLETE";
        case COAP_MSG_CODE_RESPONSE_PRECONDITION_FAILED:
            return "RESPONSE_PRECONDITION_FAILED";
        case COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_TOO_LARGE:
            return "RESPONSE_REQUEST_ENTITY_TOO_LARGE";
        case COAP_MSG_CODE_RESPONSE_UNSUPPORTED_CONTENT_FORMAT:
            return "RESPONSE_UNSUPPORTED_CONTENT_FORMAT";
        case COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR:
            return "RESPONSE_INTERNAL_SERVER_ERROR";
        case COAP_MSG_CODE_RESPONSE_NOT_IMPLEMENTED:
            return "RESPONSE_NOT_IMPLEMENTED";
        case COAP_MSG_CODE_RESPONSE_BAD_GATEWAY:
            return "RESPONSE_BAD_GATEWAY";
        case COAP_MSG_CODE_RESPONSE_SERVICE_UNAVAILABLE:
            return "RESPONSE_SERVICE_UNAVAILABLE";
        case COAP_MSG_CODE_RESPONSE_GATEWAY_TIMEOUT:
            return "RESPONSE_GATEWAY_TIMEOUT";
        case COAP_MSG_CODE_RESPONSE_PROXYING_NOT_SUPPORTED:
            return "RESPONSE_PROXYING_NOT_SUPPORTED";
        default:
            return "UNKNOWN";
    }
}

// return human readable mapping of msg_type to sn_coap_msg_type_e, without "COAP_MSG_TYPE_" prefix
static const char *endpoint_coap_message_type_desc(int msg_type)
{
    switch(msg_type) {
        case COAP_MSG_TYPE_CONFIRMABLE:
            return "CONFIRMABLE";
        case COAP_MSG_TYPE_NON_CONFIRMABLE:
            return "NON_CONFIRMABLE";
        case COAP_MSG_TYPE_ACKNOWLEDGEMENT:
            return "ACKNOWLEDGEMENT";
        case COAP_MSG_TYPE_RESET:
            return "RESET";
        default:
            return "UNKNOWN";
    }
}
#endif


#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
static size_t endpoint_itoa_len(uint32_t value)
#else
static size_t endpoint_itoa_len(int64_t value)
#endif
{
    size_t i = 0;

#ifdef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    if (value < 0) {
        i++; // minus sign
        value *= -1;
    }
#endif

    do {
        i++;
    } while ((value /= 10) > 0);

    return i;
}


#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
static uint8_t *endpoint_itoa(uint8_t *ptr, uint32_t value)
#else
static uint8_t *endpoint_itoa(uint8_t *ptr, int64_t value)
#endif
{

    uint8_t start = 0;
    uint8_t end = 0;
    int i;

#ifdef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    bool negative = false;
    if (value < 0) {
        negative = true;
        value *= -1;
    }
#endif

    i = 0;

    /* ITOA */
    do {
        ptr[i++] = (value % 10) + '0';
    } while ((value /= 10) > 0);

#ifdef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    if (negative) {
        ptr[i++] = '-';
    }
#endif

    end = i - 1;

    /* reverse (part of ITOA) */
    while (start < end) {
        uint8_t chr;

        chr = ptr[start];
        ptr[start] = ptr[end];
        ptr[end] = chr;

        start++;
        end--;

    }
    return (ptr + i);
}

// validate that values are NULL, or that they do have nonzero length and they do not contain illegal chars
static bool validate_parameters(const endpoint_t *endpoint)
{
//    if (!validate(endpoint->domain, '&')) {TODO
//        return false;
//    }
//
//    // the endpoint name can not be empty
//    if (endpoint->name == NULL) {
//        return false;
//    }
//    if (!validate(endpoint->name, '&')) {
//        return false;
//    }

    if (!validate(endpoint->type, '&')) {
        return false;
    }
    return true;
}

static bool validate(const char* ptr, char illegalChar)
{
    if (ptr) {
        // The endpoint params need to be either NULL or have something meaningful value in them.
        // This avoids the need for silly checks everywhere for empty values.
        if (is_empty(ptr)) {
            return false;
        }
        if (strchr(ptr, illegalChar) != NULL) {
            return false;
        }
    }
    return true;
}

static bool is_empty(const char* ptr)
{
    if (ptr[0] == '\0') {
        return true;
    } else {
        return false;
    }
}

unsigned int endpoint_last_message_sent(const endpoint_t *endpoint)
{
    return endpoint->last_message_type;
}

bool endpoint_set_uri_query_parameters(endpoint_t *endpoint, const char *uri_query_params)
{
    tr_debug("set_uri_query_parameters");

    assert(endpoint);
    assert(uri_query_params);

    size_t query_len = strlens(uri_query_params);
    size_t current_len = strlens(endpoint->custom_uri_query_params);
    size_t new_size = query_len + current_len;

    if (query_len == 0 ||
        query_len > MAX_ALLOWED_STRING_LENGTH ||
        new_size > MAX_ALLOWED_STRING_LENGTH) {
        tr_error("set_uri_query_parameters - invalid size");
        return false;
    }

    // Append into existing string
    if (endpoint->custom_uri_query_params) {
        // Reserve space for "&" and null marks.

        // Note: we can't directly overwrite endpoint->custom_uri_query_params as realloc would
        // overwrite the old buffer pointer with NULL and lead into memory leak.
        void *temp_uri_query_params = lwm2m_realloc(endpoint->custom_uri_query_params,
                                                                 1 + new_size + 1);
        if (temp_uri_query_params == NULL) {
            // let the caller still use and free the original buffer
            return false;
        }

        endpoint->custom_uri_query_params = temp_uri_query_params;

        memcpy(endpoint->custom_uri_query_params + current_len, "&", 1);
        memcpy(endpoint->custom_uri_query_params + current_len + 1, uri_query_params, query_len);
        endpoint->custom_uri_query_params[1 + new_size] = '\0';
    } else {
        endpoint->custom_uri_query_params = (char*)lwm2m_alloc(query_len + 1);
        if (endpoint->custom_uri_query_params == NULL) {
            return false;
        }

        memcpy(endpoint->custom_uri_query_params, uri_query_params, query_len);
        endpoint->custom_uri_query_params[query_len] = '\0';
    }

    tr_info("set_uri_query_parameters - custom string %s", endpoint->custom_uri_query_params);
    return true;
}

#if defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP) || defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE)
static void endpoint_request_coap_ping(endpoint_t *endpoint)
{

    // Send only in TCP mode
    if (endpoint->mode != BINDING_MODE_T ||
        MBED_CLIENT_TCP_KEEPALIVE_INTERVAL == 0 ||
        endpoint->coap_time < endpoint->next_coap_ping_send_time ||
        endpoint->coap_ping_id) {
        return;
    }

    endpoint->coap_ping_request = true;
    send_queue_request(endpoint, SEND_QUEUE_COAP_PING);
}

void endpoint_send_coap_ping(endpoint_t *endpoint)
{
    sn_coap_hdr_s coap_ping = {0};

    if (!endpoint->coap_ping_request) {
        send_queue_sent(endpoint, true);
        return;
    }

    /* Configure CoAP structure for CoAP ping. */
    coap_ping.msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    coap_ping.msg_code = COAP_MSG_CODE_EMPTY;
    coap_ping.content_format = COAP_CT_NONE;

    /* Send message */
    if (ENDPOINT_STATUS_OK != endpoint_send_coap_message(endpoint, NULL, &coap_ping)) {
        tr_error("send_coap_ping - endpoint_send_coap_message failed");
        endpoint_send_event(endpoint, ENDPOINT_EVENT_ERROR_REREGISTER, ENDPOINT_EVENT_STATUS_NO_MEMORY);
        send_queue_sent(endpoint, true);
    } else {
        endpoint->coap_ping_id = coap_ping.msg_id;
    }
}

static void calculate_new_coap_ping_send_time(endpoint_t *endpoint)
{
    endpoint->next_coap_ping_send_time = endpoint->coap_time + MBED_CLIENT_TCP_KEEPALIVE_INTERVAL;
    endpoint->coap_ping_request = false;
}
#endif

static bool endpoint_command(endpoint_t *endpoint, unsigned message_type)
{
    if (endpoint->message_type != ENDPOINT_MSG_UNDEFINED) {
        tr_warn("command %d in progress", endpoint->message_type);
        return ENDPOINT_STATUS_ERROR;
    }
    tr_info("command");
    endpoint->message_type = message_type;
    send_queue_request(endpoint, SEND_QUEUE_ENDPOINT);
    return ENDPOINT_STATUS_OK;
}

void endpoint_stop_coap_exec_timer(endpoint_t *endpoint)
{
    eventOS_timeout_cancel(endpoint->coap_timeout);
    endpoint->coap_timeout = NULL;
}

void endpoint_start_coap_exec_timer(endpoint_t *endpoint)
{
    endpoint_stop_coap_exec_timer(endpoint);
    endpoint->old_tick = eventOS_event_timer_ticks();
    // To reduce the effect of jitter remainder is originally initialized to 50.
    // Time is incremented if remainder is in range 50-150, i.e. "in the middle of a second".
    // This allows up to 0.5s jitter before gaps or clumping in the tick values coap library sees.
    endpoint->tick_remainder = 50;

    endpoint->coap_timeout = eventOS_timeout_every_ms(&endpoint_coap_timer, 1000, endpoint);
}

#if MBED_CLIENT_ENABLE_PUBLISH_RESOURCE_VALUE_IN_REG_MSG

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
uint8_t* write_resource_value(uint8_t *packet, const registry_path_t *path, int32_t *packet_len, const endpoint_t *endpoint)
{
    const lwm2m_resource_meta_definition_t *static_data;
    if (REGISTRY_STATUS_OK == registry_meta_get_resource_definition(path->object_id,
                                                                    path->resource_id,
                                                                    &static_data)) {

        int64_t int_value = 0;
#if MBED_CLIENT_ENABLE_FLOAT_VALUE
        float float_value = 0;
#endif
        bool bool_value = false;
        const char *string_value = NULL;
        registry_data_opaque_t *opaque_value = NULL;

        switch (static_data->type) {
            case LWM2M_RESOURCE_TYPE_STRING:
                if (registry_get_value_string(&endpoint->registry, path, &string_value) == REGISTRY_STATUS_OK &&
                    string_value) {
                    packet = write_parameter(packet,
                                             resource_value,
                                             sizeof(resource_value),
                                             string_value,
                                             strlen(string_value),
                                             0,
                                             packet_len);
                }
                break;

            case LWM2M_RESOURCE_TYPE_INTEGER:
                if (registry_get_value_int(&endpoint->registry, path, &int_value) == REGISTRY_STATUS_OK) {
                    size_t int_len = endpoint_itoa_len(int_value);
                    uint8_t int_ptr[REGISTRY_INT64_STRING_MAX_LEN];
                    endpoint_itoa((uint8_t*)&int_ptr, int_value);
                    packet = write_parameter(packet,
                                             resource_value,
                                             sizeof(resource_value),
                                             (char*)&int_ptr,
                                             int_len,
                                             0,
                                             packet_len);
                }
                break;

#if MBED_CLIENT_ENABLE_FLOAT_VALUE
            case LWM2M_RESOURCE_TYPE_FLOAT:
                if (registry_get_value_float(&endpoint->registry, path, &float_value) == REGISTRY_STATUS_OK) {
                    char float_string[48];
                    int value_len = snprintf(float_string, 48, "%f", float_value);
                    if (value_len < 48) {
                        packet = write_parameter(packet,
                                                 resource_value,
                                                 sizeof(resource_value),
                                                 float_string,
                                                 strlens(float_string),
                                                 0,
                                                 packet_len);
                    }
                }
                break;
#endif

            case LWM2M_RESOURCE_TYPE_BOOLEAN:
                if (registry_get_value_boolean(&endpoint->registry, path, &bool_value) == REGISTRY_STATUS_OK) {
                    size_t bool_len = endpoint_itoa_len(bool_value);
                    uint8_t bool_ptr[2];
                    endpoint_itoa((uint8_t*)&bool_ptr, bool_value);
                    packet = write_parameter(packet,
                                             resource_value,
                                             sizeof(resource_value),
                                             (char*)&bool_ptr,
                                             bool_len,
                                             0,
                                             packet_len);
                }
                break;
            case LWM2M_RESOURCE_TYPE_OPAQUE:
                if (registry_get_value_opaque(&endpoint->registry, path, &opaque_value) == REGISTRY_STATUS_OK &&
                    opaque_value) {
                    size_t dst_size = (((opaque_value->size + 2) / 3) << 2) + 1;
                    unsigned char *dst = (unsigned char*) lwm2m_alloc(dst_size);
                    size_t olen = 0;
                    if (dst) {
                        int ret_val = mbedtls_base64_encode(dst, dst_size, &olen,opaque_value->data, opaque_value->size);
                        if (ret_val == 0 && olen > 0) {
                            packet = write_parameter(packet,
                                                     resource_value,
                                                     sizeof(resource_value),
                                                     (char*)dst,
                                                     olen,
                                                     0,
                                                     packet_len);

                        } else {
                            tr_error("write_resource_value - Base64 encoding err: %d, olen: %lu", ret_val, (unsigned long)olen);
                        }
                        lwm2m_free(dst);
                    }
                }
                break;
            default:
                break;
        }
    }

    return packet;
}
#endif

#endif // MBED_CLIENT_ENABLE_PUBLISH_RESOURCE_VALUE_IN_REG_MSG

#ifdef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
void endpoint_register_object_handler(endpoint_t *endpoint, object_handler_t *handler)
{
    if (!endpoint->object_handlers) {
        endpoint->object_handlers = handler;
    } else {
        object_handler_t *temp = endpoint->object_handlers;
        while (temp->next) {
            temp = temp->next;
        }
        temp->next = handler;
    }
}

void endpoint_deallocate_object_handlers(endpoint_t *endpoint)
{
    object_handler_t *to_free = endpoint->object_handlers;
    object_handler_t *next;

    while (to_free) {
        next = to_free->next;
        lwm2m_free(to_free);
        to_free = next;
    }

    endpoint->object_handlers = NULL;
}

object_handler_t *endpoint_allocate_object_handler(uint16_t object_id, get_resources_cb *res_cb,
                                                   coap_req_cb *req_cb, registry_callback_t obj_cb)
{
    object_handler_t *tmp = lwm2m_alloc(sizeof(object_handler_t));
    if (tmp) {
        tmp->object_id = object_id;
        tmp->res_cb = res_cb;
        tmp->req_cb = req_cb;
        tmp->obj_cb = obj_cb;
        tmp->next = NULL;
    }

    return tmp;
}

static uint16_t get_auto_obs_id(endpoint_t *endpoint)
{
    // auto obs token range is between 1 -1023
    endpoint->auto_obs_token++;
    if (endpoint->auto_obs_token > 1023) {
        endpoint->auto_obs_token = 1;
    }
    return endpoint->auto_obs_token;
}

static uint8_t *encode_resource_value_int(int64_t value, uint8_t *ptr, size_t *len)
{
    const size_t buf_len = *len;

    *len = endpoint_itoa_len(value);

    assert(ptr);
    assert(buf_len >= *len);
    ((void)buf_len);

    return endpoint_itoa(ptr, value);
}

register_resource_t *endpoint_create_register_resource_str(endpoint_t *endpoint,
                                                           const char *id, bool auto_obs,
                                                           const uint8_t *value, uint16_t len)
{
    register_resource_t *res = lwm2m_alloc(sizeof(register_resource_t));
    if (!res) {
        return NULL;
    }
    res->next = NULL; // zero-init the link
    res->full_res_id = id;

#if MBED_CLIENT_ENABLE_AUTO_OBSERVATION
    if (auto_obs) {
        res->aobs_id = get_auto_obs_id(endpoint);
    } else {
        res->aobs_id = 0;
    }
#else
    res->aobs_id = 0;
    (void)auto_obs;
    (void)endpoint;
#endif

#if MBED_CLIENT_ENABLE_PUBLISH_RESOURCE_VALUE_IN_REG_MSG
    if (value && len) {
        uint8_t *val = lwm2m_alloc_copy(value, len);
        if (!val) {
            lwm2m_free(res);
            return NULL;
        }
        res->value_len = len;
        res->value = val;
    } else {
        res->value_len = 0;
        res->value = NULL;
    }
#else
    (void)value;
    (void)len;
#endif

    return res;
}

register_resource_t *endpoint_create_register_resource_int(endpoint_t *endpoint,
                                                           const char *id,
                                                           bool auto_obs,
                                                           int64_t value)
{
    uint8_t int_buf[REGISTRY_INT64_STRING_MAX_LEN];
    size_t len = sizeof(int_buf);

    encode_resource_value_int(value, int_buf, &len);

    return endpoint_create_register_resource_str(endpoint, id, auto_obs, int_buf, len);
}

register_resource_t *endpoint_create_register_resource_opaque(endpoint_t *endpoint,
                                                           const char *id, bool auto_obs,
                                                           const uint8_t *value, uint16_t len)
{
    int ret;
    register_resource_t * res;
    size_t dst_size;
    uint8_t *dst;
    size_t olen;

    dst_size = (((len + 2) / 3) << 2) + 1;
    dst = (uint8_t*) lwm2m_alloc(dst_size);
    if (!dst) {
        tr_error("create_register_resource_opaque - failed to allocate buffer");
        return NULL;
    }

    olen = 0;
    ret = mbedtls_base64_encode(dst, dst_size, &olen, value, len);
    if (ret == 0 && olen > 0) {
        res = endpoint_create_register_resource_str(endpoint, id, auto_obs, dst, olen);
    } else {
        tr_error("create_register_resource_opaque - Base64 encoding err: %d, olen: %d", ret, olen);
        res = NULL;
    }
    lwm2m_free(dst);

    return res;
}

register_resource_t *endpoint_create_register_resource(endpoint_t *endpoint, const char *id, bool auto_obs)
{
    return endpoint_create_register_resource_str(endpoint, id, auto_obs, NULL, 0);
}

static object_handler_t* get_object_handler(endpoint_t* endpoint, uint16_t object_id)
{
    object_handler_t *handler = endpoint->object_handlers;
    while (handler) {
        if (handler->object_id == object_id) {
            return handler;
        }
        handler = handler->next;
    }
    return NULL;
}

coap_req_cb* endpoint_get_coap_request_callback(endpoint_t *endpoint, uint16_t object_id)
{
    object_handler_t *handler = get_object_handler(endpoint, object_id);
    if (handler) {
        return handler->req_cb;
    }
    return NULL;
}

registry_callback_t endpoint_get_object_callback(endpoint_t *endpoint, uint16_t object_id)
{
    object_handler_t *handler = get_object_handler(endpoint, object_id);
    if (handler) {
        return handler->obj_cb;
    }
    return NULL;
}

int endpoint_send_notification_int(endpoint_t *endpoint, registry_path_t *path, uint16_t aobs_id, int64_t value)
{
    int ret = -1;
    uint16_t token;
    uint8_t int_buf[REGISTRY_INT64_STRING_MAX_LEN];
    size_t len = sizeof(int_buf);

    tr_debug("send_notification(), object id: %d, resource id %d", path->object_id, path->resource_id);

    assert(endpoint);
    assert(path);

    if (!endpoint->registered) {
        return NOTIFICATION_STATUS_NOT_REGISTERED;
    }

    if (endpoint->notifier.notifying) {
        tr_debug("a notification is already pending");
        return NOTIFICATION_STATUS_RESEND_QUEUE_FULL;
    }

    encode_resource_value_int(value, int_buf, &len);

    // swap token byte order
    token = (aobs_id & 0xFF00) >> 8 | (aobs_id & 0xFF) << 8;

    ret = notifier_send_observation_notification(endpoint, endpoint->lifetime, (uint8_t*)&token, sizeof(token), int_buf, len, COAP_CT_TEXT_PLAIN);
    if (ret == NOTIFICATION_STATUS_SENT) {
        endpoint->notifier.last_notified = *path;
        endpoint->notifier.notifying = true;
    }

    return ret;
}
#endif
