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

#include "lwm2m_connection.h"
#include "lwm2m_network_connection.h"
#include "lwm2m_heap.h"
#include "mbed_trace.h"
#include "eventOS_event.h"
#if defined(MBEDTLS_SSL_CONF_RNG)
#include "shared_rng.h"
#endif

#include <string.h>

#define TRACE_GROUP "Conn"

//TODO: Check error handling for all functions.

static void protoman_event_handler(protoman_id_t protoman_id, protoman_layer_id_t layer_id, uint8_t event_id, void* connection)
{
    int perror;

    switch (event_id) {

        case PROTOMAN_EVENT_DATA_AVAIL:
            ((connection_t*)connection)->event_handler(CONNECTION_EVENT_DATA, ((connection_t*)connection)->context, 0);
            break;

        case PROTOMAN_EVENT_CONNECTED:
            ((connection_t*)connection)->event_handler(CONNECTION_EVENT_CONNECTED, ((connection_t*)connection)->context, 0);
            break;

        case PROTOMAN_EVENT_ERROR:
            perror = protoman_get_layer_error(protoman_id);

            if (PROTOMAN_ERR_CONNECTION_CLOSED == perror) {
                tr_info("protoman_event_handler - remote disconnected");
                ((connection_t*)connection)->event_handler(CONNECTION_EVENT_DISCONNECTED, ((connection_t*)connection)->context, perror);
                break;
            }

            ((connection_t*)connection)->event_handler(CONNECTION_EVENT_ERROR, ((connection_t*)connection)->context, perror);
            break;

        case PROTOMAN_EVENT_DISCONNECTED:
            /* This is user initiated disconnection event */
        case PROTOMAN_APPEVENT_STATE_CHANGE:
            /* Protoman state has changed, note that connected and disconnected use their own IDs */
        case PROTOMAN_EVENT_INITIALIZED:
            /* Protoman initialized. */
            break;

        case PROTOMAN_EVENT_DATA_WRITTEN:
            ((connection_t*)connection)->event_handler(CONNECTION_EVENT_DATA_SENT, ((connection_t*)connection)->context, 0);
            break;

        default:
            tr_warn("protoman_event_handler - protoman event not handled, id: %s (%d)", protoman_strevent(event_id), event_id);
            break;

    }
}

int8_t connection_init(connection_t *connection, void(*event_handler)(connection_event_t,void*,int), int8_t event_handler_id,
        void *context, char *hostname, uint16_t port, uint8_t mode, void* interface,
        const uint8_t *ca_cert, uint16_t ca_cert_len, const uint8_t *cert, uint16_t cert_len, const uint8_t *key, uint16_t key_len
#if defined(PROTOMAN_USE_SSL_SESSION_RESUME) || defined(PROTOMAN_OFFLOAD_TLS)
        , bool bootstrap
#endif
        )
{

    connection->event_handler = event_handler;
    connection->event_handler_id = event_handler_id;

    connection->context = context;

    protoman_open(&connection->protoman, &protoman_event_handler, connection);
    struct protoman_config_s *protoman_config = protoman_get_config(&connection->protoman, NULL);

    if (mode & CONNECTION_MODE_FLAG_TCP) {
        protoman_config->is_dgram = false;
    } else {
        protoman_config->is_dgram = true;
    }

    if (mode & CONNECTION_MODE_FLAG_SECURE) {

#ifndef PROTOMAN_OFFLOAD_TLS
#if defined (PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
        struct protoman_config_tls_certificate_s *tls_configuration;
        memset(&connection->protoman_layer_mbedtls, 0, sizeof(struct protoman_layer_mbedtls_certificate_s));
        protoman_add_layer_mbedtls(&connection->protoman, (protoman_layer_id_t)&connection->protoman_layer_mbedtls);

        tls_configuration = protoman_get_config(&connection->protoman, (protoman_layer_id_t)&connection->protoman_layer_mbedtls);

        tls_configuration->common.security_mode = PROTOMAN_SECURITY_MODE_CERTIFICATE;
        tls_configuration->cacert.header.type = PROTOMAN_IO_CERTBUF;

        tls_configuration->cacert.buf = (uint8_t*)ca_cert;
        tls_configuration->cacert.len = ca_cert_len;

        tls_configuration->owncert.header.type = PROTOMAN_IO_CERTBUF;
        tls_configuration->owncert.buf = (uint8_t*)cert;
        tls_configuration->owncert.len = cert_len;

        tls_configuration->ownkey.header.type = PROTOMAN_IO_KEYBUF;
        tls_configuration->ownkey.buf = (uint8_t*)key;
        tls_configuration->ownkey.len = key_len;

#ifdef PROTOMAN_USE_SSL_SESSION_RESUME
        tls_configuration->bootstrap = bootstrap;
#endif

#elif defined (PROTOMAN_SECURITY_ENABLE_PSK)
        struct protoman_config_tls_psk_s *tls_configuration;
        memset(&connection->protoman_layer_mbedtls, 0, sizeof(struct protoman_layer_mbedtls_psk_s));
        protoman_add_layer_mbedtls(&connection->protoman, (protoman_layer_id_t)&connection->protoman_layer_mbedtls);
        tls_configuration = protoman_get_config(&connection->protoman, (protoman_layer_id_t)&connection->protoman_layer_mbedtls);

        tls_configuration->common.security_mode = PROTOMAN_SECURITY_MODE_PSK;

        tls_configuration->psk.header.type = PROTOMAN_IO_PSKBUF;

        tls_configuration->psk.buf = (uint8_t*)key;
        tls_configuration->psk.len = key_len;

        tls_configuration->psk_identity.header.type = PROTOMAN_IO_BYTES;

        tls_configuration->psk_identity.buf = (uint8_t*)cert;
        tls_configuration->psk_identity.len = cert_len;
#else
        tr_error("Select either Certificate or PSK mode for secure connection");
#endif
#endif // #ifndef PROTOMAN_OFFLOAD_TLS
    }

    // Add connectivity layers to protoman
    return connection_protoman_layers_init(connection, hostname, port, interface
#ifdef PROTOMAN_OFFLOAD_TLS
                                           , bootstrap
#endif
                                           );
}

void connection_destroy(connection_t *connection)
{
    protoman_close(&connection->protoman);
#if MBED_CONF_NSAPI_PRESENT
    network_connection_destroy();
#endif
}

void connection_close(connection_t *connection)
{
    protoman_close(&connection->protoman);
}

void connection_start(connection_t *connection)
{
    protoman_connect(&connection->protoman);
}

void connection_stop(connection_t *connection)
{
    protoman_disconnect(&connection->protoman);
}


int8_t connection_send_data(connection_t *connection, uint8_t *data, const size_t data_len, bool free_data)
{

    int protoman_return_value;
    int8_t status = CONNECTION_STATUS_ERROR_GENERIC;
    struct protoman_io_bytes_s msg;

    if (free_data) {
        //NOTE: To be able to use this feature protoman MUST use the same allocator as lwm2m_alloc.
        msg.header.type = PROTOMAN_IO_ZEROCOPY;
    } else {
        msg.header.type = PROTOMAN_IO_BYTES;
    }
    msg.buf = data;
    msg.len = data_len;

    protoman_return_value = protoman_write(&connection->protoman, (struct protoman_io_header_s*)&msg);

    switch(protoman_return_value) {

        case PROTOMAN_ERR_NOMEM:
        case PROTOMAN_ERR_WOULDBLOCK:

            tr_warn("connection_send_data - local congestion, trashing packet");
            status = CONNECTION_STATUS_WOULD_BLOCK;
            break;

        case PROTOMAN_ERR_WRONG_IO_TYPE:
        case PROTOMAN_ERR_INVALID_INPUT:

            tr_error("connection_send_data - input error");
            status = CONNECTION_STATUS_IO_ERROR;
            break;

        default:

            if (protoman_return_value > 0) {
                return CONNECTION_STATUS_OK;
            }

            tr_error("connection_send_data - protoman error: %d", protoman_return_value);

    }

    if (free_data) {
        lwm2m_free(data);
    }

    return status;

}

int8_t connection_read_data(connection_t *connection, uint8_t **data, size_t *data_len, uint8_t **address, uint8_t *address_len, uint16_t *port)
{
    struct protoman_io_bytes_s msg;

    msg.header.type = PROTOMAN_IO_ZEROCOPY;
    msg.buf = NULL;
    msg.len = *data_len;

    *data_len = protoman_read(&connection->protoman, (struct protoman_io_header_s*)&msg);

    if (0 >= *data_len) {
        return CONNECTION_STATUS_ERROR_GENERIC;
    }

    *data = msg.buf;

    *address = protoman_get_info(&connection->protoman, NULL, PROTOMAN_INFO_IP_BYTES);
    *address_len = *(size_t *)protoman_get_info(&connection->protoman, NULL, PROTOMAN_INFO_IP_LEN);
    *port = *(uint16_t *)protoman_get_info(&connection->protoman, NULL, PROTOMAN_INFO_PORT);

    return CONNECTION_STATUS_OK;

}

int8_t connection_get_server_address(connection_t *connection, uint8_t **address, uint8_t *address_len, uint16_t *port)
{
    *address = protoman_get_info(&connection->protoman, NULL, PROTOMAN_INFO_IP_BYTES);
    *address_len = 0;
    *port = 0;
    if (*address) {
        void *return_value = 0;

        return_value = protoman_get_info(&connection->protoman, NULL, PROTOMAN_INFO_IP_LEN);
        if (return_value) {
            *address_len = *(size_t *)return_value;
        }

        return_value = protoman_get_info(&connection->protoman, NULL, PROTOMAN_INFO_PORT);
        if (return_value) {
            *port = *(uint16_t *)return_value;
        }
    } else {
        return CONNECTION_STATUS_ERROR_GENERIC;
    }

    return CONNECTION_STATUS_OK;
}
#ifndef PROTOMAN_OFFLOAD_TLS
int8_t connection_set_entropy_callback(connection_t *connection, entropy_cb callback)
{
#if !defined(MBEDTLS_SSL_CONF_RNG)
    int status = mbedtls_entropy_add_source(&connection->protoman_layer_mbedtls.common.entropy, callback.entropy_source_ptr, callback.p_source, callback.threshold, callback.strong);

#else
    int status = mbedtls_entropy_add_source(get_global_entropy(), callback.entropy_source_ptr, callback.p_source, callback.threshold, callback.strong);
#endif

    if (status == MBEDTLS_ERR_ENTROPY_MAX_SOURCES) {
        return CONNECTION_STATUS_ERROR_MAX_ENTROPY_SOURCES;
    }

    return CONNECTION_STATUS_OK;
}
#endif // #ifndef PROTOMAN_OFFLOAD_TLS

static void connection_send_event(connection_t *connection, uint8_t type, uint32_t status)
{
    arm_event_t event;

    event.data_ptr = connection->context;
    event.event_data = status;
    event.event_id = CONNECTION_EVENT_ID;
    event.event_type = type;
    event.priority = ARM_LIB_LOW_PRIORITY_EVENT;
    event.receiver = connection->event_handler_id;
    event.sender = 0;

    if (0 > eventOS_event_send(&event)) {
        tr_error("eventOS_event_send() failed.");
    }
}


void connection_interface_status(connection_t *connection, bool up)
{
    connection_send_event(connection, CONNECTION_EVENT_INTERFACE_STATUS, !up);
}
