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

#ifndef LWM2M_CONNECTION_H
#define LWM2M_CONNECTION_H

#include "lwm2m_config.h"
#include "protoman.h"
#include "protoman_layer_mbedtls.h"
#include "connection_protoman_layers.h"

#ifdef MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#include MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#else
#error "User must define MBED_CLOUD_CLIENT_USER_CONFIG_FILE"
#endif


/** \file lwm2m_connection.h
 *  \brief Client Lite network connectivity API.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  \brief Defines connection event types.
 */
typedef enum connection_event_e {

    CONNECTION_EVENT_CONNECTED, ///< Connection ready.
    CONNECTION_EVENT_DISCONNECTED, ///< Connection closed.
    CONNECTION_EVENT_DESTROYED, ///< Connection destroyed.
    CONNECTION_EVENT_DATA, ///< Data available.
    CONNECTION_EVENT_DATA_SENT, ///< Data has been sent.
    CONNECTION_EVENT_INTERFACE_STATUS,
    CONNECTION_EVENT_ERROR, ///< General connection error occurred.

} connection_event_t;

#define CONNECTION_EVENT_ID 70

/**
 *  \brief Main data structure for Client Lite connectivity logic.
 *
 *  \note Fields of this structure are only used internally by this module.
 */
typedef struct connection_s {

    struct protoman_s protoman; ///< Protocol manager that is used with the connection.
    void(*event_handler)(connection_event_t, void*, int); ///< Pointer to the event handler.
    void *context; ///< Pointer given as a parameter when calling the event handler.

#ifndef PROTOMAN_OFFLOAD_TLS
#ifdef PROTOMAN_SECURITY_ENABLE_CERTIFICATE
    struct protoman_layer_mbedtls_certificate_s protoman_layer_mbedtls; ///< Protoman structure for certificate.
#elif defined (PROTOMAN_SECURITY_ENABLE_PSK)
    struct protoman_layer_mbedtls_psk_s protoman_layer_mbedtls; ///< Protoman structure for PSK.
#else
#error "Select Certificate or PSK mode"
#endif // PROTOMAN_SECURITY_ENABLE_CERTIFICATE || PROTOMAN_SECURITY_ENABLE_PSK
#endif // PROTOMAN_OFFLOAD_TLS

    connection_protoman_layers_t protoman_layers; ///< Structure for connectivity layers.

    int8_t event_handler_id;

} connection_t;

#define CONNECTION_STATUS_WOULD_BLOCK 1 ///< No more data available.
#define CONNECTION_STATUS_OK 0 ///< Success.
#define CONNECTION_STATUS_IO_ERROR (-2) ///< Invalid input.
#define CONNECTION_STATUS_ERROR_GENERIC (-3) ///< Generic error.
#define CONNECTION_STATUS_ERROR_MAX_ENTROPY_SOURCES (-4) ///< Entropy source cannot be added as the limit is reached.


#define CONNECTION_MODE_FLAG_SECURE 1 ///< Flag for setting DTLS or TLS on.
#define CONNECTION_MODE_FLAG_TCP    2 ///< Flag or setting TCP on.

#define CONNECTION_MODE_UDP         0 ///< UDP mode.
#define CONNECTION_MODE_TCP         CONNECTION_MODE_FLAG_TCP ///< TCP mode.
#define CONNECTION_MODE_DTLS        CONNECTION_MODE_FLAG_SECURE ///< DTLS mode.
#define CONNECTION_MODE_TLS         (CONNECTION_MODE_FLAG_SECURE | CONNECTION_MODE_FLAG_TCP) ///< TLS mode.

#if (PROTOMAN_MTU < SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE)
#error "PROTOMAN_MTU must be larger than SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE"
#endif

/**
 * \brief Initialize the connection.
 *
 * \note This function must be called before calling other connection functions.
 * \note All the parameters given to this function must stay valid as long as this connection is used.
 *
 * \param connection Pointer to the connection to be initialized.
 * \param event_handler Pointer to a function that is called when connection related event occurs.
 * \param context The value of this pointer is given as a parameter to `event_handler` when it is called.
 * \param hostname Hostname to be resolved and connected to.
 * \param port UDP or TCP port to be connected to.
 * \param mode Transport and security mode, for example `CONNECTION_MODE_DTLS` or `CONNECTION_MODE_TLS`.
 * \param interface Pointer to the interface that is used.
 * \param ca_cert Pointer to the CA certificate. Not used in PSK mode.
 * \param ca_cert_len Length of the `ca_cert`.
 * \param cert Pointer to a client certificate or PSK identity.
 * \param cert_len Length of the `cert`.
 * \param key Pointer to the certificate or PSK Key.
 * \param key_len Length of the `key`.
 * \param bootstrap Authenticating against BS or LwM2M
 *
 * \return CONNECTION_STATUS_OK Initialization done.
 * \return CONNECTION_STATUS_ERROR_GENERIC Initialization failed.
 */
int8_t connection_init(connection_t *connection, void(*event_handler)(connection_event_t,void*,int), int8_t event_handler_id,
                       void *context, char *hostname, uint16_t port, uint8_t mode, void* interface,
                       const uint8_t *ca_cert, uint16_t ca_cert_len, const uint8_t *cert, uint16_t cert_len, const uint8_t *key, uint16_t key_len
#if defined(PROTOMAN_USE_SSL_SESSION_RESUME) || defined(PROTOMAN_OFFLOAD_TLS)
                       , bool bootstrap
#endif
                       );

/**
 * \brief Destroy the connection.
 *
 * \note After calling this function, other connection calls must not be done before calling `connection_init` again.
 *
 * \param connection Pointer to the connection to be destroyed.
 */
void connection_destroy(connection_t *connection);

/**
 * \brief Close the connection. Does not completely stop everything like `connection_destroy`.
 *        Is used for temporarily closing the connection.
 *
 * \note After calling this function, other connection calls must not be done before calling `connection_init` again.
 *
 * \param connection Pointer to the connection to be destroyed.
 */
void connection_close(connection_t *connection);

/**
 * \brief Try to establish connection using the parameters set with `connection_init`.
 *
 * \param connection Pointer to the connection to be started.
 */
void connection_start(connection_t *connection);

/**
 * \brief Close the connection. The connection can be opened again.
 *
 * \param connection Pointer to the connection to be closed.
 */
void connection_stop(connection_t *connection);

/**
 * \brief Send data using a connection.
 *
 * \note Data sending may fail even if this function is successfully called.
 *
 * \param connection Connection used for sending data.
 * \param data Pointer to the data.
 * \param data_len Length of the `data`.
 * \param free_data If true, pointer `data` is freed by the connection using `lwm2m_free`.
 *
 * \return CONNECTION_STATUS_OK No errors.
 * \return CONNECTION_STATUS_WOULD_BLOCK Previous data still pending.
 * \return CONNECTION_STATUS_ERROR_GENERIC Generic error occurred.
 * \return CONNECTION_STATUS_IO_ERROR Input parameter incorrect.
 */
int8_t connection_send_data(connection_t *connection, uint8_t *data, const size_t data_len, bool free_data);

/**
 * \brief Read data using the connection.
 *
 * \param connection Connection used for reading data.
 * \param data Pointer to the data read after a successful call.
 *             After reading the data from the `data` pointer, it must be passed to `lwm2m_free`.
 * \param data_len Must be a valid pointer to `size_t`, where the length of the data read is set after a successful call.
 * \param address This parameter will point to the source address after a successful call.
 * \param address_len Must be a valid pointer to `uint8_t`, where the length of the source address is set after a successful call.
 * \param port Must be a valid pointer to `uint16_t`, where the source port is set after a successful call.
 *
 * \return CONNECTION_STATUS_OK Data read from socket.
 * \return CONNECTION_STATUS_ERROR_GENERIC Error occurred, parameters not set.
 */
int8_t connection_read_data(connection_t *connection, uint8_t **data, size_t *data_len, uint8_t **address, uint8_t *address_len, uint16_t *port);

/**
 * \brief Get server address associated with this connection.
 *
 * \param connection Connection used for reading the address.
 * \param address This parameter will point to the server address after a successful call.
 * \param address_len Must be a valid pointer to `uint8_t`, where the length of the source address is set after a successful call.
 * \param port Must be a valid pointer to uint16_t, where the server port is set after a successful call.
 *
 * \return CONNECTION_STATUS_OK Data read from socket.
 * \return CONNECTION_STATUS_ERROR_GENERIC Error occurred, parameters not set.
 */
int8_t connection_get_server_address(connection_t *connection, uint8_t **address, uint8_t *address_len, uint16_t *port);

#ifndef PROTOMAN_OFFLOAD_TLS
/**
 * \brief Set callback function for creating entropy for a secure connection.
 *
 * \param connection Secure connection.
 * \param callback Entropy callback that can be called by the connection security.
 *
 * \return CONNECTION_STATUS_OK Entropy callback set.
 * \return CONNECTION_STATUS_ERROR_MAX_ENTROPY_SOURCES New entropy callback can not be added.
 */
int8_t connection_set_entropy_callback(connection_t *connection, entropy_cb callback);
#endif // PROTOMAN_OFFLOAD_TLS

void connection_interface_status(connection_t *connection, bool up);

int8_t connection_protoman_layers_init(struct connection_s *connection, char *hostname, uint16_t port,
                                       void* interface
#ifdef PROTOMAN_OFFLOAD_TLS
                                       ,bool bootstrap
#endif
                                       );

#ifdef __cplusplus
}
#endif

#endif //LWM2M_CONNECTION_H
