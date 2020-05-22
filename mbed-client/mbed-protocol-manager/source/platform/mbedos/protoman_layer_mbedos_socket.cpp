/*
 * PackageLicenseDeclared: Apache-2.0
 * Copyright (c) 2017-2018 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if MBED_CONF_NSAPI_PRESENT

#include "mbed.h"
#include "UDPSocket.h"
#include "NetworkInterface.h"
#include "NetworkStack.h"
#include "mbed-protocol-manager/protoman.h"
#include "mbed-protocol-manager/protoman_layer.h"
#include "mbed-protocol-manager/platform/mbedos/protoman_layer_mbedos_socket.h"
#include "include/protoman_internal.h"
#include "include/platform/mbedos/protoman_layer_mbedos_socket_error_parser.h"
#include "CloudClientStorage.h"
#include "MbedCloudClientConfig.h"

#include <assert.h>

#define TRACE_GROUP  "Pmbs" /* ProtocolManager Mbed-OS socket */

// PROTOMAN_OFFLOAD_TLS feature is only available with TCP
#if defined (PROTOMAN_OFFLOAD_TLS) && (defined (MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP) || defined (MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP_QUEUE))
#error "PROTOMAN_OFFLOAD_TLS is only supported with TCP!"
#endif

#ifdef PROTOMAN_OFFLOAD_TLS
#include "DTLSSocketWrapper.h"
#include "TLSSocketWrapper.h"
#include "AT_CellularStack.h"
#endif // PROTOMAN_OFFLOAD_TLS

#ifdef MBED_HEAP_STATS_ENABLED
#include "memory_tests.h"
#endif

// This macro will enable the socket callback bouncing out of possible
// interrupt context.
// Note: the value of this macro could/should be hardware/application specific,
// as generally the NICs which use LwIP already call the callback from
// thread context and the memory needed for shared event queue could
// be eliminated completely on those platforms.
#ifndef PROTOMAN_USE_SOCKET_CALLBACK_BOUNCE

// If the OS side has enabled the IRQ safe critical section, let's use it here too.
#if MBED_CONF_NANOSTACK_HAL_CRITICAL_SECTION_USABLE_FROM_INTERRUPT == 1
#else
#define PROTOMAN_USE_SOCKET_CALLBACK_BOUNCE
#endif
#endif

#define PROTOMAN_MBEDOS_OPENING     1
#define PROTOMAN_MBEDOS_RESOLVING   2
#define PROTOMAN_MBEDOS_CONNECTING  3

struct protoman_layer_mbedos_socket_s { /* Create me with new */
    protoman_layer_mbedos_socket_s()
        : socket(NULL),
#ifdef PROTOMAN_USE_SOCKET_CALLBACK_BOUNCE
        shared_event_queue(NULL),
#endif
        state(0),
        async_dns_query(0)
    {
        memset(&layer, 0, sizeof(layer));
        memset(&config, 0, sizeof(config));
    }
    struct protoman_layer_s layer; /* must be first element */
    struct protoman_config_mbedos_socket_s config;
    SocketAddress address;
    Socket *socket;
#ifdef PROTOMAN_USE_SOCKET_CALLBACK_BOUNCE
    events::EventQueue* shared_event_queue;
#endif
    int state;
    /* identifies an ongoing asynchronous dns query if higher than zero */
    int async_dns_query;
};

/* static function declarations */
static void* layer_info(struct protoman_layer_s *layer, int info_id);

static int _do_write(struct protoman_layer_s *layer);
static int _do_read(struct protoman_layer_s *layer);
static int _do_connect(struct protoman_layer_s *layer);
static int _do_disconnect(struct protoman_layer_s *layer);
static void layer_free(struct protoman_layer_s *layer);

#ifdef PROTOMAN_USE_SOCKET_CALLBACK_BOUNCE
static void _data_received_callback_bouncer(void *ctx_in);
#endif

static void _data_received_callback(void *ctx_in);

static void _async_dns_callback_bouncer(void *data, nsapi_error_t result, SocketAddress *address);
static void _async_dns_callback(void *data, nsapi_error_t result, SocketAddress *address);

static const struct protoman_layer_callbacks_s callbacks = {
    &layer_info,
    &protoman_generic_bytes_layer_read,
    &protoman_generic_bytes_layer_write,
    &protoman_generic_layer_event,
    &layer_free,
    NULL,
    &_do_connect,
    &_do_read,
    &_do_write,
    &_do_disconnect,
    NULL,
    NULL
};

#ifdef PROTOMAN_OFFLOAD_TLS
#include "mbedtls/pem.h"

bool store_setting_to_modem(TLSSocket &socket, cloud_client_param param, int option, bool convert_to_pem);

int convert_der_to_pem(bool certificate, const uint8_t *der_buffer, const size_t der_buffer_size, uint8_t* out_buf, size_t *out_buf_len, const size_t buf_size)
{
    const char *BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n";
    const char *END_PRIVATE_KEY = "-----END PRIVATE KEY-----\n";
    const char *BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n";
    const char *END_CERTIFICATE = "-----END CERTIFICATE-----\n";

    int result = 0;
    if (certificate) {
        result = mbedtls_pem_write_buffer(BEGIN_CERTIFICATE, END_CERTIFICATE,
                                 (unsigned char *)der_buffer, der_buffer_size,
                                 out_buf, buf_size, out_buf_len );
    } else {
        result = mbedtls_pem_write_buffer(BEGIN_PRIVATE_KEY, END_PRIVATE_KEY,
                                 (unsigned char *)der_buffer, der_buffer_size,
                                 out_buf, buf_size, out_buf_len );
    }

    tr_debug("mbedtls_pem_write_buffer - res: %d, out len: %d", result, *out_buf_len);

    return result;
}
#endif //PROTOMAN_OFFLOAD_TLS

void* protoman_layer_mbedos_socket_new()
{
#ifdef PROTOMAN_VERBOSE
    struct protoman_layer_s *layer = NULL;
#endif // PROTOMAN_VERBOSE
    struct protoman_layer_mbedos_socket_s *layer_mbedos_socket;

    layer_mbedos_socket = new protoman_layer_mbedos_socket_s;

    if (NULL != layer_mbedos_socket) {
#ifdef PROTOMAN_VERBOSE
        layer = (struct protoman_layer_s *)layer_mbedos_socket;
        layer->name = "Mbed OS Socket";
#endif
        protoman_verbose("new Mbed OS socket layer at %p", layer_mbedos_socket);
    } else {
        tr_err("Not enough memory to create a new Mbed OS socket layer");
    }

    return (void *) layer_mbedos_socket;
}

void protoman_layer_mbedos_socket_delete(void *layer_in)
{
#ifdef PROTOMAN_VERBOSE
    struct protoman_layer_s *layer = (struct protoman_layer_s *)layer_in;
#endif // PROTOMAN_VERBOSE
    struct protoman_layer_mbedos_socket_s *layer_mbedos_socket = (struct protoman_layer_mbedos_socket_s *)layer_in;

    protoman_verbose("");
    delete layer_mbedos_socket;
}

// This is configured by ifdef to allow some network interfaces to continue working without bouncing,
// as the callback is already called from a thread context (which is typically the case when
// a LwIP stack is in use)
#ifdef PROTOMAN_USE_SOCKET_CALLBACK_BOUNCE
static void _data_received_callback_bouncer(void *ctx_in)
{
    struct protoman_layer_mbedos_socket_s *layer_mbedos_socket = (struct protoman_layer_mbedos_socket_s *)ctx_in;

    assert(layer_mbedos_socket);
    assert(layer_mbedos_socket->shared_event_queue);

    layer_mbedos_socket->shared_event_queue->call(_data_received_callback, ctx_in);
}
#endif

// This callback is called either by the socket API directly or by the shared event queue's helper thread
static void _data_received_callback(void *ctx_in)
{
    struct protoman_layer_s *layer = (struct protoman_layer_s *)ctx_in;
    struct protoman_s *protoman = layer->protoman;

    protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
}

/* info needs to return pointer, so we have few consts here to avoid some pointless RAM usage */
static const size_t ipv4_address_bytes = NSAPI_IPv4_BYTES;
static const size_t ipv6_address_bytes = NSAPI_IPv6_BYTES;

static void* layer_info(struct protoman_layer_s *layer, int info_id)
{
    struct protoman_layer_mbedos_socket_s *layer_mbedos_socket = (struct protoman_layer_mbedos_socket_s *)layer;
    protoman_verbose("info request for %s", protoman_strinfo(info_id));
    nsapi_version_t addr_version;

    switch (info_id) {
        case PROTOMAN_INFO_HOSTNAME:
            return layer_mbedos_socket->config.socket.hostname;

        case PROTOMAN_INFO_IP_STR:
            return (void*)layer_mbedos_socket->address.get_ip_address();

        case PROTOMAN_INFO_IP_BYTES:
            return (void*)layer_mbedos_socket->address.get_ip_bytes();

        case PROTOMAN_INFO_IP_LEN:
            addr_version = layer_mbedos_socket->address.get_ip_version();
            switch (addr_version) {
                case NSAPI_IPv4:
                    return (void*)&ipv4_address_bytes;
                case NSAPI_IPv6:
                    return (void*)&ipv6_address_bytes;
                default:
                    break;
            }
            return NULL; /* failed */

        case PROTOMAN_INFO_PORT:
            return &layer_mbedos_socket->config.socket.port;

        default:
            return NULL;
    }
}

int protoman_add_layer_mbedos_socket(struct protoman_s *protoman, struct protoman_layer_s *layer)
{
    struct protoman_layer_mbedos_socket_s *layer_mbedos_socket = (struct protoman_layer_mbedos_socket_s *)layer;

    layer->name = "Mbed OS socket"; // must be set before first print from this layer
    layer->callbacks = &callbacks;

    protoman_debug("");

    layer->config = &layer_mbedos_socket->config;
    layer_mbedos_socket->state = PROTOMAN_MBEDOS_OPENING;
    layer_mbedos_socket->async_dns_query = 0;

#ifdef PROTOMAN_USE_SOCKET_CALLBACK_BOUNCE
    // Pre fetch and store the shared queue used for bouncing the callbacks out of interrupt
    // context, as the user of it may be ran from interrupt and it can't go and start
    // creating worker threads from there.
    // Note: the code uses mbed_highprio_event_queue() instead of mbed_event_queue()
    // as the high priority queue and its thread is likely there already thanks to
    // arm_hal_timer.cpp. Technically the client side does not really care, if the events
    // were delayed a bit by other events or not, so any queue will do fine.
    layer_mbedos_socket->shared_event_queue = mbed_highprio_event_queue();
    if (layer_mbedos_socket->shared_event_queue == NULL) {
        protoman_err("failed to initialize shared event queue");
        return -1;
    }
#endif

    if (protoman->config.is_dgram) {
        layer_mbedos_socket->socket = new UDPSocket();
    } else {
#ifdef PROTOMAN_OFFLOAD_TLS
        layer_mbedos_socket->socket = new TLSSocket();
#else
        layer_mbedos_socket->socket = new TCPSocket();
#endif // PROTOMAN_OFFLOAD_TLS
    }

    if (NULL == layer_mbedos_socket->socket) {
        protoman_err("failed to allocate socket");
        return -1;
    }

    layer_mbedos_socket->socket->set_blocking(false);

#ifdef PROTOMAN_USE_SOCKET_CALLBACK_BOUNCE
    protoman_debug("Callbacks will use shared event queue");
    layer_mbedos_socket->socket->sigio(callback(&_data_received_callback_bouncer, (void*)layer));
#else
    layer_mbedos_socket->socket->sigio(callback(&_data_received_callback, (void*)layer));
#endif

    /* Add to stack */
    protoman_add_layer(protoman, layer);
    return 0;
}

static void _async_dns_callback_bouncer(void *data, nsapi_error_t result, SocketAddress *address)
{
    // This is configured by ifdef to allow some network interfaces to continue working without bouncing
#ifdef PROTOMAN_USE_SOCKET_CALLBACK_BOUNCE
    struct protoman_layer_mbedos_socket_s *layer_mbedos_socket = (struct protoman_layer_mbedos_socket_s *)data;

    assert(layer_mbedos_socket);
    assert(layer_mbedos_socket->shared_event_queue);

    layer_mbedos_socket->shared_event_queue->call(_async_dns_callback, data, result, address);
#else
    _async_dns_callback(data, result, address);
#endif
}

static void _async_dns_callback(void *data, nsapi_error_t result, SocketAddress *address)
{
    struct protoman_layer_s *layer = (struct protoman_layer_s *) data;
    struct protoman_s *protoman = (struct protoman_s *)layer->protoman;
    struct protoman_layer_mbedos_socket_s *layer_mbedos_socket = (struct protoman_layer_mbedos_socket_s *)layer;

    if (NSAPI_ERROR_OK == result) {
        layer_mbedos_socket->address = *address;
    }

    layer_mbedos_socket->async_dns_query = result;

    protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);

}

static int _do_connect(struct protoman_layer_s *layer)
{
    struct protoman_s *protoman = (struct protoman_s *)layer->protoman;
    struct protoman_layer_mbedos_socket_s *layer_mbedos_socket = (struct protoman_layer_mbedos_socket_s *)layer;
    NetworkInterface& interface = *(NetworkInterface *)layer_mbedos_socket->config.interface;

#ifdef PROTOMAN_OFFLOAD_TLS
    TLSSocket& tsocket = *(TLSSocket*)layer_mbedos_socket->socket;
#else
    TCPSocket& tsocket = *(TCPSocket*)layer_mbedos_socket->socket;
#endif // PROTOMAN_OFFLOAD_TLS

    UDPSocket& usocket = *(UDPSocket*)layer_mbedos_socket->socket;

    int retval;
    nsapi_error_t result;

    protoman_verbose("");

    switch(layer_mbedos_socket->state) {
        case PROTOMAN_MBEDOS_OPENING:
            if (protoman->config.is_dgram) {
                retval = usocket.open(&interface);
            } else {
                retval = tsocket.open(&interface);

#ifdef PROTOMAN_OFFLOAD_TLS
                if (layer_mbedos_socket->config.bootstrap) {
                    if (!store_setting_to_modem(tsocket, BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE, NSAPI_TLSSOCKET_SET_CACERT, false)) {
                        return PROTOMAN_STATE_RETVAL_ERROR;
                    }
                } else {
                    if (!store_setting_to_modem(tsocket, LWM2M_SERVER_ROOT_CA_CERTIFICATE, NSAPI_TLSSOCKET_SET_CACERT, true)) {
                        return PROTOMAN_STATE_RETVAL_ERROR;
                    }
                }

                if (layer_mbedos_socket->config.bootstrap) {
                    if (!store_setting_to_modem(tsocket, BOOTSTRAP_DEVICE_CERTIFICATE, NSAPI_TLSSOCKET_SET_CLCERT, false)) {
                        return PROTOMAN_STATE_RETVAL_ERROR;
                    }
                } else {
                    if (!store_setting_to_modem(tsocket, LWM2M_DEVICE_CERTIFICATE, NSAPI_TLSSOCKET_SET_CLCERT, true)) {
                        return PROTOMAN_STATE_RETVAL_ERROR;
                    }
                }

                if (layer_mbedos_socket->config.bootstrap) {
                    if (!store_setting_to_modem(tsocket, BOOTSTRAP_DEVICE_PRIVATE_KEY, NSAPI_TLSSOCKET_SET_CLKEY, false)) {
                        return PROTOMAN_STATE_RETVAL_ERROR;
                    }
                } else {
                    if (!store_setting_to_modem(tsocket, LWM2M_DEVICE_PRIVATE_KEY, NSAPI_TLSSOCKET_SET_CLKEY, true)) {
                        return PROTOMAN_STATE_RETVAL_ERROR;
                    }
                }

                bool enabled = true;
                tsocket.setsockopt(NSAPI_TLSSOCKET_LEVEL, NSAPI_TLSSOCKET_ENABLE, &enabled, sizeof(enabled));
#endif // PROTOMAN_OFFLOAD_TLS
            }

            if (0 != retval) {
                protoman_err("socket.open() failed with %s (%d)", protoman_str_nsapi_error(retval), retval);
                protoman_layer_record_error(layer, PROTOMAN_ERR_NETWORK_ERROR, retval, protoman_str_nsapi_error(retval));
                return PROTOMAN_STATE_RETVAL_ERROR;
            }

            layer_mbedos_socket->state = PROTOMAN_MBEDOS_RESOLVING;
            assert(layer_mbedos_socket->async_dns_query == 0);

            retval = interface.gethostbyname_async(layer_mbedos_socket->config.socket.hostname,
                                                   mbed::Callback<void(nsapi_error_t, SocketAddress *)>(_async_dns_callback_bouncer, layer));

            if (0 > retval) {
                protoman_err("interface.gethostbyname_async() failed with %s (%d)", protoman_str_nsapi_error(retval), retval);
                protoman_layer_record_error(layer, PROTOMAN_ERR_DNS_RESOLVING_FAILED, retval, protoman_str_nsapi_error(retval));
                return PROTOMAN_STATE_RETVAL_ERROR;
            }

            protoman_verbose("interface.gethostbyname_async() started an asynchronous DNS query: %d", retval);
            layer_mbedos_socket->async_dns_query = retval;
            return PROTOMAN_STATE_RETVAL_WAIT;

        case PROTOMAN_MBEDOS_RESOLVING:

            result = layer_mbedos_socket->async_dns_query;

            if (result > 0) {
                return PROTOMAN_STATE_RETVAL_WAIT;
            } else if (NSAPI_ERROR_OK != result) {
                protoman_err("interface.gethostbyname_async() failed with %s (%d)", protoman_str_nsapi_error(result), result);
                protoman_layer_record_error(layer, PROTOMAN_ERR_DNS_RESOLVING_FAILED, result, protoman_str_nsapi_error(result));
                return PROTOMAN_STATE_RETVAL_ERROR;
            }

            protoman_info("destination \"%s\" resolved to \"%s\"",
                layer_mbedos_socket->config.socket.hostname,
                layer_mbedos_socket->address.get_ip_address());

            layer_mbedos_socket->address.set_port(layer_mbedos_socket->config.socket.port);

            if (protoman->config.is_dgram) {
                /* Everything completed for UDP */
                return PROTOMAN_STATE_RETVAL_FINISHED;
            }

            layer_mbedos_socket->state = PROTOMAN_MBEDOS_CONNECTING;
            /* continue to next step */

        case PROTOMAN_MBEDOS_CONNECTING:
            if (protoman->config.is_dgram) {
                retval = usocket.connect(layer_mbedos_socket->address);
            } else {
                retval = tsocket.connect(layer_mbedos_socket->address);
            }

            if (NSAPI_ERROR_NO_CONNECTION == retval) {
                protoman_warn("socket.connect() connection timeout");
                break;
            } else if (NSAPI_ERROR_IN_PROGRESS == retval || NSAPI_ERROR_ALREADY == retval) {
                /* wait for sigio event for connection -> run event -> try tsocket.conenct() again in here */
                return PROTOMAN_STATE_RETVAL_WAIT;
            } else if (0 != retval && NSAPI_ERROR_IS_CONNECTED != retval) {
                protoman_err("socket.connect() failed with %s (%d)", protoman_str_nsapi_error(retval), retval);
                protoman_layer_record_error(layer, PROTOMAN_ERR_NETWORK_ERROR, retval, protoman_str_nsapi_error(retval));
                return PROTOMAN_STATE_RETVAL_ERROR;
            }

            /* Everything completed */
            return PROTOMAN_STATE_RETVAL_FINISHED;
    }
    return PROTOMAN_STATE_RETVAL_AGAIN;
}

static int _do_disconnect(struct protoman_layer_s *layer)
{
    struct protoman_layer_mbedos_socket_s *layer_mbedos_socket = (struct protoman_layer_mbedos_socket_s *)layer;
    Socket& socket = *layer_mbedos_socket->socket;

    protoman_verbose("");
    socket.close(); /* NOTE: return value is ignored, next connection will fail if error happens here */

    if (layer_mbedos_socket->async_dns_query > 0) {
        NetworkInterface& interface = *(NetworkInterface *)layer_mbedos_socket->config.interface;
        interface.gethostbyname_async_cancel(layer_mbedos_socket->async_dns_query);
    }

    layer_mbedos_socket->state = PROTOMAN_MBEDOS_OPENING;
    return PROTOMAN_STATE_RETVAL_FINISHED;
}

static void layer_free(struct protoman_layer_s *layer)
{
    struct protoman_layer_mbedos_socket_s *layer_mbedos_socket = (struct protoman_layer_mbedos_socket_s *)layer;
    Socket& socket = *layer_mbedos_socket->socket;

    protoman_verbose("");

    /* Generic free */
    protoman_generic_layer_free(layer);

    /* Layer specific free */
    socket.close();

    if (layer_mbedos_socket->async_dns_query > 0) {
        NetworkInterface& interface = *(NetworkInterface *)layer_mbedos_socket->config.interface;
        interface.gethostbyname_async_cancel(layer_mbedos_socket->async_dns_query);
    }

}

static int _do_write(struct protoman_layer_s *layer)
{
    struct protoman_s *protoman = (struct protoman_s *)layer->protoman;
    struct protoman_layer_mbedos_socket_s *layer_mbedos_socket = (struct protoman_layer_mbedos_socket_s *)layer;

#ifdef PROTOMAN_OFFLOAD_TLS
    TLSSocket& tsocket = *(TLSSocket*)layer_mbedos_socket->socket;
#else
    TCPSocket& tsocket = *(TCPSocket*)layer_mbedos_socket->socket;
#endif

    UDPSocket& usocket = *(UDPSocket*)layer_mbedos_socket->socket;

    int retval;

    protoman_verbose("");

    if (NULL == layer->tx_buf) {
        protoman_verbose("layer->tx_buf is empty");
        return PROTOMAN_STATE_RETVAL_WAIT;
    }

    if (protoman->config.is_dgram) {
        retval = usocket.sendto(layer_mbedos_socket->address, layer->tx_buf, layer->tx_len);
    } else {
        retval = tsocket.send(layer->tx_buf + layer->tx_offset, layer->tx_len - layer->tx_offset);
    }

    if (NSAPI_ERROR_WOULD_BLOCK == retval) {
        protoman_verbose("WOULDBLOCK");
        return PROTOMAN_STATE_RETVAL_WAIT;
    }

    if (retval < 0) {
        protoman_err("socket.send(to)() failed with %s", protoman_str_nsapi_error(retval));
        protoman_layer_record_error(layer, PROTOMAN_ERR_NETWORK_ERROR, retval, protoman_str_nsapi_error(retval));
        return PROTOMAN_STATE_RETVAL_ERROR;
    }

    layer->tx_offset += (size_t)retval;

    /* Is all data sent? */
    if (layer->tx_offset == (size_t)layer->tx_len) {
        protoman_debug("wrote last %d bytes of %d", retval, (int)layer->tx_len);
        PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer->tx_buf);
        protoman_tx_free(protoman, layer->tx_buf);
        layer->tx_buf = NULL;
        protoman_event(protoman, layer, PROTOMAN_EVENT_DATA_WRITTEN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
    } else {
        /* Not all data was sent, wait for socket sigio to send rest. */
        protoman_verbose("wrote %d bytes of %d", retval, (int)layer->tx_len);

        /* Write until NSAPI_ERROR_WOULD_BLOCK */
        return PROTOMAN_STATE_RETVAL_AGAIN;
    }
    return PROTOMAN_STATE_RETVAL_WAIT;
}

static int _do_read(struct protoman_layer_s *layer)
{
    struct protoman_s *protoman = (struct protoman_s *)layer->protoman;
    struct protoman_layer_mbedos_socket_s *layer_mbedos_socket = (struct protoman_layer_mbedos_socket_s *)layer;

#ifdef PROTOMAN_OFFLOAD_TLS
    TLSSocket& tsocket = *(TLSSocket*)layer_mbedos_socket->socket;
#else
    TCPSocket& tsocket = *(TCPSocket*)layer_mbedos_socket->socket;
#endif

    UDPSocket& usocket = *(UDPSocket*)layer_mbedos_socket->socket;

    SocketAddress recv_addr;

    int retval;
    int state_retval = PROTOMAN_STATE_RETVAL_WAIT;

    protoman_verbose("");

    /* Own input buffer is not empty */
    if (NULL != layer->rx_buf) {
        protoman_verbose("layer->rx_buf is not empty");
        goto exit;
    }

    /* Allocate space for receiving data */
    layer->rx_buf = (uint8_t*)protoman_rx_alloc(protoman, protoman->config.mtu);
    if (NULL == layer->rx_buf) {
        protoman_err("layer->rx_buf malloc(%d) failed", (int)protoman->config.mtu);
        protoman_layer_record_error(layer, PROTOMAN_ERR_NOMEM, PROTOMAN_ERR_NOMEM, "PROTOMAN_ERR_NOMEM");
        state_retval = PROTOMAN_STATE_RETVAL_ERROR;
        goto exit;
    }

    if (protoman->config.is_dgram) {
        retval = usocket.recvfrom(&recv_addr, layer->rx_buf, protoman->config.mtu);
    } else {
        retval = tsocket.recv(layer->rx_buf, protoman->config.mtu);
    }

    /* EOF -> disconnect */
    if (0 == retval) {
        protoman_warn("EOF");
        if (PROTOMAN_STATE_DISCONNECTED == protoman->target_state) {
            state_retval = PROTOMAN_STATE_RETVAL_DISCONNECT;
            goto cleanup;
        }
        protoman_layer_record_error(layer, PROTOMAN_ERR_CONNECTION_CLOSED, retval, "EOF");
        state_retval = PROTOMAN_STATE_RETVAL_ERROR;
        goto cleanup;
    }

    /* Check for WOULDBLOCK */
    if (NSAPI_ERROR_WOULD_BLOCK == retval) {
        protoman_verbose("WOULDBLOCK");
        state_retval = PROTOMAN_STATE_RETVAL_WAIT;
        goto cleanup;
    }

    /* Check for errors */
    if (retval < 0) {
        protoman_err("socket.recv(from)() failed with %s (%d)", protoman_str_nsapi_error(retval), retval);
        protoman_layer_record_error(layer, PROTOMAN_ERR_NETWORK_ERROR, retval, protoman_str_nsapi_error(retval));
        state_retval = PROTOMAN_STATE_RETVAL_ERROR;
        goto cleanup;
    }

    if (protoman->config.is_dgram) {
        /* Check for correct source */
        if (layer_mbedos_socket->address != recv_addr) {
            protoman_debug("socket.recv(from)() wrong source address, %s is not %s, trashing packet",
                recv_addr.get_ip_address(), layer_mbedos_socket->address.get_ip_address());
            goto cleanup;
        } else {
            protoman_debug("socket.recv(from)() good source address, %s == %s",
                recv_addr.get_ip_address(), layer_mbedos_socket->address.get_ip_address());
        }
    }

    /* OK */
    layer->rx_len = (size_t) retval;
    layer->rx_offset = 0;
    protoman_debug("socket.recv(from)() read %d bytes", (int)layer->rx_len);
    protoman_event(protoman, layer, PROTOMAN_EVENT_DATA_AVAIL, PROTOMAN_EVENT_PRIORITY_LOW, 0);
    protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
    state_retval = PROTOMAN_STATE_RETVAL_AGAIN; /* read until WOULDBLOCK */
    goto exit;

cleanup:
    PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer->rx_buf);
    protoman_rx_free(protoman, layer->rx_buf);
    layer->rx_buf = NULL;
exit:
    return state_retval;
}

#ifdef PROTOMAN_OFFLOAD_TLS
bool store_setting_to_modem(TLSSocket &socket, cloud_client_param param,
                            int option,
                            bool convert_to_pem)
{
    uint8_t buffer[1024];
    size_t real_size = 0;
    uint8_t pem_buffer[1024];
    size_t pem_size = 0;
    size_t buffer_size = 1024;

    if (CCS_STATUS_SUCCESS != get_config_parameter(param, buffer, buffer_size, &real_size)) {
        tr_error("Failed to read key: %d", (int)param);
        return false;
    }

    if (convert_to_pem) {
        bool certificate = true;
        if (param == LWM2M_DEVICE_PRIVATE_KEY) {
            certificate = false;
        }

        if (convert_der_to_pem(certificate, buffer, real_size, (uint8_t*)&pem_buffer, &pem_size, buffer_size) != 0) {
            tr_error("PEM conversion failed!");
            return false;
        } else {
            memcpy(buffer, pem_buffer, pem_size);
            real_size = pem_size;
        }
    }

    if (socket.setsockopt(NSAPI_TLSSOCKET_LEVEL, option, buffer, real_size - 1) != 0) {
        tr_error("Failed to store setting to a modem, %d", (int)param);
        return false;
    }

    return true;
}
#endif // PROTOMAN_OFFLOAD_TLS
#endif // MBED_CONF_NSAPI_PRESENT
