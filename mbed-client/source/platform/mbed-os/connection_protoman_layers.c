/*
 * Copyright (c) 2019 ARM Limited. All rights reserved.
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

#if defined(TARGET_LIKE_MBED) && (!defined(USE_PLATFORM_CODE_OVERRIDE_PROTOMAN) || (USE_PLATFORM_CODE_OVERRIDE_PROTOMAN == 0))

#include <string.h>

#define TRACE_GROUP "ConP"


int8_t connection_protoman_layers_init(struct connection_s *connection, char *hostname, uint16_t port, void* interface
#ifdef PROTOMAN_OFFLOAD_TLS
                                       , bool bootstrap
#endif
                                       )
{

    struct protoman_config_mbedos_socket_s *socket_config;

    connection->protoman_layers.protoman_layer_mbedos_socket = protoman_layer_mbedos_socket_new();
    if (!connection->protoman_layers.protoman_layer_mbedos_socket ||
        0 != protoman_add_layer_mbedos_socket(&connection->protoman, connection->protoman_layers.protoman_layer_mbedos_socket)) {
        return CONNECTION_STATUS_ERROR_GENERIC;
    }
    socket_config = protoman_get_config(&connection->protoman, connection->protoman_layers.protoman_layer_mbedos_socket);
    socket_config->interface = interface;
    socket_config->socket.hostname = hostname;
    socket_config->socket.port = port;
#ifdef PROTOMAN_OFFLOAD_TLS
    socket_config->bootstrap = bootstrap;
#endif

    return CONNECTION_STATUS_OK;

}

#endif
