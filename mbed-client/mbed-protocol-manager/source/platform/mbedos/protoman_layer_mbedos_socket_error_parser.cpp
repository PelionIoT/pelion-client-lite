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


#include "include/platform/mbedos/protoman_layer_mbedos_socket_error_parser.h"

const char* protoman_str_nsapi_error(int state)
{
#ifndef PROTOMAN_ERROR_STRING
    return "?";
#else
    switch (state) {
        case NSAPI_ERROR_OK:
            return "NSAPI_ERROR_OK";
        case NSAPI_ERROR_WOULD_BLOCK:
            return "NSAPI_ERROR_WOULD_BLOCK";
        case NSAPI_ERROR_UNSUPPORTED:
            return "NSAPI_ERROR_UNSUPPORTED";
        case NSAPI_ERROR_PARAMETER:
            return "NSAPI_ERROR_PARAMETER";
        case NSAPI_ERROR_NO_CONNECTION:
            return "NSAPI_ERROR_NO_CONNECTION";
        case NSAPI_ERROR_NO_SOCKET:
            return "NSAPI_ERROR_NO_SOCKET";
        case NSAPI_ERROR_NO_ADDRESS:
            return "NSAPI_ERROR_NO_ADDRESS";
        case NSAPI_ERROR_NO_MEMORY:
            return "NSAPI_ERROR_NO_MEMORY";
        case NSAPI_ERROR_NO_SSID:
            return "NSAPI_ERROR_NO_SSID";
        case NSAPI_ERROR_DNS_FAILURE:
            return "NSAPI_ERROR_DNS_FAILURE";
        case NSAPI_ERROR_DHCP_FAILURE:
            return "NSAPI_ERROR_DHCP_FAILURE";
        case NSAPI_ERROR_AUTH_FAILURE:
            return "NSAPI_ERROR_AUTH_FAILURE";
        case NSAPI_ERROR_DEVICE_ERROR:
            return "NSAPI_ERROR_DEVICE_ERROR";
        case NSAPI_ERROR_IN_PROGRESS:
            return "NSAPI_ERROR_IN_PROGRESS";
        case NSAPI_ERROR_ALREADY:
            return "NSAPI_ERROR_ALREADY";
        case NSAPI_ERROR_IS_CONNECTED:
            return "NSAPI_ERROR_IS_CONNECTED";
        case NSAPI_ERROR_CONNECTION_LOST:
            return "NSAPI_ERROR_CONNECTION_LOST";
        case NSAPI_ERROR_CONNECTION_TIMEOUT:
            return "NSAPI_ERROR_CONNECTION_TIMEOUT";
        default:
            return "unknown nsapi error";
    }
#endif // PROTOMAN_ERROR_STRING
}
#endif //MBED_CONF_NSAPI_PRESENT