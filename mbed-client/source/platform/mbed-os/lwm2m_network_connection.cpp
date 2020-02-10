/*
 * Copyright (c) 2018 - 2019 ARM Limited. All rights reserved.
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

#include "mbed.h"

#define TRACE_GROUP "NCon"

#if MBED_CONF_NSAPI_PRESENT

static connection_t *lwm2m_connection = NULL;

static void network_status_caller(bool up)
{
    if (lwm2m_connection) {
        connection_interface_status(lwm2m_connection, up);
    }
}

static void network_status_callback(nsapi_event_t event, intptr_t status)
{

    if (event != NSAPI_EVENT_CONNECTION_STATUS_CHANGE) {
        return;
    }

    switch(status) {
        case NSAPI_STATUS_GLOBAL_UP:
            tr_info("NSAPI_STATUS_GLOBAL_UP");
            if (lwm2m_connection) {
                mbed::mbed_event_queue()->call(&network_status_caller, true);
            }
            break;

        case NSAPI_STATUS_LOCAL_UP:
            tr_info("NSAPI_STATUS_LOCAL_UP");
            break;

        case NSAPI_STATUS_DISCONNECTED:
            tr_info("NSAPI_STATUS_DISCONNECTED");
            break;

        case NSAPI_STATUS_CONNECTING:
            tr_info("NSAPI_STATUS_CONNECTING");
            break;

        case NSAPI_STATUS_ERROR_UNSUPPORTED:
            tr_info("NSAPI_STATUS_ERROR_UNSUPPORTED");
            break;
    }

}

extern "C" void network_connection_init(connection_t *connection, void *interface)
{
    lwm2m_connection = connection;
    ((NetworkInterface*)interface)->attach(&network_status_callback);
}

extern "C" void network_connection_destroy(void)
{
    lwm2m_connection = NULL;
}

#else

extern "C" void network_connection_init(connection_t *connection, void *interface)
{
    (void)connection;
    (void)interface;
}

extern "C" void network_connection_destroy(void)
{
}

#endif // MBED_CONF_NSAPI_PRESENT
