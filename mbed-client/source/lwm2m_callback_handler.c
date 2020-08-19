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

#include <assert.h>

#include "lwm2m_callback_handler.h"
#include "lwm2m_heap.h"
#ifdef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
#include "lwm2m_endpoint.h"
#endif
#include "eventOS_event.h"
#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP "CbHa"

typedef struct callback_handler_s {
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    registry_t *registry;
#else
    endpoint_t *endpoint;
#endif
    int8_t event_handler_id;
} callback_handler_t;

static callback_handler_t callback_handler = {.event_handler_id = (-1)};

static void callback_free_data(callback_data_t *cb_data)
{
    lwm2m_free(cb_data->cb_opaque_data);
    lwm2m_free(cb_data);
}

static void callback_event_handler(arm_event_t *event)
{
    callback_data_t *cb_data = (callback_data_t *)event->data_ptr;
    registry_callback_t callback;

    const registry_callback_type_t event_type = (registry_callback_type_t)event->event_type;

    switch (event_type) {
        case REGISTRY_CALLBACK_EXECUTE:
        case REGISTRY_CALLBACK_VALUE_UPDATED:
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
            if (registry_get_callback(callback_handler.registry, &cb_data->path, &callback) == REGISTRY_STATUS_OK) {
                callback(event_type, &cb_data->path, &cb_data->cb_token, &cb_data->cb_value, NOTIFICATION_STATUS_IGNORE, callback_handler.registry);
            }
#else
            callback = endpoint_get_object_callback(callback_handler.endpoint, cb_data->path.object_id);
            if (callback) {
                callback(event_type, &cb_data->path, &cb_data->cb_token, &cb_data->cb_value, NOTIFICATION_STATUS_IGNORE, callback_handler.endpoint);
            }
#endif
            callback_free_data(cb_data);
            break;
        case CALLBACK_HANDLER_EVENT_INIT:
            // No need to do anything here.
            break;
        default:
            tr_error("callback_event_handler, unexpected type %d.", event->event_type);
            break;
    }
}

void callback_handler_send_event(void *data, uint8_t type)
{
    arm_event_t event;

    event.data_ptr = data;
    event.event_data = 0;
    event.event_id = CALLBACK_HANDLER_EVENT_ID;
    event.event_type = type;
    event.priority = ARM_LIB_LOW_PRIORITY_EVENT;
    event.receiver = callback_handler.event_handler_id;
    event.sender = 0;

    if (0 > eventOS_event_send(&event)) {
        callback_free_data(event.data_ptr);
        tr_error("eventOS_event_send failed.");
    }
}

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
void callback_handler_init(registry_t *registry)
#else
void callback_handler_init(endpoint_t *endpoint)
#endif
{
    tr_info("callback_handler_init");
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    callback_handler.registry = registry;
#else
    callback_handler.endpoint = endpoint;
#endif
    if(callback_handler.event_handler_id < 0) {
        callback_handler.event_handler_id = eventOS_event_handler_create(&callback_event_handler,
                                                                         CALLBACK_HANDLER_EVENT_INIT);
    }

    if (callback_handler.event_handler_id < 0) {
        tr_error("callback_handler_init, eventOS_event_handler_create failed!");
        assert(0);
    }
}
