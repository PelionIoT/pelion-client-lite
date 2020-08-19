/*
 * Copyright (c) 2017-2020 ARM Limited. All rights reserved.
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

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY

#include "lwm2m_constants.h"
#include "lwm2m_endpoint.h"
#include "lwm2m_heap.h"
#include "lwm2m_notifier.h"
#include "lwm2m_registry.h"
#include "eventOS_event.h"
#include "eventOS_event_timer.h"
#include "lwm2m_registry_meta.h"
#include "tlvserializer.h"
#include "mbed-trace/mbed_trace.h"
#include "sn_coap_protocol_internal.h"

#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#define TRACE_GROUP "Ntfr"

#define NOTIFIER_EVENT_INIT 0
#define NOTIFIER_EVENT_ID 20
#define NOTIFIER_EVENT_TIMER 7

#define NOTIFIER_UINT24_MAX 0xFFFFFF

#ifndef NOTIFIER_DEFAULT_PMIN
#define NOTIFIER_DEFAULT_PMIN 0
#endif
#ifndef NOTIFIER_DEFAULT_PMAX
#define NOTIFIER_DEFAULT_PMAX NOTIFIER_TIME_INFINITE
#endif

#define NOTIFIER_MINIMUM_DELAY_MS 100

#if MBED_CLIENT_ENABLE_FLOAT_VALUE
#define NOTIFIER_OBSERVATION_VALUE_TYPE_INT 0
#define NOTIFIER_OBSERVATION_VALUE_TYPE_FLOAT 1
#endif

#define NOTIFTER_USE_INITIAL_DELAY true

#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
typedef struct notifier_observation_value_s {

    registry_observation_value_t value;
#if MBED_CLIENT_ENABLE_FLOAT_VALUE
    unsigned type:1;
#endif

} notifier_observation_value_t;
#else
typedef void notifier_observation_value_t;
#endif // MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS

static void notifier_value_changed(notifier_t *notifier);

static void notifier_timer_expired(notifier_t *notifier);

static void notifier_notify_next(notifier_t *notifier, const registry_path_t *path, bool *notified);

static uint32_t notifier_get_current_time(notifier_t *notifier);

static void notifier_schedule_notification(notifier_t *notifier, uint32_t current_time, uint32_t time_to_notification);

static void notifier_event_handler(arm_event_t *event)
{
    notifier_t *notifier = event->data_ptr;

    switch (event->event_id) {

    //Currently there should be no need to check the event type as we only expect one type of event from each event source.

        case REGISTRY_EVENT_ID:

            tr_debug("REGISTRY_EVENT_VALUE_CHANGED");
            notifier_value_changed(notifier);
            registry_event_processed(&notifier->endpoint->registry, event);
            break;

        case NOTIFIER_EVENT_ID:

            tr_debug("NOTIFIER_EVENT_TIMER");
            notifier_timer_expired(notifier);
            break;

    }

}

void notifier_init(notifier_t *notifier, endpoint_t *endpoint)
{
    tr_info("notifier_init");

    notifier->endpoint = endpoint;

    notifier->event_handler_id = -1;
    notifier->current_time = 0;
    notifier->next_event_time = 0;
    notifier->last_ticks = 0;

    notifier->notify_option_number = 0; //TODO: Check if this needs to be random?

    notifier->message_id = 0;

    notifier->running = true;
    notifier->notifying = false;
    notifier->notify_next = false;
}

bool notifier_setup(notifier_t *notifier)
{
    bool success = false;

    // XXX: this needs to be fixed to a singleton, as it will leak the tasklet
    notifier->event_handler_id = eventOS_event_handler_create(&notifier_event_handler, NOTIFIER_EVENT_INIT); //TODO: Check error codes?

    if (notifier->event_handler_id >= 0) {

        if (registry_listen_events(&notifier->endpoint->registry, notifier, REGISTRY_EVENT_LISTEN_VALUE_CHANGES, notifier->event_handler_id) == REGISTRY_STATUS_OK) {
            success = true;
        }
    }

    return success;
}

void notifier_stop(notifier_t *notifier)
{
    notifier->running = false;
    if (notifier->event_handler_id >= 0) {
        eventOS_event_timer_cancel(NOTIFIER_EVENT_ID, notifier->event_handler_id);
    }
    registry_listen_events_stop(&notifier->endpoint->registry, notifier, REGISTRY_EVENT_LISTEN_VALUE_CHANGES, notifier->event_handler_id);
}

void notifier_pause(notifier_t *notifier)
{
    notifier->running = false;
    eventOS_event_timer_cancel(NOTIFIER_EVENT_ID, notifier->event_handler_id);
}

void notifier_continue(notifier_t *notifier)
{
    registry_observation_parameters_t parameters;

    if(notifier->message_id &&
      REGISTRY_STATUS_OK == registry_get_observation_parameters(&notifier->endpoint->registry, &notifier->last_notified, &parameters)) {

        if (parameters.sent) {
            parameters.sent = false;
            registry_set_observation_parameters(&notifier->endpoint->registry, &notifier->last_notified, &parameters);
        }
    }

    notifier->running = true;
    notifier->notifying = false;
    notifier->next_event_time = 0;
    send_queue_request(notifier->endpoint, SEND_QUEUE_NOTIFIER);
}

static uint32_t notifier_get_notify_option_number(notifier_t *notifier)
{

    notifier->notify_option_number++;

    if (notifier->notify_option_number > NOTIFIER_UINT24_MAX) {
        notifier->notify_option_number = 0;
    }

    return notifier->notify_option_number;
}

static uint32_t notifier_time_to_pmax(notifier_t *notifier, registry_observation_parameters_t *parameters, uint32_t current_time)
{
#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
    uint32_t time_passed;

    time_passed = (current_time - parameters->time);

    if (parameters->available.pmax) {

        if (time_passed > parameters->pmax) {
            return 0;
        }

        if (parameters->pmax >= NOTIFIER_TIME_INFINITE) {
            return NOTIFIER_TIME_INFINITE;
        }

        return (parameters->pmax - time_passed);

    }

#if NOTIFIER_DEFAULT_PMAX == NOTIFIER_TIME_INFINITE
    return NOTIFIER_TIME_INFINITE;
#else
    if (time_passed > NOTIFIER_DEFAULT_PMAX) {
        return 0;
    }

    return (NOTIFIER_DEFAULT_PMAX - time_passed);
#endif // NOTIFIER_DEFAULT_PMAX == NOTIFIER_TIME_INFINITE

#else
    (void)notifier;
    (void)parameters;
    (void)current_time;
    return NOTIFIER_TIME_INFINITE;
#endif // MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS

}

static uint32_t notifier_time_to_pmin(notifier_t *notifier, registry_observation_parameters_t *parameters, uint32_t current_time)
{
#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
    uint32_t time_passed;

    time_passed = (current_time - parameters->time);

    if (parameters->available.pmin) {

        if (time_passed > parameters->pmin) {
            return 0;
        }

        if (parameters->pmin >= NOTIFIER_TIME_INFINITE) {
            return NOTIFIER_TIME_INFINITE;
        }

        return (parameters->pmin - time_passed);

    }

#if NOTIFIER_DEFAULT_PMIN == 0
    return 0;
#else
    if (time_passed >= NOTIFIER_DEFAULT_PMIN) {
        return 0;
    }

    return (NOTIFIER_DEFAULT_PMIN - time_passed);
#endif // NOTIFIER_DEFAULT_PMIN == 0

#else
    (void)notifier;
    (void)parameters;
    (void)current_time;
    return 0;
#endif // MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
}

static uint8_t notifier_check_lt_gt_st(registry_observation_parameters_t *parameters, notifier_observation_value_t *value)
{

#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS

    if ((!parameters->available.gt && !parameters->available.lt && !parameters->available.st) || !parameters->available.previous_value) {
        return 1;
    }

    if (!value) {
        return 1;
    }
#if MBED_CLIENT_ENABLE_FLOAT_VALUE
    if (value->type == NOTIFIER_OBSERVATION_VALUE_TYPE_INT) {
#endif

        //Report if crossing threshold
        if ((parameters->available.gt && parameters->available.previous_value) &&
                ((parameters->previous_value.int_value > parameters->gt && value->value.int_value <= parameters->gt) ||
                (parameters->previous_value.int_value <= parameters->gt && value->value.int_value > parameters->gt))) {
            return 1;
        }

        if ((parameters->available.lt && parameters->available.previous_value) &&
                ((parameters->previous_value.int_value < parameters->lt && value->value.int_value >= parameters->lt) ||
                (parameters->previous_value.int_value >= parameters->lt && value->value.int_value < parameters->lt))) {
            return 1;
        }

        if (parameters->available.st && parameters->available.previous_value && llabs(parameters->previous_value.int_value - value->value.int_value) >= parameters->st) {
            return 1;
        }
#if MBED_CLIENT_ENABLE_FLOAT_VALUE
    } else {

        //Report if crossing threshold
        if ((parameters->available.gt && parameters->available.previous_value) &&
                ((parameters->previous_value.float_value > parameters->gt && value->value.float_value <= parameters->gt) ||
                (parameters->previous_value.float_value <= parameters->gt && value->value.float_value > parameters->gt))) {
            return 1;
        }

        if ((parameters->available.lt && parameters->available.previous_value) &&
                ((parameters->previous_value.float_value < parameters->lt && value->value.float_value >= parameters->lt) ||
                (parameters->previous_value.float_value >= parameters->lt && value->value.float_value < parameters->lt))) {
            return 1;
        }

        if (parameters->available.st && parameters->available.previous_value && fabsf((parameters->previous_value.float_value - value->value.float_value)) >= parameters->st) {
            return 1;
        }

    }
#endif

    return 0;

#else
    (void)parameters;
    (void)value;
    return 1;
#endif //MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS

}

#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
static notifier_observation_value_t *notifier_read_value(notifier_t *notifier, const registry_path_t *path, notifier_observation_value_t *value, registry_object_value_t *object_value)
{

    const lwm2m_resource_meta_definition_t *static_data;

    if (path->path_type < REGISTRY_PATH_RESOURCE) {
        return NULL;
    }

    if (REGISTRY_STATUS_OK != registry_meta_get_resource_definition(path->object_id, path->resource_id, &static_data)) {
        return NULL;
    }

    notifier_observation_value_t* result = NULL;

    switch (static_data->type) {

        case LWM2M_RESOURCE_TYPE_INTEGER:

#if MBED_CLIENT_ENABLE_FLOAT_VALUE
            value->type = NOTIFIER_OBSERVATION_VALUE_TYPE_INT;
#endif

            if (object_value) {
                value->value.int_value = object_value->int_value;
                result = value;
            } else if (REGISTRY_STATUS_OK == registry_get_value_int(&notifier->endpoint->registry, path, &value->value.int_value)) {
                result = value;
            }
            break;

#if MBED_CLIENT_ENABLE_FLOAT_VALUE
        case LWM2M_RESOURCE_TYPE_FLOAT:

            value->type = NOTIFIER_OBSERVATION_VALUE_TYPE_FLOAT;

            if (object_value) {
                value->value.float_value = object_value->float_value;
                result = value;
            } else if (REGISTRY_STATUS_OK == registry_get_value_float(&notifier->endpoint->registry, path, &value->value.float_value)) {
                result = value;
            }
            break;
#endif

        case LWM2M_RESOURCE_TYPE_TIME:

#if MBED_CLIENT_ENABLE_FLOAT_VALUE
            value->type = NOTIFIER_OBSERVATION_VALUE_TYPE_INT;
#endif

            if (object_value) {
                value->value.int_value = object_value->int_value;
                result = value;
            } else if (REGISTRY_STATUS_OK == registry_get_value_time(&notifier->endpoint->registry, path, &value->value.int_value)) {
                result = value;
            }
            break;

        default:
            result = NULL;
    }

    return result;
}
#endif //MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS

static uint32_t notifier_get_current_time(notifier_t *notifier)
{
#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
    uint32_t ticks;
    uint32_t ticks_since;

    ticks = eventOS_event_timer_ticks();

    ticks_since = ticks - notifier->last_ticks;

    if (!notifier->current_time) {
        notifier->last_ticks = ticks;
        notifier->current_time = 1;
    } else if (eventOS_event_timer_ticks_to_ms(ticks_since) / 1000) {
        notifier->last_ticks = ticks - eventOS_event_timer_ms_to_ticks(eventOS_event_timer_ticks_to_ms(ticks_since) % 1000);
        notifier->current_time += eventOS_event_timer_ticks_to_ms(ticks_since) / 1000;
    }

    return notifier->current_time;
#else
    (void)notifier;
    return 1;
#endif
}

static void notifier_schedule_notification(notifier_t *notifier, uint32_t current_time, uint32_t time_to_notification)
{
    uint32_t time_ms;
    uint32_t notification_time = current_time + time_to_notification;
    const arm_event_t event = {notifier->event_handler_id, notifier->event_handler_id, NOTIFIER_EVENT_TIMER,
                               NOTIFIER_EVENT_ID, notifier, ARM_LIB_LOW_PRIORITY_EVENT, 0};

    if (NOTIFIER_TIME_INFINITE == time_to_notification || notifier->notifying) {
        return;
    }

    if (notifier->next_event_time == 0 || notifier->next_event_time > notification_time) {

        notifier->next_event_time = notification_time;

        tr_debug("current_time %" PRIu32, current_time);

        if (time_to_notification)
        {
            time_ms = time_to_notification * 1000;
        } else {
            time_ms = NOTIFIER_MINIMUM_DELAY_MS;
        }

        tr_debug("Scheduling notification in: %" PRIu32 " ms", time_ms);

        eventOS_event_timer_cancel(NOTIFIER_EVENT_ID, notifier->event_handler_id);
        if (!eventOS_event_timer_request_in(&event, eventOS_event_timer_ms_to_ticks(time_ms))) {
            tr_error("schedule_notification timer_request failed");
            assert(0);
        }
    }

}

static uint8_t notifier_set_parameters(notifier_t *notifier, registry_observation_parameters_t *parameters, const registry_path_t *path,
                                       const uint32_t current_time, const registry_observation_value_t *value, const uint8_t *token,
                                       const uint8_t token_len, const bool observe, const int sent, const sn_coap_content_format_e *content_type)
{
    *parameters = (registry_observation_parameters_t){0};
    if(REGISTRY_STATUS_OK != registry_get_observation_parameters(&notifier->endpoint->registry, path, parameters)) {
    }

    if (sent >= 0) {
        parameters->sent = sent;
    }

#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
    parameters->available.time = true;
    parameters->time = current_time;

    if (value) {
        parameters->available.previous_value = true;
        parameters->previous_value = *value;
    }
#endif

    if (content_type) {
        parameters->available.content_type = 1;
        parameters->content_type = *content_type;
    }


    if (token && token_len) {
        parameters->token_size = token_len;
        memcpy(parameters->token, token, parameters->token_size);
    }

    if (observe) {
        parameters->observed = 1;
    }

    if (REGISTRY_STATUS_OK == registry_set_observation_parameters(&notifier->endpoint->registry, path, parameters)) {
        return 1;
    }

    return 0;

}

static void notifier_callback(notifier_t *notifier, const registry_path_t *path, registry_notification_status_t status)
{

    registry_callback_t callback;

    if (registry_get_callback(&notifier->endpoint->registry, path, &callback) == REGISTRY_STATUS_OK) {
        callback(REGISTRY_CALLBACK_NOTIFICATION_STATUS, path, NULL, NULL, status, &notifier->endpoint->registry);
    }

}

static bool notifier_send_observation_notification(endpoint_t *endpoint, const registry_path_t *path, uint8_t *token_ptr, uint8_t token_len,
                                                      uint8_t *payload_ptr, uint16_t payload_len, sn_coap_content_format_e content_format)
{
    sn_coap_hdr_s   *notification_message_ptr;
    bool success = false;

    /* Check parameters */
    if (endpoint == NULL || endpoint->coap == NULL || endpoint->connection == NULL) {
        tr_error("notifier_send_observation_notification invalid parameters.");
        notifier_callback(&endpoint->notifier, path, NOTIFICATION_STATUS_BUILD_ERROR);
        return false;
    }

    /* Allocate and initialize memory for header struct */
    notification_message_ptr = sn_coap_parser_alloc_message(endpoint->coap);
    if (notification_message_ptr == NULL) {
        tr_error("notifier_send_observation_notification alloc_message failed.");
        notifier_callback(&endpoint->notifier, path, NOTIFICATION_STATUS_BUILD_ERROR);
        return false;
    }

    if (sn_coap_parser_alloc_options(endpoint->coap, notification_message_ptr) == NULL) {
        tr_error("notifier_send_observation_notification alloc_options failed.");
        lwm2m_free(notification_message_ptr);
        notifier_callback(&endpoint->notifier, path, NOTIFICATION_STATUS_BUILD_ERROR);
        return false;
    }

    /* Read max age from registry */
    if (registry_get_max_age(&endpoint->registry, path, &notification_message_ptr->options_list_ptr->max_age) != REGISTRY_STATUS_OK) {
        tr_error("notifier_send_observation_notification() could not read max_age from registry!");
        sn_coap_parser_release_allocated_coap_msg_mem(endpoint->coap, notification_message_ptr);
        notifier_callback(&endpoint->notifier, path, NOTIFICATION_STATUS_BUILD_ERROR);
        return false;
    }

    /* Fill header */
    notification_message_ptr->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    notification_message_ptr->msg_code = COAP_MSG_CODE_RESPONSE_CONTENT;

    /* Fill token */
    notification_message_ptr->token_len = token_len;
    notification_message_ptr->token_ptr = token_ptr;

    /* Fill payload */
    notification_message_ptr->payload_len = payload_len;
    notification_message_ptr->payload_ptr = payload_ptr;

    /* Fill observe */
    notification_message_ptr->options_list_ptr->observe = notifier_get_notify_option_number(&endpoint->notifier);

    /* Fill content format */
    notification_message_ptr->content_format = content_format;

    /* Send message */
    int ret_val = endpoint_send_coap_message(endpoint, NULL, notification_message_ptr);

    if (ENDPOINT_STATUS_OK == ret_val) {

        success = true;

        endpoint->notifier.message_id = notification_message_ptr->msg_id;

        if (payload_len > endpoint->coap->sn_coap_block_data_size) {
            endpoint->notifier.block_notify = true;
        } else {
            endpoint->notifier.block_notify = false;
        }

        notifier_callback(&endpoint->notifier, path, NOTIFICATION_STATUS_SENT);
    } else if (ENDPOINT_STATUS_ERROR_MEMORY_FAILED == ret_val) {
        // Failed to allocate memory for building CoAP message.
        notifier_callback(&endpoint->notifier, path, NOTIFICATION_STATUS_BUILD_ERROR);
    } else {
        // Other transmission errors like Queue full.
        notifier_callback(&endpoint->notifier, path, NOTIFICATION_STATUS_RESEND_QUEUE_FULL);

    }

    /* Clear pointers we do not want to free. */
    notification_message_ptr->payload_ptr = NULL;
    notification_message_ptr->token_ptr = NULL;

    /* Free memory */
    sn_coap_parser_release_allocated_coap_msg_mem(endpoint->coap, notification_message_ptr);

    return success;
}

static bool notifier_send_notification(notifier_t *notifier, const registry_path_t *path, registry_observation_parameters_t *parameters, uint32_t current_time, registry_observation_value_t *value, bool dirty_only)
{
    uint8_t *data;
    uint32_t len;
    bool success = false;
    registry_observation_parameters_t parameters_set;
    sn_coap_content_format_e content_type = (sn_coap_content_format_e)COAP_CONTENT_OMA_TLV_TYPE;
    bool multiple = true;
    registry_serialization_format_t serialization_format;
    registry_tlv_serialize_status_t serializer_status;
    const lwm2m_resource_meta_definition_t* meta_data = NULL;

    tr_info("notifier_send_notification()");

    if(path->path_type == REGISTRY_PATH_RESOURCE) {

        if (REGISTRY_STATUS_OK != registry_meta_get_resource_definition(path->object_id, path->resource_id, &meta_data)) {
            assert(0);
            return false;
        }

    }
    if (path->path_type == REGISTRY_PATH_RESOURCE_INSTANCE || (path->path_type == REGISTRY_PATH_RESOURCE && !meta_data->multiple)) {
            multiple = false;
    }

#if MBED_CLIENT_ENABLE_SERIALIZE_PLAINTEXT
    if (parameters->available.content_type) {
        content_type = parameters->content_type;
    } else if (!multiple) {
        content_type = COAP_CT_TEXT_PLAIN;
    }
#endif

    if (content_type == COAP_CONTENT_OMA_OPAQUE_TYPE) {
        serialization_format = REGISTRY_SERIALIZE_OPAQUE;
    } else {
#if MBED_CLIENT_ENABLE_SERIALIZE_PLAINTEXT
        if (content_type == COAP_CONTENT_OMA_TLV_TYPE_OLD ||
                content_type == COAP_CONTENT_OMA_TLV_TYPE) {
            serialization_format = REGISTRY_SERIALIZE_TLV;
        } else {
            serialization_format = REGISTRY_SERIALIZE_PLAINTEXT;
        }
#else
        serialization_format = REGISTRY_SERIALIZE_TLV;
#endif // MBED_CLIENT_ENABLE_SERIALIZE_PLAINTEXT
    }

    data = registry_serialize(&notifier->endpoint->registry, path, &len, serialization_format, (multiple && dirty_only), &serializer_status);


    success = notifier_send_observation_notification(notifier->endpoint,
                                                    path,
                                                    parameters->token,
                                                    parameters->token_size,
                                                    data,
                                                    len,
                                                    content_type);
#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
    notifier_set_parameters(notifier, &parameters_set, path, parameters->time, value, NULL, 0, false, 1, NULL);
#else
    notifier_set_parameters(notifier, &parameters_set, path, 0, value, NULL, 0, false, 1, NULL);
#endif

    lwm2m_free(data);

    if (success) {

        notifier->last_notified = *path;
        notifier->notifying = true;

        eventOS_event_timer_cancel(NOTIFIER_EVENT_ID, notifier->event_handler_id);
        notifier->next_event_time = 0;

    } else {
        send_queue_sent(notifier->endpoint, true);
    }

    return success;

}

static void notifier_clear_dirty_children(notifier_t *notifier, const registry_path_t *path)
{

    registry_listing_t listing;
    registry_observation_parameters_t parameters;
    int previous_level = path->path_type;
    bool clear_children = true;

    listing.path = *path;
    listing.set_registered = 0;
    listing.listing_type = REGISTRY_LISTING_RECURSIVE;

    // Recursively loop resources under path and clear dirty if value has been sent.

    while (REGISTRY_STATUS_OK == registry_get_objects(&notifier->endpoint->registry, &listing, NULL, &parameters)) {

        if (!listing.parameters_set) {
            continue;
        }

        if (listing.path.path_type > previous_level && !clear_children) {
            continue;
        }

        previous_level = listing.path.path_type;

        if (parameters.observed && parameters.dirty && !parameters.sent) {

            clear_children = false;

        } else if (parameters.dirty) {

            parameters.dirty = false;
            parameters.sent = false;
            print_registry_path("notifier_clear_dirty_children() clear:", &listing.path);
            registry_set_observation_parameters(&notifier->endpoint->registry, &listing.path, &parameters);

        }

    }

}

static void notifier_clear_dirty(notifier_t *notifier, const registry_path_t *path)
{

    registry_observation_parameters_t parameters;
    registry_path_t current_path = *path;

    // Read parameters starting from object level.
    // Clear level if it has been sent, stop cleaning from first level not sent to make sure every level is sent.

    current_path.path_type = REGISTRY_PATH_OBJECT;

    do {

        if (REGISTRY_STATUS_OK == registry_get_observation_parameters(&notifier->endpoint->registry, &current_path, &parameters)) {

            if (parameters.observed && parameters.dirty && !parameters.sent) {

                return;

            } else if (parameters.dirty) {

                parameters.dirty = false;
                parameters.sent = false;
                print_registry_path("notifier_clear_dirty() clear:", &current_path);
                registry_set_observation_parameters(&notifier->endpoint->registry, &current_path, &parameters);

            }

        }

    } while (current_path.path_type++ != path->path_type);


    notifier_clear_dirty_children(notifier, path);

}

void notifier_notification_sent(notifier_t *notifier, bool success, const registry_path_t *path)
{

    registry_observation_parameters_t parameters;

    notifier->notifying = false;
    notifier->message_id = 0;
    notifier->block_notify = false;

    if (success) {

        // Set time, path.
        notifier_set_parameters(notifier, &parameters, path, notifier_get_current_time(notifier), NULL, NULL, 0, false, (-1), NULL);
        notifier_clear_dirty(notifier, path);
        notifier->notify_next = true;

    } else if (REGISTRY_STATUS_OK == registry_get_observation_parameters(&notifier->endpoint->registry, path, &parameters)) {

        if (parameters.sent) {
            parameters.sent = false;
            registry_set_observation_parameters(&notifier->endpoint->registry, path, &parameters);
        }

    }

    send_queue_sent(notifier->endpoint, true);
    send_queue_request(notifier->endpoint, SEND_QUEUE_NOTIFIER);

}

static void notifier_notify(notifier_t *notifier, const registry_path_t *path, registry_observation_parameters_t *parameters, notifier_observation_value_t *value, bool *notified)
{
    uint32_t current_time;
    uint32_t time_to_pmin;
    uint32_t time_to_pmax;
    uint8_t notification_required = 0;
    registry_observation_value_t *observation_value = NULL;

    if (!parameters->observed
#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
            || !parameters->available.time
#endif
            ) {
        return;
    }

#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
    if (value) {
        observation_value = &value->value;
    }
#endif

    current_time = notifier_get_current_time(notifier);

    time_to_pmax = notifier_time_to_pmax(notifier, parameters, current_time);

    if (!time_to_pmax) {
        if (!*notified) {
            tr_debug("notifier_notify() !time_to_pmax");
            *notified = notifier_send_notification(notifier, path, parameters, current_time, observation_value, false);
        } else {
            notifier_schedule_notification(notifier, current_time, time_to_pmax);
        }

        return;

    }

    if (parameters->dirty) {
        notification_required = notifier_check_lt_gt_st(parameters, value);
    }

    if (notification_required) {

        time_to_pmin = notifier_time_to_pmin(notifier, parameters, current_time);

        if (!time_to_pmin && !*notified) {
            tr_debug("notifier_notify() !time_to_pmin");
            *notified = notifier_send_notification(notifier, path, parameters, current_time, observation_value, true);
        } else {
            notifier_schedule_notification(notifier, current_time, time_to_pmin);
        }

        return;

    }

    notifier_schedule_notification(notifier, current_time, time_to_pmax);


}

static uint8_t notifier_get_observation_parameters(notifier_t *notifier, registry_path_t *path, registry_observation_parameters_t *parameters)
{
#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
    registry_path_t current_path = *path;
    uint8_t parameters_found = 0;
    registry_available_parameters_t parameters_available = {false};

    // Read parameters starting from object level.
    // Upper level parameters are overwritten if lower level parameters are found.

    current_path.path_type = REGISTRY_PATH_OBJECT;

    do {

        if (REGISTRY_STATUS_OK == registry_get_observation_parameters(&notifier->endpoint->registry, &current_path, parameters)) {
            parameters_found = 1;
            parameters->available.gt |= parameters_available.gt;
            parameters->available.lt |= parameters_available.lt;
            parameters->available.st |= parameters_available.st;
            parameters->available.pmin |= parameters_available.pmin;
            parameters->available.pmax |= parameters_available.pmax;
            parameters->available.previous_value |= parameters_available.previous_value;
            parameters_available = parameters->available;
        }

    } while (current_path.path_type++ != path->path_type);

    return parameters_found;
#else
    return (REGISTRY_STATUS_OK == registry_get_observation_parameters(&notifier->endpoint->registry, path, parameters));
#endif

}

static void notifier_init_parameters(notifier_t *notifier, const registry_path_t *path)
{

    registry_listing_t listing;
    registry_observation_parameters_t parameters;

    listing.path = *path;
    listing.set_registered = 0;
    listing.listing_type = REGISTRY_LISTING_RECURSIVE;

    // Recursively loop resources and initialize observation parameters if they have not been initialized before.

    while (REGISTRY_STATUS_OK == registry_get_objects(&notifier->endpoint->registry, &listing, NULL, &parameters)) {

        if (!listing.parameters_set) {

            parameters = (registry_observation_parameters_t){0};
            registry_set_observation_parameters(&notifier->endpoint->registry, &listing.path, &parameters);

        }

    }

}

int32_t notifier_start_observation(notifier_t *notifier, const registry_path_t *path, const uint8_t *token, const uint8_t token_len, const sn_coap_content_format_e content_type)
{

#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
    notifier_observation_value_t object_value;
#endif
    registry_observation_value_t *value = NULL;
    const sn_coap_content_format_e *type = NULL;
    registry_observation_parameters_t parameters;
    int32_t current_time;
    uint32_t pmax;

    if (!path) {
        return (-1);
    }

    if (content_type != COAP_CT_NONE) {
        type = &content_type;
    }

    current_time = notifier_get_current_time(notifier);

#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
    if (notifier_read_value(notifier, path, &object_value, NULL)) {
        value = &object_value.value;
    }
#endif

    if (!notifier_set_parameters(notifier, &parameters, path, current_time, value, token, token_len, true, false, type)) {
        return (-1);
    }

    notifier_init_parameters(notifier, path);

    pmax = notifier_time_to_pmax(notifier, &parameters, current_time);

    notifier_schedule_notification(notifier, current_time, pmax);

    return notifier_get_notify_option_number(notifier);

}

void notifier_stop_observation(notifier_t *notifier, const registry_path_t *path)
{
    registry_callback_t callback;
    registry_observation_parameters_t parameters;
    bool notification_sent = false;

    if (!path) {
        return;
    }

    if (REGISTRY_STATUS_OK != registry_get_observation_parameters(&notifier->endpoint->registry, path, &parameters)) {
        return;
    }

    if (!parameters.observed) {
        return;
    }

    if (notifier->message_id && registry_compare_path(path, &notifier->last_notified)) {
        notification_sent = true;
        notifier->message_id = 0;
        notifier->block_notify = false;
    }

#if MBED_CLIENT_ENABLE_AUTO_OBSERVATION
    if (!registry_is_auto_observable(&notifier->endpoint->registry, &notifier->last_notified)) {
#endif

        print_registry_path("notifier_stop_observation() ", path);

        parameters.observed = 0;
        parameters.token_size = 0;

        registry_set_observation_parameters(&notifier->endpoint->registry, path, &parameters);

        if (registry_get_callback(&notifier->endpoint->registry, path, &callback) == REGISTRY_STATUS_OK) {
            callback(REGISTRY_CALLBACK_NOTIFICATION_STATUS, path, NULL, NULL, NOTIFICATION_STATUS_UNSUBSCRIBED, &notifier->endpoint->registry);
        }

#if MBED_CLIENT_ENABLE_AUTO_OBSERVATION
    } else {
        tr_warn("notifier_stop_observation() Auto-observation may not be stopped.");
    }
#endif

    if (notification_sent) {
        notifier->notifying = false;
        notifier->notify_next = true;
        send_queue_request(notifier->endpoint, SEND_QUEUE_NOTIFIER);
        send_queue_sent(notifier->endpoint, true);
    }

}

static void notifier_notify_resource(notifier_t *notifier, const registry_path_t *path, registry_object_value_t *resource_value, bool *notified)
{

    registry_path_t current_path = *path;
    registry_observation_parameters_t resource_parameters;
    registry_observation_parameters_t parameters;
#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
    notifier_observation_value_t value;
#endif
    notifier_observation_value_t *value_read;

    // Read GT, LT, ST, PMIN and PMAX parameters for the resource.
    if (!notifier_get_observation_parameters(notifier, &current_path, &resource_parameters)) {
        return;
    }

#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
    value_read = notifier_read_value(notifier, path, &value, resource_value);
#else
    value_read = NULL;
#endif

    // Try to notify the resource at all levels starting form object level.

    current_path.path_type = REGISTRY_PATH_OBJECT;

    do {

        if (REGISTRY_STATUS_OK != registry_get_observation_parameters(&notifier->endpoint->registry, &current_path, &parameters)) {
            continue;
        }

        if (!parameters.observed) {
            continue;
        }

        // Set the level depend parameters.
        resource_parameters.dirty = (!parameters.sent && parameters.dirty);
#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
        resource_parameters.available.time = parameters.available.time;
        resource_parameters.time = parameters.time;
#endif
        resource_parameters.observed = parameters.observed;
        memcpy(resource_parameters.token, parameters.token, sizeof(resource_parameters.token));
        resource_parameters.token_size = parameters.token_size;

        notifier_notify(notifier, &current_path, &resource_parameters, value_read, notified);

    } while (current_path.path_type++ != path->path_type);


}

void notifier_set_dirty(registry_t *registry, const registry_path_t *path)
{

    registry_path_t current_path = *path;
    registry_observation_parameters_t parameters;
    bool observed = false;
    const lwm2m_resource_meta_definition_t* resdef;
    if (REGISTRY_STATUS_OK != registry_meta_get_resource_definition(path->object_id, path->resource_id, &resdef)) {
        return;
    }

    current_path.path_type = REGISTRY_PATH_OBJECT;

    //Set dirty the resource and also all the parent levels that are observed.

    do {

        if (REGISTRY_STATUS_OK != registry_get_observation_parameters(registry, &current_path, &parameters)) {

            if (current_path.path_type == path->path_type && observed) {
                // This is a new resource, initialize parameters.
                parameters = (registry_observation_parameters_t){0};
            } else {
                continue;
            }
        }

        if (!observed && !(observed = parameters.observed)) {
            // Skip levels that are not observed.
            // If the parent level is observed, child levels are also under observation and set dirty.
            continue;
        }

        if (parameters.dirty && !parameters.sent) {
            // Already set.
            continue;
        }

        parameters.dirty = true;
        parameters.sent = false;

        // The content-type needs to be set explicitly only for OPAQUE.
        if (resdef->type == LWM2M_RESOURCE_TYPE_OPAQUE) {
            parameters.available.content_type = 1;
            parameters.content_type = COAP_CONTENT_OMA_OPAQUE_TYPE;
        }

        registry_set_observation_parameters(registry, &current_path, &parameters);

    } while (current_path.path_type++ != path->path_type);

}

static void notifier_check_all_resources(notifier_t *notifier, bool *notified)
{
    registry_listing_t listing;
    registry_object_value_t value;
    registry_observation_parameters_t parameters;
    unsigned previoust_path_type = REGISTRY_PATH_OBJECT;
    bool init_parameters = false;
    bool check_notified = !*notified;

    if (!notifier->running) {
        return;
    }

    listing.listing_type = REGISTRY_LISTING_ALL;
    listing.set_registered = 0;

    // While notification has not been sent, loop all resources.

    while (REGISTRY_STATUS_OK == registry_get_objects(&notifier->endpoint->registry, &listing, &value, NULL) && (!check_notified || !*notified)) {

        // Check if there is need to initialize parameters for any resources that has been just created.
        if (previoust_path_type >= listing.path.path_type) {
            init_parameters = false;
        } else if (init_parameters && !listing.parameters_set) {
            parameters = (registry_observation_parameters_t){0};
            registry_set_observation_parameters(&notifier->endpoint->registry, &listing.path, &parameters);
        }
        if (listing.parameters_set && parameters.observed) {
            init_parameters = true;
        }

        previoust_path_type = listing.path.path_type;

        if (listing.value_set) {

            // Resources has a value, try to notify it.
            notifier_notify_resource(notifier, &listing.path, &value, notified);

        }

    }

}

static void notifier_value_changed(notifier_t *notifier)
{
    bool notified = NOTIFTER_USE_INITIAL_DELAY;

    notifier_check_all_resources(notifier, &notified);

}

static void notifier_timer_expired(notifier_t *notifier)
{
    notifier->next_event_time = 0;
    notifier->notify_next = false;
    send_queue_request(notifier->endpoint, SEND_QUEUE_NOTIFIER);
}

static void notifier_notify_next(notifier_t *notifier, const registry_path_t *path, bool *notified)
{
    registry_listing_t listing;
    registry_object_value_t value;
    bool skip = true;
    int round = 1;

    // Loop resources starting from resource last notified.
    // On first round loop resources that are found after resource last notified.
    // On second round loop resources from start to resource last notified.

    do {

        listing.listing_type = REGISTRY_LISTING_ALL;
        listing.set_registered = 0;

        while (REGISTRY_STATUS_OK == registry_get_objects(&notifier->endpoint->registry, &listing, &value, NULL) && !*notified) {

            // Skip resources until the resource that was notified last time is found.
            if (skip) {

                skip = !registry_compare_path(&listing.path, path);

            } else if (listing.value_set) {

                notifier_notify_resource(notifier, &listing.path, &value, notified);

            }

            if (round == 2 && registry_compare_path(&listing.path, path)) {
                // All resources looped.
                return;
            }

        }

        // If no resources notified on first round, make a second round to loop remaining resources.
        skip = false;

    } while (!*notified && round++ == 1);

}

void notifier_send_now(notifier_t *notifier)
{
    bool notified = false;
    if (notifier->notify_next) {
        notifier_notify_next(notifier, &notifier->last_notified, &notified);
    } else {
        notifier_check_all_resources(notifier, &notified);
    }

    if (!notified) {
        send_queue_sent(notifier->endpoint, true);
    }

}

void notifier_parameters_changed(notifier_t *notifier, const registry_path_t *path)
{
    bool notified = NOTIFTER_USE_INITIAL_DELAY;
    if (notifier->running) {
        notifier_notify_resource(notifier, path, NULL, &notified);
    }
}

void notifier_clear_notifications(notifier_t *notifier)
{
    registry_listing_t listing;
    registry_observation_parameters_t parameters;

    listing.set_registered = 0;
    listing.listing_type = REGISTRY_LISTING_ALL;

    // Loop all resources and remove observation if set.

    while (REGISTRY_STATUS_OK == registry_get_objects(&notifier->endpoint->registry, &listing, NULL, &parameters)) {

        if (listing.parameters_set && parameters.observed
#if MBED_CLIENT_ENABLE_AUTO_OBSERVATION
            && !registry_is_auto_observable(&notifier->endpoint->registry, &listing.path)
#endif
            ) {

            parameters.observed = false;
            parameters.token_size = 0;
            registry_set_observation_parameters(&notifier->endpoint->registry, &listing.path, &parameters);

        }

    }
}

#endif // !defined(MBED_CLOUD_CLIENT_DISABLE_REGISTRY)
