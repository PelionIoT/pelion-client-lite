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

#include "ns_list.h"
#include "nanostack-event-loop/eventOS_scheduler.h"
#include "nanostack-event-loop/eventOS_event.h"
#include "nanostack-event-loop/eventOS_event_timer.h"

#define PROTOMAN_CORE_FILE /* needs to be before protoman_trace.h -> needs to be before protoman_internal.h */
#define TRACE_GROUP  "PMan"
#include "mbed-protocol-manager/protoman.h"
#include "mbed-protocol-manager/protoman_layer.h"
#include "include/protoman_internal.h"
#include "arm_hal_interrupt.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static void _protoman_state_change(struct protoman_s *protoman, int new_state);
static struct protoman_event_storage_unit_s *protoman_event_storage_alloc(struct protoman_event_storage_s *event_storage, uint8_t event_type, uint32_t scheduled_at);
static void protoman_event_processed(struct protoman_event_storage_s *protoman_event_storage, arm_event_s *event);
static void protoman_events_cancel(struct protoman_event_storage_s *event_storage);
static int _protoman_drive_layers_to_state(struct protoman_s *protoman, int target_state);


void *protoman_internal_calloc(size_t nmemb, size_t size)
{
    if (0 == nmemb || 0 == size) {
        return NULL;
    }
    void *ptr = PROTOMAN_MALLOC(size * nmemb);
    if (NULL == ptr) {
        return NULL;
    }
    return memset(ptr, 0, size * nmemb);
}

int protoman_read(struct protoman_s *protoman, struct protoman_io_header_s *operation)
{
    struct protoman_layer_s *layer;

    if ((PROTOMAN_STATE_CONNECTED == protoman->current_state) || (PROTOMAN_STATE_RESUMED == protoman->current_state)) {
        layer = ns_list_get_first(&protoman->layers);
        protoman_info("reading from %s layer", layer->name);
        return layer->callbacks->layer_read(layer, operation);
    }

    protoman_warn("trying to read when not connected");
    return PROTOMAN_ERR_WOULDBLOCK;
}

int protoman_write(struct protoman_s *protoman, struct protoman_io_header_s *operation)
{
    struct protoman_layer_s *layer;

    if ((PROTOMAN_STATE_CONNECTED == protoman->current_state) || (PROTOMAN_STATE_RESUMED == protoman->current_state))
    {
        layer = ns_list_get_first(&protoman->layers);
        protoman_info("writing to %s layer", layer->name);
        return layer->callbacks->layer_write(layer, operation);
    }

    protoman_warn("trying to write when not connected");
    return PROTOMAN_ERR_WOULDBLOCK;
}

/* Returns the perceived state for a layer. Perceived state is required, as it makes ProtocolManager
 * wait all scheduled events and not read directly the layer->current_state. For example,
 * if layer->current_state was used here and a call to protoman_run() was invoked, the ProtocolManager
 * might change the global state to connecting as it looped all states through with _layers_in_state()
 * and thought that all layers are in correct disconnected state. But after a short while in the
 * connecting state the ProtocolManager receives the old delayed PROTOMAN_EVENT_DISCONNECTED event
 * and thinks that something must have been gone wrong with the connecting phase.
 */
static bool _layers_in_state(struct protoman_s *protoman, int state)
{
    protoman_verbose("%s", protoman_strstate(state));
    ns_list_foreach(struct protoman_layer_s, layer, &protoman->layers) {
        protoman_verbose("%s layer", layer->name);

        if (layer->no_statemachine) {
            continue;
        }

        if (layer->perceived_state != state) {
            protoman_verbose("%s layer is in wrong state %s", layer->name, protoman_strstate(layer->perceived_state));
            return false;
        }
    }
    return true;
}

static bool _layer_exists(struct protoman_s *protoman, struct protoman_layer_s *layer_in)
{
    ns_list_foreach(struct protoman_layer_s, layer, &protoman->layers) {
        if (layer == layer_in) {
            protoman_verbose("%s layer", layer->name);
            return true;
        }
    }
    return false;
}

void protoman_connect(struct protoman_s *protoman)
{
    protoman_info("");
    if (protoman->config.is_dgram) {
        protoman_info("connecting in UDP mode");
    } else {
        protoman_info("connecting in TCP mode");
    }
    protoman->target_state = PROTOMAN_STATE_CONNECTED;
    protoman_event(protoman, NULL, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
}

void protoman_disconnect(struct protoman_s *protoman)
{
    protoman_info("");
    protoman->target_state = PROTOMAN_STATE_DISCONNECTED;
    protoman_event(protoman, NULL, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
}

void protoman_pause(struct protoman_s *protoman)
{
    protoman_info("");
    protoman->target_state = PROTOMAN_STATE_PAUSED;
    protoman_event(protoman, NULL, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
}

void protoman_resume(struct protoman_s *protoman)
{
    protoman_info("");
    protoman->target_state = PROTOMAN_STATE_RESUMED;
    protoman_event(protoman, NULL, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
}

static void _protoman_state_change(struct protoman_s *protoman, int new_state)
{
    int old_state = protoman->current_state;
    bool state_transition = old_state != new_state;

    if (state_transition) {
#ifdef PROTOMAN_ERROR_STRING
        protoman_debug("%s -> %s",
                 protoman_strstate(old_state),
                 protoman_strstate(new_state));
#else
        protoman_debug("%d -> %d", old_state, new_state);
#endif
    } else {
        return;
    }

    protoman->current_state = new_state;
    /* protoman_event() must be called before event_cb() in case protoman_close() within the callback */
    protoman_event(protoman, NULL, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);

    switch (new_state) {
        case PROTOMAN_STATE_INITIALIZED:
            protoman_info("initialized");
            protoman->event_cb(protoman, NULL, PROTOMAN_EVENT_INITIALIZED, protoman->event_ctx);
            break;
        case PROTOMAN_STATE_CONNECTING:
            protoman_info("connecting");
            break;
        case PROTOMAN_STATE_CONNECTED:
            protoman_info("connected");
            protoman->event_cb(protoman, NULL, PROTOMAN_EVENT_CONNECTED, protoman->event_ctx);
            break;
        case PROTOMAN_STATE_DISCONNECTING:
            protoman_info("disconnecting");
            break;
        case PROTOMAN_STATE_DISCONNECTED:
            protoman_info("disconnected");
            protoman->event_cb(protoman, NULL, PROTOMAN_EVENT_DISCONNECTED, protoman->event_ctx);
            break;
        case PROTOMAN_STATE_PAUSING:
            protoman_info("pausing");
            break;
        case PROTOMAN_STATE_PAUSED:
            protoman_info("paused");
            protoman->event_cb(protoman, NULL, PROTOMAN_EVENT_PAUSED, protoman->event_ctx);
            break;
        case PROTOMAN_STATE_RESUMING:
            protoman_info("resuming");
            break;
        case PROTOMAN_STATE_RESUMED:
            protoman_info("resumed");
            protoman->event_cb(protoman, NULL, PROTOMAN_EVENT_RESUMED, protoman->event_ctx);
            break;
        case PROTOMAN_STATE_ERRORED:
            protoman_err("errored");
            protoman->event_cb(protoman, protoman->first_error, PROTOMAN_EVENT_ERROR, protoman->event_ctx);
            break;
        case PROTOMAN_STATE_ERRORING:
            // The erroring state is just a transient state, which can be left to default handler (at cost of a warning trace)
        default:
            protoman_info("unhandled state: %d", new_state);
            protoman->event_cb(protoman, NULL, PROTOMAN_APPEVENT_STATE_CHANGE, protoman->event_ctx);
            break;
    }
}

uint8_t protoman_get_state(struct protoman_s *protoman)
{
    protoman_info("<- %s", protoman_strstate(protoman->current_state));
    return protoman->current_state;
}

int protoman_get_layer_error(struct protoman_s *protoman)
{
    protoman_verbose("");

    if (protoman->first_error) {
        return protoman->first_error->protoman_error;
    }

    return 0;
}

int protoman_get_layer_error_specific(struct protoman_s *protoman)
{
    protoman_verbose("");

    if (protoman->first_error) {
        return protoman->first_error->specific_error;
    }

    return 0;
}

const char* protoman_get_layer_error_str(struct protoman_s *protoman)
{
    protoman_verbose("");

#ifdef PROTOMAN_ERROR_STRING
    if (protoman->first_error) {
        return protoman->first_error->specific_error_str;
    }
#else
    (void) protoman;
#endif // PROTOMAN_ERROR_STRING

    return "?";
}

void *protoman_get_info(struct protoman_s *protoman, struct protoman_layer_s *layer_id, int info_id)
{
    void *info;
    (void)layer_id;
    protoman_verbose("info request for %s", protoman_strinfo(info_id));
    /* Loop through all layers from top to down */
    ns_list_foreach(struct protoman_layer_s, layer, &protoman->layers) {
        protoman_verbose("%s layer", layer->name);
        /* Call info check if info function is defined */
        if (NULL != layer->callbacks->layer_info) {
            info = layer->callbacks->layer_info(layer, info_id);
            /* Return the info pointer to the caller */
            if (NULL != info) {
                protoman_verbose("%s layer, found matching info", layer->name);
                return info;
            }
        }
    }
    /* No match found */
    return NULL;
}

void *protoman_get_config(struct protoman_s *protoman, protoman_layer_id_t layer_id)
{
    struct protoman_layer_s *layer = layer_id;

    if (NULL != layer_id) {
        protoman_info("%s layer", layer->name);
        return layer->config;
    } else {
        protoman_info("protoman");
        return &protoman->config;
    }
}

// helper for going through layers and driving them to the target state
static int _protoman_drive_layers_to_state(struct protoman_s *protoman, int target_state)
{
    protoman_verbose("");

    /* Loop layers from top down */
    ns_list_foreach(struct protoman_layer_s, layer, &protoman->layers) {
        /* Skip layers without state */
        if (layer->no_statemachine) {
            continue;
        }

        /* Already in target state, continue to next */
        if (target_state == layer->perceived_state) {
            continue;
        }

        /* Start state transition */
        layer->target_state = target_state;
        protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
        break;
    }

    /* If all layers have freed their context, free layers */
    if (_layers_in_state(protoman, target_state)) {
        return PROTOMAN_STATE_RETVAL_FINISHED;
    }
    return PROTOMAN_STATE_RETVAL_WAIT;
}


static int _do_disconnect(struct protoman_s *protoman)
{
    protoman_verbose("");

    return _protoman_drive_layers_to_state(protoman, PROTOMAN_STATE_DISCONNECTED);
}

static int _do_connect(struct protoman_s *protoman)
{
    struct protoman_layer_s *last_layer = ns_list_get_last(&protoman->layers);

    protoman_verbose("");

    /* Trigger last layer to start connecting */
    /* TODO this will break if last layer does not have statemachine
     *  solution: find first layer with statemachine and call that */
    if (PROTOMAN_STATE_CONNECTED != last_layer->target_state) {
        last_layer->target_state = PROTOMAN_STATE_CONNECTED;
        protoman_event(protoman, last_layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
    }

    if (_layers_in_state(protoman, PROTOMAN_STATE_CONNECTED)) {
        return PROTOMAN_STATE_RETVAL_FINISHED;
    }
    return PROTOMAN_STATE_RETVAL_WAIT;
}

static int _do_pause(struct protoman_s *protoman)
{
    protoman_verbose("");

    return _protoman_drive_layers_to_state(protoman, PROTOMAN_STATE_PAUSED);
}

static int _do_resume(struct protoman_s *protoman)
{
    protoman_verbose("");

    return _protoman_drive_layers_to_state(protoman, PROTOMAN_STATE_RESUMED);
}

void protoman_run(struct protoman_s *protoman)
{
    struct protoman_layer_s *last_layer = ns_list_get_last(&protoman->layers);

    protoman_verbose("%s (>> %s)",
             protoman_strstate(protoman->current_state),
             protoman_strstate(protoman->target_state));

    switch (protoman->current_state) {
        case PROTOMAN_STATE_INITIALIZING:
            if (_layers_in_state(protoman, PROTOMAN_STATE_INITIALIZED)) {
                _protoman_state_change(protoman, PROTOMAN_STATE_INITIALIZED);
                break;
            }
            /* Create even for initialization. */
            protoman_event(protoman, last_layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
            break;

        case PROTOMAN_STATE_CONNECTING:
            switch (_do_connect(protoman)) {
                case PROTOMAN_STATE_RETVAL_FINISHED:
                    _protoman_state_change(protoman, PROTOMAN_STATE_CONNECTED);
                    break;
            }
            break;

        case PROTOMAN_STATE_RESUMED:
            // fall trough for now
        case PROTOMAN_STATE_CONNECTED:
            /* User initiated disconnection */
            switch (protoman->target_state) {
                case PROTOMAN_STATE_DISCONNECTED:
                    _protoman_state_change(protoman, PROTOMAN_STATE_DISCONNECTING);
                    break;
                case PROTOMAN_STATE_PAUSED:
                    _protoman_state_change(protoman, PROTOMAN_STATE_PAUSING);
                    break;
            }
            break;

        case PROTOMAN_STATE_DISCONNECTING:
            switch (_do_disconnect(protoman)) {
                case PROTOMAN_STATE_RETVAL_FINISHED:
                    _protoman_state_change(protoman, PROTOMAN_STATE_DISCONNECTED);
                    break;
            }
            break;

        case PROTOMAN_STATE_PAUSED:
            // fall trough for now

        case PROTOMAN_STATE_INITIALIZED:
        case PROTOMAN_STATE_DISCONNECTED:
            switch (protoman->target_state) {
                case PROTOMAN_STATE_CONNECTED:
                    /* Don't start (re)connecting until all layers are disconnected or initialized */
                    if (!(_layers_in_state(protoman, PROTOMAN_STATE_DISCONNECTED) ||
                            _layers_in_state(protoman, PROTOMAN_STATE_INITIALIZED) ||
                            _layers_in_state(protoman, PROTOMAN_STATE_PAUSED))) {
                        break;
                    }
                    _protoman_state_change(protoman, PROTOMAN_STATE_CONNECTING);
                    break;

                case PROTOMAN_STATE_RESUMED:
                    /* Don't start (re)connecting until all layers are disconnected or initialized */
                    if (!(_layers_in_state(protoman, PROTOMAN_STATE_DISCONNECTED) ||
                            _layers_in_state(protoman, PROTOMAN_STATE_INITIALIZED) ||
                            _layers_in_state(protoman, PROTOMAN_STATE_PAUSED))) {
                        break;
                    }
                    _protoman_state_change(protoman, PROTOMAN_STATE_RESUMING);
                    break;
            }
            break;

        case PROTOMAN_STATE_ERRORING:
            _protoman_state_change(protoman, PROTOMAN_STATE_ERRORED);
            break;

        case PROTOMAN_STATE_ERRORED:
            break;

        case PROTOMAN_STATE_PAUSING:
            switch (_do_pause(protoman)) {
                case PROTOMAN_STATE_RETVAL_FINISHED:
                    _protoman_state_change(protoman, PROTOMAN_STATE_PAUSED);
                    break;
            }
            break;

        case PROTOMAN_STATE_RESUMING:
            switch (_do_resume(protoman)) {
                case PROTOMAN_STATE_RETVAL_FINISHED:
                    // XXX: or should we actually skip to CONNECTED
                    _protoman_state_change(protoman, PROTOMAN_STATE_RESUMED);
                    break;
            }
            break;

        default:
            protoman_err("unknown default state %s", protoman_strstate(protoman->current_state));
            assert(false);
            _protoman_state_change(protoman, PROTOMAN_STATE_ERRORING);
            break;
    }
}

void protoman_event(struct protoman_s *protoman,
                   struct protoman_layer_s *layer,
                   uint8_t event_type,
                   int priority,
                   uint32_t after_ms)
{
    uint32_t ticks_at_new_scheduled = eventOS_event_timer_ticks() + eventOS_event_timer_ms_to_ticks(after_ms);

    /* determine event storage */
    struct protoman_event_storage_s *protoman_event_storage;
    if (NULL == layer) {
        protoman_event_storage = &protoman->protoman_event_storage;
    } else {
        protoman_event_storage = &layer->protoman_event_storage;
    }

    /* determine event storage unit */
    struct protoman_event_storage_unit_s *protoman_event_storage_unit;

    // Following code can be ran only from one thread at a time, as the protoman_event_storage_alloc()
    // can return a uninitialized event to multiple simultaneous callers. The race condition will
    // happen also if eventOS_event_timer_request_at() is called for a time in the past, which
    // will then trigger a event delivery immediately.
    platform_enter_critical();

    protoman_event_storage_unit = protoman_event_storage_alloc(protoman_event_storage, event_type, ticks_at_new_scheduled);

    if (!protoman_event_storage_unit) {
        platform_exit_critical();
        return;
    }

    /* populate eventOS event */
    arm_event_s event;
    event.receiver = protoman->tasklet_id;
    event.sender = protoman->tasklet_id;
    event.event_type = event_type;
    if (NULL == layer) {
        event.data_ptr = protoman;
        event.event_type += PROTOMAN_EVENT_BELONGS_TO_CORE;
    } else {
        event.data_ptr = layer;
    }

    /* Translate priority */
    switch (priority) {
        case PROTOMAN_EVENT_PRIORITY_HIGH:
            event.priority = ARM_LIB_HIGH_PRIORITY_EVENT;
            break;
        case PROTOMAN_EVENT_PRIORITY_MED:
            event.priority = ARM_LIB_MED_PRIORITY_EVENT;
            break;
        default: /* PROTOMAN_EVENT_PRIORITY_LOW */
            event.priority = ARM_LIB_LOW_PRIORITY_EVENT;
            break;
    }

#ifdef PROTOMAN_INTERRUPT_PRINT
    if (NULL != layer) {
        protoman_verbose("scheduling event %s from %s layer in %d ticks (%d ms)",
                 protoman_strevent(event_type), layer->name, ticks, after_ms);
    } else {
        protoman_verbose("scheduling event %s from protoman in %d ticks (%d ms)",
                 protoman_strevent(event_type), ticks, after_ms);
    }
#endif

    arm_event_storage_t *scheduled_event = eventOS_event_timer_request_at(&event, ticks_at_new_scheduled);
    if (NULL == scheduled_event) {
        platform_exit_critical();
        protoman_err("failed to schedule event, might result to event exhaustion");
        return;
    }
    protoman_event_storage_unit->ticks_at_scheduled = ticks_at_new_scheduled;
    protoman_event_storage_unit->arm_event_storage = scheduled_event;
    platform_exit_critical();

#ifdef PROTOMAN_INTERRUPT_PRINT
    protoman_verbose("succesfully scheduled %s id=%p", protoman_strevent(event_type), scheduled_event);
#endif
}

static struct protoman_event_storage_unit_s *protoman_event_storage_alloc(struct protoman_event_storage_s *event_storage, uint8_t event_type, uint32_t scheduled_at)
{
    int i;

    platform_enter_critical();
    for (i = 0; i < PROTOMAN_NUMBER_OF_EVENTS_TO_STORE; i++) {
        if (event_storage->events_stored[i].arm_event_storage) {
            if (event_storage->events_stored[i].arm_event_storage->data.event_type == event_type) {

                if (event_storage->events_stored[i].ticks_at_scheduled > scheduled_at) {
#ifdef PROTOMAN_INTERRUPT_PRINT
                    protoman_verbose("rescheduling PROTOMAN_EVENT_RUN %" PRIu32 " ticks", scheduled_at);
#endif
                    eventOS_cancel(event_storage->events_stored[i].arm_event_storage);
                    event_storage->events_stored[i].arm_event_storage = NULL;
                    platform_exit_critical();
                    return &event_storage->events_stored[i];
                }
#ifdef PROTOMAN_INTERRUPT_PRINT
                protoman_verbose("protoman_event_storage_alloc() ignoring request, there is already event scheduled %"PRIi32" ticks earlier", (scheduled_at - event_storage->events_stored[i].ticks_at_scheduled));
#endif
                platform_exit_critical();
                return NULL;

            }
        }
    }

    for (i = 0; i < PROTOMAN_NUMBER_OF_EVENTS_TO_STORE; i++) {
        if (!event_storage->events_stored[i].arm_event_storage) {
            platform_exit_critical();
            return &event_storage->events_stored[i];
        }
    }
#ifdef PROTOMAN_INTERRUPT_PRINT
    protoman_err("protoman_event_storage_alloc() Event allocation failed, dropping event %s (%d)", protoman_strevent(event_type), event_type);
#endif
    platform_exit_critical();
    return NULL;

}

static void protoman_event_processed(struct protoman_event_storage_s *protoman_event_storage, arm_event_s *event)
{
    int i;

    platform_enter_critical();
    for (i = 0; i < PROTOMAN_NUMBER_OF_EVENTS_TO_STORE; i++) {
        if (&protoman_event_storage->events_stored[i].arm_event_storage->data == event) {
            protoman_event_storage->events_stored[i].arm_event_storage = NULL;
            platform_exit_critical();
            return;
        }
    }

    //It must not be possible to have unknown events so
    //if this happens it is a coding error. Let's assert
    assert(0);

    platform_exit_critical();
}

static void protoman_events_cancel(struct protoman_event_storage_s *event_storage)
{
    int i;

    platform_enter_critical();
    for (i = 0; i < PROTOMAN_NUMBER_OF_EVENTS_TO_STORE; i++) {
        eventOS_cancel(event_storage->events_stored[i].arm_event_storage);
        event_storage->events_stored[i].arm_event_storage = NULL;
    }
    platform_exit_critical();
}


void protoman_event_handler(arm_event_s *event)
{
    struct protoman_s *protoman = NULL;
    struct protoman_layer_s *layer = NULL;
    struct protoman_event_storage_s *protoman_event_storage;

    /* Exit handler if no event->event_type */
    if (NULL == event->data_ptr) {
        if (PROTOMAN_EVENT_INITIALIZED != event->event_type) {
            protoman_err("received event without event->data_ptr");
            return;
        }
        /* OK to ignore PROTOMAN_EVENT_INITIALIZED event, it's just a mandatory thing from the eventOS */
        return;
    }

    /* Figure out if incoming event is core event (for protoman) */
    if (event->event_type >= PROTOMAN_EVENT_BELONGS_TO_CORE) {
        event->event_type -= PROTOMAN_EVENT_BELONGS_TO_CORE;
        protoman = event->data_ptr;
        layer = NULL;
        protoman_event_storage = &protoman->protoman_event_storage;
    } else {
        layer = event->data_ptr;
        protoman = layer->protoman;
        protoman_event_storage = &layer->protoman_event_storage;
    }

    protoman_event_processed(protoman_event_storage, event);

    /* NS_CONTAINER_OF() is used to get the container pointer that was given to use previously
     * when we scheduled the event with eventOS_event_send_after(). */
    protoman_verbose("%s (%d) event_id=%p", protoman_strevent(event->event_type), event->event_type, NS_CONTAINER_OF(event, arm_event_storage_t, data));

    /*  ProtocolManager event
     * ======================= */
    if (NULL == layer) {
        switch (event->event_type) {
            case PROTOMAN_EVENT_RUN:
                protoman_run(protoman);
                return;
            default:
                protoman_err("unsupported event_type %d", event->event_type);
                _protoman_state_change(protoman, PROTOMAN_STATE_ERRORING);
                return;
        }
    }

    if (!_layer_exists(protoman, layer)) {
        /* Don't poke further as it's likely the given layer was already freed
         * and this is just late event */
        protoman_err("received event from non-existent layer");
        return;
    }

    /*  Layer event
     * ============= */

    /* Find next layer with event callback */
    struct protoman_layer_s *next_layer = layer;
    while (NULL != next_layer) {
        next_layer = ns_list_get_previous(&protoman->layers, next_layer);
        /* If this is topmost layer, send event to application */
        if (NULL == next_layer) {
            break; /* below is a check for null next_layer, event -> application */
        }

        /* Search above layer for event callback */
        if (NULL != next_layer->callbacks->layer_event) {
            break;
        }
    }

    /* Perceive layer state -- this perceived state is used to gate ProtocolManager CONNECTING->CONNECTED */
    switch (event->event_type) {
        case PROTOMAN_EVENT_INITIALIZED:
            layer->perceived_state = PROTOMAN_STATE_INITIALIZED;
            protoman_event(protoman, NULL, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
            break;
        case PROTOMAN_EVENT_CONNECTED:
            layer->perceived_state = PROTOMAN_STATE_CONNECTED;
            protoman_event(protoman, NULL, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
            break;
        case PROTOMAN_EVENT_DISCONNECTED:
            layer->perceived_state = PROTOMAN_STATE_DISCONNECTED;
            _protoman_state_change(protoman, PROTOMAN_STATE_DISCONNECTING);
            break;
        case PROTOMAN_EVENT_PAUSED:
            layer->perceived_state = PROTOMAN_STATE_PAUSED;
            protoman_event(protoman, NULL, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
            break;
        case PROTOMAN_EVENT_RESUMED:
            layer->perceived_state = PROTOMAN_STATE_RESUMED;
            protoman_event(protoman, NULL, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
            break;
        case PROTOMAN_EVENT_ERROR:
            if (NULL == protoman->first_error) {
                protoman->first_error = layer;
            }
            layer->perceived_state = PROTOMAN_STATE_ERRORED;
            _protoman_state_change(protoman, PROTOMAN_STATE_ERRORING);
            break;
    }

    /* Handle run/timer events (go directly to the calling layer */
    switch (event->event_type) {
        case PROTOMAN_EVENT_RUN:
            protoman_verbose("sending %s (%d) to %s layer", protoman_strevent(event->event_type), event->event_type, layer->name);
            layer->callbacks->layer_event(layer, PROTOMAN_EVENT_RUN);
            return;
    }

    /* Handle application event */
    if (NULL == next_layer) {
        switch (event->event_type) {
            case PROTOMAN_EVENT_CONNECTED:
            case PROTOMAN_EVENT_DISCONNECTED:
            case PROTOMAN_EVENT_PAUSED:
            case PROTOMAN_EVENT_RESUMED:
            case PROTOMAN_EVENT_ERROR:
                /* Progress ProtocolManager state through protoman_run() */
                protoman_event(protoman, NULL, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
                break;
            default:
                /* Progress PROTOMAN_EVENT_DATA_AVAILs directly to application */
                protoman_debug("sending %s (%d) to application from %s", protoman_strevent(event->event_type), event->event_type, layer->name);
                protoman->event_cb(protoman, layer, event->event_type, protoman->event_ctx);
                break;
        }
    } else {
        /* All the rest of the events progress through layer stack */
        protoman_verbose("sending %s (%d) to %s from %s", protoman_strevent(event->event_type), event->event_type, next_layer->name, layer->name);
        next_layer->callbacks->layer_event(next_layer, event->event_type);
    }
}

void protoman_add_layer(struct protoman_s *protoman, struct protoman_layer_s *layer)
{
    assert(layer->name);

    if (protoman->current_state != PROTOMAN_STATE_INITIALIZING) {
        protoman_err("trying to add layers after connect");
        _protoman_state_change(protoman, PROTOMAN_STATE_ERRORING);
        return;
    }

    layer->protoman = protoman;

    protoman_verbose("adding %s layer", layer->name);
    ns_list_add_to_end(&protoman->layers, layer);
}

struct protoman_s *protoman_create(protoman_event_cb_t event_cb, void *event_ctx)
{
    struct protoman_s *protoman = PROTOMAN_CALLOC(sizeof(struct protoman_s));
    if (NULL == protoman) {
        protoman_err("not enough memory to allocate protoman");
        return NULL;
    }

    PROTOMAN_DEBUG_PRINT_ALLOC("protoman", sizeof(struct protoman_s), protoman);

    return protoman_open(protoman, event_cb, event_ctx);
}

struct protoman_s *protoman_open(protoman_id_t protoman_id,  protoman_event_cb_t event_cb, void *event_ctx)
{
    struct protoman_s *protoman = protoman_id;
    /* eventOS does not support destroying event handler, so using
       the same tasklet_id over all ProtocolManagers. This is ok because
       tasklet_id is only used by eventOS to forward the events to
       ProtocolManager event handler */
    /* volatile is for if ProtocolManagers are created in multiple threads */
    static volatile int8_t shared_tasklet_id = -1;

    memset(protoman, 0 , sizeof(struct protoman_s));

    protoman->event_cb = event_cb;
    protoman->event_ctx = event_ctx;

    protoman->config.is_dgram = true;
    protoman->config.is_client = true;

    ns_list_init(&protoman->layers);

    if (shared_tasklet_id < 0) {
        shared_tasklet_id = eventOS_event_handler_create(&protoman_event_handler, PROTOMAN_EVENT_INITIALIZED);
        protoman_debug("created new event handler with tasklet_id of %d", shared_tasklet_id);
    }
    protoman->tasklet_id = shared_tasklet_id;

    if (protoman->tasklet_id < 0) {
        protoman_err("tasklet allocation failed with %d", protoman->tasklet_id);
        return NULL;
    }

    protoman->config.mtu = PROTOMAN_MTU;

    protoman_verbose("created protoman succesfully at %p", protoman);
    return protoman;
}

void protoman_close(protoman_id_t protoman)
{
    protoman_info("");
    if (NULL == protoman) {
        return;
    }

    /*  Cleanup layers
     * ---------------- */

    ns_list_foreach_safe(struct protoman_layer_s, layer, &protoman->layers) {

        /* Cancel events for this layer */
        protoman_events_cancel(&layer->protoman_event_storage);

        /* Call layer free */
        if (NULL != layer->callbacks->layer_free) {
            layer->callbacks->layer_free(layer);
        }
        ns_list_remove(&protoman->layers, layer);
    }

    /*  Cleanup protoman
     * ------------------ */
    /* Cancel events for protoman */
    protoman_events_cancel(&protoman->protoman_event_storage);

    protoman->current_state = PROTOMAN_STATE_DISCONNECTED;

}

void protoman_free(protoman_id_t protoman)
{
    protoman_info("");
    protoman_close(protoman);
    PROTOMAN_FREE(protoman);
}
