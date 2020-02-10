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

#include <stdint.h>

#include "mbed-protocol-manager/protoman_config.h"

#ifndef PROTOMAN_OFFLOAD_TLS

#include "nanostack-event-loop/eventOS_event_timer.h"

#include "protoman.h"
#include "protoman_layer.h"
#include "protoman_layer_mbedtls.h"
#define TRACE_GROUP  "mTLS"
#include "include/protoman_internal.h"
#include "include/protoman_layer_mbedtls_timer.h"

void timer_set(void *timer_ctx, uint32_t int_ms, uint32_t fin_ms)
{
    struct protoman_layer_s *layer = timer_ctx;
    struct protoman_s *protoman = layer->protoman;
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *)layer;

    protoman_verbose("int_ms=%u, fin_ms=%u", (unsigned int)int_ms, (unsigned int)fin_ms);

    /* Cannot store these as ticks as they might get rounded down and interpret as cancelled */
    layer_mbedtls_common->mbedtls_timer_int_ms = int_ms;
    layer_mbedtls_common->mbedtls_timer_fin_ms = fin_ms;

    if (fin_ms == 0) {
        protoman_verbose("cancel timer");
        return;
    }

    layer_mbedtls_common->mbedtls_timer_started_ticks = eventOS_event_timer_ticks();

    /* If using a event-driven style of programming, an event must be generated
     * when the final delay is passed. The event must cause a call to mbedtls_ssl_handshake()
     * with the proper SSL context to be scheduled. */
    protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, fin_ms);
}

void timer_rearm(struct protoman_s *protoman, struct protoman_layer_s *layer)
{
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *)layer;

    /* Rearming is not valid in errored state */
    if (PROTOMAN_STATE_ERRORED == layer->current_state) {
        protoman_verbose("layer in \"%s\"", protoman_strstate(layer->current_state));
        return;
    }

    /* Exit if timer is cancelled */
    if (layer_mbedtls_common->mbedtls_timer_fin_ms == 0) {
        protoman_verbose("timer is cancelled");
        return;
    }

    /* Calculate new event */
    uint32_t timer_ticks_started = layer_mbedtls_common->mbedtls_timer_started_ticks;
    uint32_t timer_ticks_at_fin = timer_ticks_started + eventOS_event_timer_ms_to_ticks(layer_mbedtls_common->mbedtls_timer_fin_ms);
    int32_t timer_ticks_to_fin = timer_ticks_at_fin - eventOS_event_timer_ticks();
    if (timer_ticks_to_fin < 0) {
        protoman_verbose("adjusting to zero");
        timer_ticks_to_fin = 0; /* in case the timer event should be now and it advances during this call */
    }
    uint32_t timer_ms_to_fin = eventOS_event_timer_ticks_to_ms(timer_ticks_to_fin);

    /* Create new event */
    protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, timer_ms_to_fin);
}

int timer_get(void *timer_ctx)
{
    int retval;
    struct protoman_layer_s *layer = timer_ctx;
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *)layer;

    /* Option cancelled */
    if (layer_mbedtls_common->mbedtls_timer_fin_ms == 0) {
        protoman_verbose("returning -1 (cancelled)");
        return -1; /* if cancelled (fin_ms == 0) */
    }

    uint32_t timer_ticks_current = eventOS_event_timer_ticks();
    uint32_t timer_ticks_passed = timer_ticks_current - layer_mbedtls_common->mbedtls_timer_started_ticks;
    uint32_t timer_fin_ticks = eventOS_event_timer_ms_to_ticks(layer_mbedtls_common->mbedtls_timer_fin_ms);
    uint32_t timer_int_ticks = eventOS_event_timer_ms_to_ticks(layer_mbedtls_common->mbedtls_timer_int_ms);

    if (timer_ticks_passed > timer_fin_ticks) {
        retval = 2; /* if the final delay has passed */
    } else if (timer_ticks_passed > timer_int_ticks) {
        retval = 1; /* if only the intermediate delay has passed */
    } else {
        retval = 0; /* if none of the delays have passed */
    }
    protoman_verbose("returning %d", retval);
    return retval;
}
#endif
