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

#ifndef PROTOMAN_INTERNAL_H
#define PROTOMAN_INTERNAL_H

#include <stdint.h>
#include "protoman_trace.h"
#include "nanostack-event-loop/eventOS_scheduler.h"
#include "nanostack-event-loop/eventOS_event.h"
#include "nanostack-event-loop/eventOS_event_timer.h"

#ifndef PROTOMAN_NUMBER_OF_EVENTS_TO_STORE
#define PROTOMAN_NUMBER_OF_EVENTS_TO_STORE 3 // This value should be large enough to hold all events for one layer,
                                              // if not it should be overwritten with a bigger value.
#endif

struct protoman_event_storage_unit_s {
    arm_event_storage_t *arm_event_storage;
    uint32_t ticks_at_scheduled;
};

struct protoman_event_storage_s {
    struct protoman_event_storage_unit_s events_stored[PROTOMAN_NUMBER_OF_EVENTS_TO_STORE];
};

#endif // PROTOMAN_INTERNAL_H
