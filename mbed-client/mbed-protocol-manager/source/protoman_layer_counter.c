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

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "mbed-protocol-manager/protoman.h"
#include "mbed-protocol-manager/protoman_layer.h"
#include "mbed-protocol-manager/protoman_layer_counter.h"
#define TRACE_GROUP  "Pcnt"
#include "include/protoman_internal.h"

static int layer_read(struct protoman_layer_s *layer, struct protoman_io_header_s *operation);
static int layer_write(struct protoman_layer_s *layer, struct protoman_io_header_s *operation);

static const struct protoman_layer_callbacks_s callbacks = {
    NULL,
    &layer_read,
    &layer_write,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

void protoman_add_layer_counter(struct protoman_s *protoman, struct protoman_layer_s *layer)
{
    struct protoman_layer_counter_s *layer_counter = (struct protoman_layer_counter_s *)layer;

    layer->name = "Counter"; // must be set before first print from this layer

    protoman_debug("");

    layer->callbacks = &callbacks;
    layer->no_statemachine = true;

    layer->config = &layer_counter->config;

    protoman_add_layer(protoman, layer);
}

static void _print_count(struct protoman_layer_s *layer, struct protoman_config_counter_unit_s *unit)
{
    protoman_debug("count = %" PRIu32, unit->count);
    protoman_debug("bytes = %" PRIu32, unit->bytes);
    protoman_debug("nomem = %" PRIu32, unit->nomem);
    protoman_debug("wblck = %" PRIu32, unit->wouldblock);
}

static int _retval_parse(struct protoman_layer_s *layer, struct protoman_config_counter_unit_s *unit, int retval)
{
    if (retval >= 0) {
        protoman_debug("logging %d bytes", retval);
        unit->count++;
        unit->bytes += retval;
    } else if (PROTOMAN_ERR_NOMEM == retval) {
        protoman_debug("logging PROTOMAN_ERR_NOMEM");
        unit->nomem++;
    } else if (PROTOMAN_ERR_WOULDBLOCK == retval) {
        protoman_debug("logging PROTOMAN_ERR_WOULDBLOCK");
        unit->wouldblock++;
    }
    _print_count(layer, unit);
    return retval;
}

static int layer_write(struct protoman_layer_s *layer, struct protoman_io_header_s *operation)
{
    struct protoman_config_counter_s *config = (struct protoman_config_counter_s *)layer->config;
    struct protoman_config_counter_unit_s *tx_counter = &config->tx;

    protoman_verbose("");

    return _retval_parse(layer, tx_counter, protoman_layer_write_next(layer, operation));
}

static int layer_read(struct protoman_layer_s *layer, struct protoman_io_header_s *operation)
{
    struct protoman_config_counter_s *config = (struct protoman_config_counter_s *)layer->config;
    struct protoman_config_counter_unit_s *rx_counter = &config->rx;

    protoman_verbose("");

    return _retval_parse(layer, rx_counter, protoman_layer_read_next(layer, operation));
}

