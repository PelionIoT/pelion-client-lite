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
#include "mbed-protocol-manager/protoman_layer_null.h"
#define TRACE_GROUP  "Pnul"
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

void protoman_add_layer_null(struct protoman_s *protoman, struct protoman_layer_s *layer)
{
#ifdef MBED_CONF_MBED_TRACE_ENABLE
    layer->name = "NULL"; // must be set before first print from this layer
#else
    layer->name = NULL;
#endif

    protoman_debug("");

    layer->callbacks = &callbacks;
    layer->no_statemachine = true;

    protoman_add_layer(protoman, layer);
}

static int layer_write(struct protoman_layer_s *layer, struct protoman_io_header_s *operation)
{
    struct protoman_io_bytes_s *op = (struct protoman_io_bytes_s *)operation;

    protoman_verbose("");

    return op->len;
}

static int layer_read(struct protoman_layer_s *layer, struct protoman_io_header_s *operation)
{
    protoman_verbose("");

    return PROTOMAN_ERR_WOULDBLOCK;
}

