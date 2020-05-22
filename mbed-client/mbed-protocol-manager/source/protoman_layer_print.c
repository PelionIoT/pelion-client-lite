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
#include "mbed-protocol-manager/protoman_layer_print.h"
#define TRACE_GROUP  "Prnt"
#include "include/protoman_internal.h"

/* static function declarations */
static int layer_read(struct protoman_layer_s *layer, struct protoman_io_header_s *operation);
static int layer_write(struct protoman_layer_s *layer, struct protoman_io_header_s *operation);
static void *layer_info(struct protoman_layer_s *layer, int info_id);

static const struct protoman_layer_callbacks_s callbacks = {
    &layer_info,
    &layer_read,
    &layer_write,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

void protoman_add_layer_print(struct protoman_s *protoman, struct protoman_layer_s *layer)
{
    layer->name = "Print"; // must be set before first print from this layer

    protoman_debug("");

    layer->callbacks = &callbacks;
    layer->no_statemachine = true;

    protoman_add_layer(protoman, layer);
}

static void *layer_info(struct protoman_layer_s *layer, int info_id)
{
    protoman_info("%s", protoman_strinfo(info_id));
    return NULL;
}

static int layer_write(struct protoman_layer_s *layer, struct protoman_io_header_s *operation)
{
#if MBED_CONF_MBED_TRACE_ENABLE
    struct protoman_io_bytes_s *op = (struct protoman_io_bytes_s *)operation;
#endif
    protoman_debug("buf[%zd]=%s", op->len, mbed_trace_array(op->buf, op->len));

    /* pass on */
    return protoman_layer_write_next(layer, operation);
}

static int layer_read(struct protoman_layer_s *layer, struct protoman_io_header_s *operation)
{
#if MBED_CONF_MBED_TRACE_ENABLE
    struct protoman_io_bytes_s *op = (struct protoman_io_bytes_s *)operation;
#endif
    ssize_t retval;

    retval = protoman_layer_read_next(layer, operation);

    /* If read was succesful */
    if (retval > 0) {
        protoman_debug("buf[%zd]=%s", retval, mbed_trace_array(op->buf, retval));
    }

    /* pass on */
    return retval;
}

