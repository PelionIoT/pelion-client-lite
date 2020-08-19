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
#include "mbed-protocol-manager/protoman_layer_buffer.h"
#define TRACE_GROUP  "Pbuf"
#include "include/protoman_internal.h"

/* static function declarations */
static int layer_read(struct protoman_layer_s *layer, struct protoman_io_header_s *operation);
static int layer_write(struct protoman_layer_s *layer, struct protoman_io_header_s *operation);
static void layer_event(struct protoman_layer_s *layer, int event_id);

static void _layer_run(struct protoman_layer_s *layer);
static int _do_write(struct protoman_layer_s *layer);
static int _do_read(struct protoman_layer_s *layer);

static const struct protoman_layer_callbacks_s callbacks = {
    NULL,
    &layer_read,
    &layer_write,
    &layer_event,
    &protoman_generic_layer_free,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

void protoman_add_layer_buffer(struct protoman_s *protoman, struct protoman_layer_s *layer)
{
#ifdef MBED_CONF_MBED_TRACE_ENABLE
    layer->name = "Buffer"; // must be set before first print from this layer
#else
    layer->name = NULL;
#endif

    protoman_debug("");

    layer->callbacks = &callbacks;
    layer->no_statemachine = true;

    protoman_add_layer(protoman, layer);
}

static void layer_event(struct protoman_layer_s *layer, int event_id)
{
    struct protoman_s *protoman = layer->protoman;

    protoman_verbose("%s", protoman_strevent(event_id));

    switch (event_id) {
        case PROTOMAN_EVENT_INITIALIZED:
        case PROTOMAN_EVENT_CONNECTED:
        case PROTOMAN_EVENT_DISCONNECTED:
            /* Propagate above because no state machien */
            protoman_event(protoman, layer, event_id, PROTOMAN_EVENT_PRIORITY_LOW, 0);
            break;
        case PROTOMAN_EVENT_DATA_WRITTEN:
        case PROTOMAN_EVENT_DATA_AVAIL:
        case PROTOMAN_EVENT_RUN:
            _layer_run(layer);
            break;
        default:
            protoman_err("not implemented event_id %d", event_id);
            break;
    }
}

static int _do_write(struct protoman_layer_s *layer)
{
    struct protoman_s *protoman = layer->protoman;
    struct protoman_io_bytes_s op_bytes;

    protoman_verbose("");

    if (NULL == layer->tx_buf) {
        protoman_verbose("nothing to send");
        return PROTOMAN_STATE_RETVAL_WAIT;
    }

    /* Write to below */
    op_bytes.header.type = PROTOMAN_IO_BYTES;
    op_bytes.buf = layer->tx_buf; /* The data will be copied in next layer without modifications */
    op_bytes.len = layer->tx_len;
    int retval = (int)protoman_layer_write_next(layer, (struct protoman_io_header_s *)&op_bytes);

    if (retval < 0) {
        protoman_verbose("protoman_layer_write_next() returned %s (%d)", protoman_strerror(retval), retval);
        return PROTOMAN_STATE_RETVAL_WAIT;
    }

    size_t write_len = retval;
    layer->tx_offset += write_len;

    if ((int)layer->tx_offset == layer->tx_len) {
        /* all sent */
        PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer->tx_buf);
        protoman_tx_free(protoman, layer->tx_buf);
        layer->tx_buf = NULL;
        layer->tx_len = 0;
        layer->tx_offset = 0;
        protoman_event(protoman, layer, PROTOMAN_EVENT_DATA_WRITTEN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
        return PROTOMAN_STATE_RETVAL_WAIT;
    } else {
        /* needs work */
        return PROTOMAN_STATE_RETVAL_AGAIN;
    }
}

static int _do_read(struct protoman_layer_s *layer)
{
    struct protoman_s *protoman = layer->protoman;
    struct protoman_io_bytes_s op_bytes;

    protoman_verbose("");

    /* Check if old data is still in */
    if (NULL != layer->rx_buf) {
        protoman_verbose("cannot read new data as layer->rx_buf holds data");
        return PROTOMAN_STATE_RETVAL_WAIT;
    }

    /* Allocate space to read data to */
    layer->rx_buf = protoman_rx_alloc(protoman, protoman->config.mtu);
    if (NULL == layer->rx_buf) {
        protoman_warn("no memory to alloc layer->rx_buf");
        return PROTOMAN_STATE_RETVAL_AGAIN;
    }

    PROTOMAN_DEBUG_PRINT_ALLOC(layer->name, protoman->config.mtu, layer->rx_buf);

    /* Read from below */
    op_bytes.header.type = PROTOMAN_IO_BYTES;
    op_bytes.buf = layer->rx_buf; /* The data will be copied in next layer without modifications */
    op_bytes.len = protoman->config.mtu;
    int retval = (int)protoman_layer_read_next(layer, (struct protoman_io_header_s *)&op_bytes);

    if (retval < 0) {
        protoman_warn("protoman_layer_read_next() returned %s (%d)", protoman_strerror(retval), retval);
        PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer->rx_buf);
        protoman_rx_free(protoman, layer->rx_buf);
        layer->rx_buf = NULL;
        return PROTOMAN_STATE_RETVAL_WAIT;
    }

    layer->rx_len = retval;
    layer->rx_offset = 0;
    protoman_event(protoman, layer, PROTOMAN_EVENT_DATA_AVAIL, PROTOMAN_EVENT_PRIORITY_LOW, 0);
    return PROTOMAN_STATE_RETVAL_WAIT;
}

static void _layer_run(struct protoman_layer_s *layer)
{
    struct protoman_s *protoman = layer->protoman;
    int retval;

    protoman_verbose("");

    retval = _do_read(layer);
    switch(retval) {
        case PROTOMAN_STATE_RETVAL_WAIT:
            /* do nothing */
            break;

        case PROTOMAN_STATE_RETVAL_AGAIN:
            protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 50);
            break;

        default:
            protoman_err("unhandled _do_read() return value of %s (%d)", protoman_strstateretval(retval), retval);
            break;
    }

    retval = _do_write(layer);
    switch(retval) {
        case PROTOMAN_STATE_RETVAL_WAIT:
            /* do nothing */
            break;

        case PROTOMAN_STATE_RETVAL_AGAIN:
            protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 50);
            break;

        default:
            protoman_err("unhandled _do_write() return value of %s (%d)", protoman_strstateretval(retval), retval);
            break;
    }
}

static int layer_write(struct protoman_layer_s *layer, struct protoman_io_header_s *operation)
{
    ssize_t retval;

    protoman_verbose("");

    /* Try to write to next layer */
    retval = protoman_layer_write_next(layer, operation);

    /* Writing data to next layer failed, safe data to self */
    if (PROTOMAN_ERR_WOULDBLOCK == retval) {
        retval = protoman_generic_bytes_layer_write(layer, operation);
    }

    return retval;
}

static int layer_read(struct protoman_layer_s *layer, struct protoman_io_header_s *operation)
{
    ssize_t retval;

    protoman_verbose("");

    /* First try to empty own buffer */
    retval = protoman_generic_bytes_layer_read(layer, operation);

    /* No data on self, try layer below */
    if (PROTOMAN_ERR_WOULDBLOCK == retval) {
        retval = protoman_layer_read_next(layer, operation);
    }

    return retval;
}
