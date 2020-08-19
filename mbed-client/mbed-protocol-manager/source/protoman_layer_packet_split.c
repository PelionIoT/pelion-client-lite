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
#include "mbed-protocol-manager/protoman_layer_frame_lv.h"
#define TRACE_GROUP  "Pspl"
#include "include/protoman_internal.h"

/* static function declarations */
static void layer_event(struct protoman_layer_s *layer, int event_id);
static int layer_write(struct protoman_layer_s *layer, struct protoman_io_header_s *operation);
static int layer_read(struct protoman_layer_s *layer, struct protoman_io_header_s *operation);

static int _do_read(struct protoman_layer_s *layer);

static const struct protoman_layer_callbacks_s callbacks = {
    NULL,
    &layer_read,  /* Custom read that only gives small amount */
    &layer_write, /* Custom bypass write */
    &layer_event,
    &protoman_generic_layer_free,
    NULL,
    NULL,
    &_do_read,
    NULL,
    NULL,
    NULL,
    NULL
};

static void layer_event(struct protoman_layer_s *layer, int event_id)
{
    struct protoman_s *protoman = layer->protoman;

    protoman_verbose("%s", protoman_strevent(event_id));

    switch (event_id) {
        case PROTOMAN_EVENT_RUN:
        case PROTOMAN_EVENT_INITIALIZED:
        case PROTOMAN_EVENT_DATA_AVAIL:
            /* break to layer_run() below */
            break;

        case PROTOMAN_EVENT_DATA_WRITTEN:
            /* Because we don't have any write handlers, pass this to next layer */
            protoman_event(protoman, layer, PROTOMAN_EVENT_DATA_WRITTEN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
            break;

        case PROTOMAN_EVENT_DISCONNECTED:
            if (PROTOMAN_STATE_DISCONNECTED == layer->current_state) {
                /* need to manually pass the event as there is not going to be a transition */
                protoman_event(protoman, layer, PROTOMAN_EVENT_DISCONNECTED, PROTOMAN_EVENT_PRIORITY_LOW, 0);
            }
            layer->target_state = PROTOMAN_STATE_DISCONNECTED;
            break;

        case PROTOMAN_EVENT_CONNECTED:
            layer->target_state = PROTOMAN_STATE_CONNECTED;
            break;

        default:
            protoman_err("not implemented event_id %d", event_id);
            return;
    }
    protoman_generic_layer_run(layer);
}

void protoman_add_layer_packet_split(struct protoman_s *protoman, struct protoman_layer_s *layer)
{
    struct protoman_layer_packet_split_s *layer_packet_split = (struct protoman_layer_packet_split_s *)layer;
#ifdef MBED_CONF_MBED_TRACE_ENABLE
    layer->name = "Packet Split"; // must be set before first print from this layer
#else
    layer->name = NULL;
#endif

    protoman_debug("");

    layer->config = &layer_packet_split->config;
    layer->callbacks = &callbacks;

    layer_packet_split->config.read_max_bytes = protoman->config.mtu; /* Default to off */

    protoman_add_layer(protoman, layer);
}

static int layer_write(struct protoman_layer_s *layer, struct protoman_io_header_s *operation)
{
    protoman_verbose("");

    /* skip to next layer */
    return protoman_layer_write_next(layer, operation);
}

static int layer_read(struct protoman_layer_s *layer, struct protoman_io_header_s *operation)
{
    struct protoman_s *protoman = layer->protoman;
    struct protoman_layer_packet_split_s *layer_packet_split = (struct protoman_layer_packet_split_s *)layer;
    struct protoman_io_bytes_s *op = (struct protoman_io_bytes_s *)operation;

    protoman_verbose("");

    /* Check data availability*/
    if (NULL == layer->rx_buf) {
        protoman_verbose("no data to read");
        return PROTOMAN_ERR_WOULDBLOCK;
    }

    /* Cap read length */
    size_t copy_length = op->len < layer_packet_split->config.read_max_bytes ? op->len : layer_packet_split->config.read_max_bytes;

    /* Cap data avail */
    size_t data_avail = layer->rx_len - layer->rx_offset;
    copy_length = copy_length < data_avail ? copy_length : data_avail;

    /* Transfer */
    protoman_verbose("%d bytes being read from %p to %p", (int)copy_length, layer->rx_buf + layer->rx_offset ,op->buf);
    memcpy(op->buf, layer->rx_buf + layer->rx_offset, copy_length);

    /* Clear incoming data buffer from memory */
    memset(layer->rx_buf + layer->rx_offset, 0, copy_length);
    layer->rx_offset += copy_length;

    /* Generate new DATA_AVAIL event if there is still data to be read */
    if ((int)layer->rx_offset != layer->rx_len) {
        protoman_verbose("still data -> PROTOMAN_EVENT_DATA_AVAIL");
        protoman_event(protoman, layer, PROTOMAN_EVENT_DATA_AVAIL, PROTOMAN_EVENT_PRIORITY_LOW, 0);
    } else {
        protoman_verbose("all data read");
        PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer->rx_buf);
        protoman_rx_free(protoman, layer->rx_buf);
        layer->rx_buf = NULL;
        layer->rx_offset = 0;
        layer->rx_len = 0;
        /* Schedule runtime for the layer now that the buffers are free. This is needed to read blocked data from below */
        protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
    }

    return copy_length;
}

static int _do_read(struct protoman_layer_s *layer)
{
    struct protoman_s *protoman = layer->protoman;
    struct protoman_io_bytes_s op_bytes;

    int retval;
    int state_retval = PROTOMAN_STATE_RETVAL_WAIT;

    protoman_verbose("");

    /* Check if old data is still in */
    if (NULL != layer->rx_buf) {
        protoman_verbose("cannot read new data as layer->rx_buf holds data");
        goto exit;
    }

    /* Allocate space to read data to */
    layer->rx_buf = protoman_rx_alloc(protoman, protoman->config.mtu);
    if (NULL == layer->rx_buf) {
        protoman_err("out of memory");
        protoman_layer_record_error(layer, PROTOMAN_ERR_NOMEM, PROTOMAN_ERR_NOMEM, protoman_strerror(PROTOMAN_ERR_NOMEM));
        state_retval = PROTOMAN_STATE_RETVAL_ERROR;
        goto exit;
    }
    PROTOMAN_DEBUG_PRINT_ALLOC(layer->name, protoman->config.mtu, layer->rx_buf);

    /* Read from below */
    op_bytes.header.type = PROTOMAN_IO_BYTES;
    op_bytes.buf = layer->rx_buf; /* The data will be copied in next layer without modifications */
    op_bytes.len = protoman->config.mtu;
    retval = (int)protoman_layer_read_next(layer, (struct protoman_io_header_s *)&op_bytes);

    switch (retval) {
        case PROTOMAN_ERR_WOULDBLOCK:
            protoman_verbose("WOULDBLOCK");
            goto cleanup;
        case PROTOMAN_ERR_NOMEM:
        case PROTOMAN_ERR_WRONG_IO_TYPE:
        case PROTOMAN_ERR_INVALID_INPUT:
            protoman_err("%s", protoman_strerror(retval));
            protoman_layer_record_error(layer, retval, retval, protoman_strerror(retval));
            state_retval = PROTOMAN_STATE_RETVAL_ERROR;
            goto cleanup;
    }

#ifdef PROTOMAN_SANITY
    if (retval < 0) {
        protoman_err("protoman_layer_read_next() is not allowed to return %d \"%s\"", retval, protoman_strerror(retval))
        protoman_layer_record_error(layer, PROTOMAN_ERR_SANITY, retval, protoman_strerror(retval));
        state_retval = PROTOMAN_STATE_RETVAL_ERROR;
        goto cleanup;
    }
#endif // PROTOMAN_SANITY

    layer->rx_len = retval;
    layer->rx_offset = 0;
    protoman_event(protoman, layer, PROTOMAN_EVENT_DATA_AVAIL, PROTOMAN_EVENT_PRIORITY_LOW, 0);
    goto exit;

cleanup:
    PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer->rx_buf);
    protoman_rx_free(protoman, layer->rx_buf);
    layer->rx_buf = NULL;
exit:
    return state_retval;
}
