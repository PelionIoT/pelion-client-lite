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
#define TRACE_GROUP  "PfLV"
#include "include/protoman_internal.h"

/* static function declarations */
static int _do_init(struct protoman_layer_s *layer);
static int _do_write(struct protoman_layer_s *layer);
static int _do_read(struct protoman_layer_s *layer);
//static int _do_connect(struct protoman_layer_s *layer);
static int _do_disconnect(struct protoman_layer_s *layer);
static void layer_free(struct protoman_layer_s *layer);

static const struct protoman_layer_callbacks_s callbacks = {
    NULL,
    &protoman_generic_bytes_layer_read,
    &protoman_generic_bytes_layer_write,
    &protoman_generic_layer_event,
    &layer_free,
    &_do_init,
    NULL,
    &_do_read,
    &_do_write,
    &_do_disconnect,
    NULL,
    NULL
};

struct layer_context_s {
    uint8_t *data_buf; /* when read done, transfer this pointer to layer->rx_buf */
    uint8_t *length_buf;
    uint8_t length_offset; /* offset pointer showing current read bytes */
    int state;
    struct protoman_config_frame_lv_s config;
};

#define PROTOMAN_FRAME_LV_HEADER 1
#define PROTOMAN_FRAME_LV_DATA   2

#if MBED_CONF_MBED_TRACE_ENABLE
static const char* _str_state(int state)
{
    switch(state) {
        case PROTOMAN_FRAME_LV_HEADER:
            return "PROTOMAN_FRAME_LV_HEADER";
        case PROTOMAN_FRAME_LV_DATA:
            return "PROTOMAN_FRAME_LV_DATA";
        default:
            return "unknown state";
    }
}
#endif

void protoman_add_layer_frame_lv(struct protoman_s *protoman, struct protoman_layer_s *layer)
{
    struct protoman_layer_frame_lv_s *layer_frame_lv = (struct protoman_layer_frame_lv_s *)layer;

    layer->name = "LV Frame"; // must be set before first print from this layer

    protoman_debug("");

    /* Connect layer callbacks */
    layer->config = &layer_frame_lv->config;
    layer->callbacks = &callbacks;

    layer_frame_lv->config.length_field_width = 4;
    layer_frame_lv->state = PROTOMAN_FRAME_LV_HEADER;

    protoman_add_layer(protoman, layer);
}


static void _build_length(struct protoman_layer_s *layer, uint8_t *buf, size_t value)
{
    struct protoman_layer_frame_lv_s *layer_frame_lv = (struct protoman_layer_frame_lv_s *)layer;
    struct protoman_config_frame_lv_s *config = &layer_frame_lv->config;

    protoman_verbose("buf[] <- %d", (int)value);

    for (uint8_t i = 0; i < layer_frame_lv->config.length_field_width; i++) {
        if (config->little_endian) {
            buf[i] = (value >> (i * 8) ) & 0xff;
        } else {
            buf[i] = (value >> ((layer_frame_lv->config.length_field_width - i - 1) * 8) ) & 0xff;
        }
    }
}

static size_t _parse_length(struct protoman_layer_s *layer, uint8_t *buf)
{
    struct protoman_layer_frame_lv_s *layer_frame_lv = (struct protoman_layer_frame_lv_s *)layer;
    struct protoman_config_frame_lv_s *config = &layer_frame_lv->config;
    size_t value = 0;

    protoman_verbose("");

    for (uint8_t i = 0; i < layer_frame_lv->config.length_field_width; i++) {
        if (config->little_endian) {
            value += buf[i] << (i * 8);
        } else {
            value += buf[i] << ((layer_frame_lv->config.length_field_width - i - 1) * 8);
        }
    }

    protoman_verbose("value = %d", (int)value);

    return value;
}

static int _do_write(struct protoman_layer_s *layer)
{
    struct protoman_layer_frame_lv_s *layer_frame_lv = (struct protoman_layer_frame_lv_s *)layer;
    struct protoman_config_frame_lv_s *config = &layer_frame_lv->config;
    struct protoman_io_bytes_s op;
    int retval;

    protoman_verbose("");

    /* Check that there is data */
    if (NULL == layer->tx_buf) {
        protoman_verbose("layer->tx_buf is empty");
        return PROTOMAN_STATE_RETVAL_WAIT;
    }

    /* Allocate larger buffer to contain header */
    size_t lv_frame_len = layer->tx_len + config->length_field_width;
    uint8_t *lv_frame = protoman_tx_alloc(protoman, lv_frame_len);
    if (NULL == lv_frame) {
        protoman_layer_record_error(layer, PROTOMAN_ERR_NOMEM, PROTOMAN_ERR_NOMEM, protoman_strerror(PROTOMAN_ERR_NOMEM));
        protoman_err("not enough memory to expand incoming packet of size %d", (int)layer->tx_len);
        return PROTOMAN_STATE_RETVAL_ERROR;
    }

    PROTOMAN_DEBUG_PRINT_ALLOC(layer->name, lv_frame_len, lv_frame);

    memcpy(lv_frame + config->length_field_width, layer->tx_buf, layer->tx_len);

    /* Add length field */
    _build_length(layer, lv_frame, layer->tx_len + layer_frame_lv->config.length_field_offset);

    /* Fill io operation for write */
    op.header.type = PROTOMAN_IO_BYTES;
    op.buf = lv_frame;
    op.len = lv_frame_len;

    /* pass on */
    retval = protoman_layer_write_next(layer, (struct protoman_io_header_s *)&op);

    /* free the temp buff */
    PROTOMAN_DEBUG_PRINT_FREE(layer->name, lv_frame);
    protoman_tx_free(protoman, lv_frame);

    /* check that all data was sent, TODO implement stream support along with read side */
    if (retval != (int)op.len) {
        protoman_err("failed to write %d bytes all %d", (int)retval, (int)op.len);
        protoman_layer_record_error(layer, PROTOMAN_ERR_NOMEM, PROTOMAN_ERR_NOMEM, "failed to write all data");
        return PROTOMAN_STATE_RETVAL_ERROR;
    }

    /* Data sent, free tx_buf */
    PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer->tx_buf);
    protoman_tx_free(protoman, layer->tx_buf);
    layer->tx_buf = NULL;

    return PROTOMAN_STATE_RETVAL_WAIT;
}

static int _do_init(struct protoman_layer_s *layer)
{
    struct protoman_layer_frame_lv_s *layer_frame_lv = (struct protoman_layer_frame_lv_s *)layer;

    protoman_verbose("");

    layer_frame_lv->length_buf = PROTOMAN_CALLOC(layer_frame_lv->config.length_field_width);
    if (NULL == layer_frame_lv->length_buf) {
        protoman_layer_record_error(layer, PROTOMAN_ERR_NOMEM, PROTOMAN_ERR_NOMEM, "failed to allocate layer_frame_lv->length_buf");
        protoman_err("failed to allocate layer_frame_lv->length_buf");
        return PROTOMAN_STATE_RETVAL_ERROR;
    }
    layer_frame_lv->length_offset = 0;

    PROTOMAN_DEBUG_PRINT_ALLOC(layer->name, layer_frame_lv->config.length_field_width, layer_frame_lv->length_buf);

    return PROTOMAN_STATE_RETVAL_FINISHED;
}

static int _do_read_header(struct protoman_layer_s *layer)
{
    struct protoman_s *protoman = layer->protoman;
    struct protoman_layer_frame_lv_s *layer_frame_lv = (struct protoman_layer_frame_lv_s *)layer;
    struct protoman_config_frame_lv_s *config = &layer_frame_lv->config;
    size_t in_len;

    int retval;
    int state_retval = PROTOMAN_STATE_RETVAL_WAIT;

    protoman_verbose("");

    /* Own input buffer is not empty */
    if (NULL != layer->rx_buf) {
        protoman_verbose("layer->rx_buf is not empty");
        goto exit;
    }

    /* Try read more header */
    struct protoman_io_bytes_s op;
    op.header.type = PROTOMAN_IO_BYTES;
    op.buf = layer_frame_lv->length_buf + layer_frame_lv->length_offset;
    op.len = config->length_field_width - layer_frame_lv->length_offset;

    retval = protoman_layer_read_next(layer, (struct protoman_io_header_s*)&op);

    switch(retval) {
        case PROTOMAN_ERR_NOMEM:
            protoman_layer_record_error(layer, retval, retval, protoman_strstateretval(retval));
            protoman_err("%s", protoman_strstateretval(retval));
            state_retval = PROTOMAN_STATE_RETVAL_ERROR;
            goto exit;

        case PROTOMAN_ERR_WOULDBLOCK:
            protoman_verbose("%s", protoman_strstateretval(retval));
            goto exit;

        case PROTOMAN_ERR_WRONG_IO_TYPE:
            protoman_layer_record_error(layer, retval, retval, protoman_strstateretval(retval));
            protoman_err("%s", protoman_strstateretval(retval));
            state_retval = PROTOMAN_STATE_RETVAL_ERROR;
            goto exit;
    }

    /* Store read bytes to offset counter */
    layer_frame_lv->length_offset += retval;

    /* bytes still to be read? */
    if (layer_frame_lv->length_offset != config->length_field_width) {
        protoman_verbose("partial read %d bytes of %d sized length header", (int)retval, (int)config->length_field_width);
        goto exit;
    }

    /* All bytes read*/
    protoman_debug("completely read %d byte length header", (int)config->length_field_width);

    /* Change state to DATA mode*/
    layer_frame_lv->state = PROTOMAN_FRAME_LV_DATA;

    /* Parse length */
    in_len = _parse_length(layer, layer_frame_lv->length_buf) + config->length_field_offset;

    /* Check length */
    if (in_len > protoman->config.mtu) {
        protoman_err("way too big incoming packet of %d bytes", (int)in_len);
        protoman_layer_record_error(layer, PROTOMAN_ERR_TOO_BIG_PACKET, PROTOMAN_ERR_TOO_BIG_PACKET, "Length given by the LV header is too big for current configuration.");
        state_retval = PROTOMAN_STATE_RETVAL_ERROR;
        goto exit;
    }

    /* Prepare data reading */
    layer->rx_len = in_len;
    layer->rx_offset = 0;

    /* Header reading done */
    state_retval = PROTOMAN_STATE_RETVAL_FINISHED;
exit:
    return state_retval;
}

static int _do_read_data(struct protoman_layer_s *layer)
{
    struct protoman_layer_frame_lv_s *layer_frame_lv = (struct protoman_layer_frame_lv_s *)layer;

    int retval;
    int state_retval = PROTOMAN_STATE_RETVAL_WAIT;

    protoman_verbose("");

    /* If first time reading data, allocate buffer */
    if (NULL == layer_frame_lv->data_buf) {
        layer_frame_lv->data_buf = protoman_rx_alloc(protoman, layer->rx_len);

        /* Temporarily store rx pointer to layer_frame_lv->data_buf and change it to
         * layer->rx_buf when whole packet is read. This prevents above
         * layers from accidentally reading during receiving. */
        if (NULL == layer_frame_lv->data_buf) {
            protoman_debug("failed to allocate layer_frame_lv->data_buf of size %d", (int)layer->rx_len);
            state_retval = PROTOMAN_STATE_RETVAL_AGAIN;
            goto exit;
        }
    }

    PROTOMAN_DEBUG_PRINT_ALLOC(layer->name, layer->rx_len, layer_frame_lv->data_buf);

    /* Try read data */
    struct protoman_io_bytes_s op;
    op.header.type = PROTOMAN_IO_BYTES;
    op.buf = layer_frame_lv->data_buf + layer->rx_offset;
    op.len = layer->rx_len - layer->rx_offset;

    retval = protoman_layer_read_next(layer, (struct protoman_io_header_s*)&op);

    switch(retval) {
        case PROTOMAN_ERR_NOMEM:
            protoman_layer_record_error(layer, retval, retval, protoman_strstateretval(retval));
            protoman_err("%s", protoman_strstateretval(retval));
            state_retval = PROTOMAN_STATE_RETVAL_ERROR;
            goto exit;

        case PROTOMAN_ERR_WOULDBLOCK:
            protoman_verbose("%s", protoman_strstateretval(retval));
            goto exit; /* Wait for DATA_AVAIL events */

        case PROTOMAN_ERR_WRONG_IO_TYPE:
            protoman_layer_record_error(layer, retval, retval, protoman_strstateretval(retval));
            protoman_err("%s", protoman_strstateretval(retval));
            state_retval = PROTOMAN_STATE_RETVAL_ERROR;
            goto exit;
    }

    /* Store read bytes to offset counter */
    layer->rx_offset += retval;

    /* Not all data was read */
    if ((int)layer->rx_offset != layer->rx_len) {
        protoman_verbose("read %d bytes of %d sized data", (int)retval, (int)layer->rx_len);
        goto exit; /* Wait for DATA_AVAIL events */
    }

    /* All data was read, transfer temp buffer to layer to enable reading */
    layer->rx_buf = layer_frame_lv->data_buf;
    layer->rx_offset = 0;

    /* Re-arm header reading (this will only begin after layer->rx_buf is emptied) */
    layer_frame_lv->state = PROTOMAN_FRAME_LV_HEADER;
    layer_frame_lv->data_buf = NULL;

    /* All done here */
    state_retval = PROTOMAN_STATE_RETVAL_FINISHED;
exit:
    return state_retval;
}

static int _do_read(struct protoman_layer_s *layer)
{
    struct protoman_s *protoman = layer->protoman;
    struct protoman_layer_frame_lv_s *layer_frame_lv = (struct protoman_layer_frame_lv_s *)layer;
    int retval;

    protoman_debug("%s", _str_state(layer_frame_lv->state));

    switch(layer_frame_lv->state) {
        case PROTOMAN_FRAME_LV_HEADER:
            retval = _do_read_header(layer);
            if (PROTOMAN_STATE_RETVAL_FINISHED != retval) {
                return retval;
            }

            /* Header read succesfully */
            layer_frame_lv->state = PROTOMAN_FRAME_LV_DATA;
            /* No break; => continue to reading data */

        case PROTOMAN_FRAME_LV_DATA:
            retval = _do_read_data(layer);
            if (PROTOMAN_STATE_RETVAL_FINISHED != retval) {
                return retval;
            }

            /* Data read succesfully */
            layer_frame_lv->state = PROTOMAN_FRAME_LV_HEADER;
            protoman_event(protoman, layer, PROTOMAN_EVENT_DATA_AVAIL, PROTOMAN_EVENT_PRIORITY_LOW, 0);
            break;

        default:
            protoman_err("unknown Frame LV layer state %d", layer_frame_lv->state);
            protoman_layer_record_error(layer, PROTOMAN_ERR_INVALID_INPUT, PROTOMAN_ERR_INVALID_INPUT, "unknown Frame LV layer state");
            return PROTOMAN_STATE_RETVAL_ERROR;
    }

    /* Go to idle state and wait for DATA_AVAIL events from below */
    return PROTOMAN_STATE_RETVAL_WAIT;
}

static int _do_disconnect(struct protoman_layer_s *layer)
{
    struct protoman_layer_frame_lv_s *layer_frame_lv = (struct protoman_layer_frame_lv_s *)layer;

    /* free bufs */
    PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer_frame_lv->data_buf);
    protoman_rx_free(protoman, layer_frame_lv->data_buf);
    layer_frame_lv->data_buf = NULL;

    PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer->rx_buf);
    protoman_rx_free(protoman, layer->rx_buf);
    layer->rx_buf = NULL;

    PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer->tx_buf);
    protoman_tx_free(protoman, layer->tx_buf);
    layer->tx_buf = NULL;

    /* reset receiving state */
    layer_frame_lv->state = PROTOMAN_FRAME_LV_HEADER;

    return PROTOMAN_STATE_RETVAL_FINISHED;
}

static void layer_free(struct protoman_layer_s *layer)
{
    struct protoman_layer_frame_lv_s *layer_frame_lv = (struct protoman_layer_frame_lv_s *)layer;

    /* Do generic free */
    protoman_generic_layer_free(layer);

    /* Do layer specific clean */
    PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer_frame_lv->length_buf);
    protoman_rx_free(protoman, layer_frame_lv->length_buf);
    layer_frame_lv->length_buf = NULL;
}
