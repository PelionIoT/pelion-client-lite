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

#include "mbed-coap/sn_coap_header.h"
#include "mbed-coap/sn_coap_protocol.h"

#include "mbed-protocol-manager/protoman.h"
#include "mbed-protocol-manager/protoman_layer.h"
#include "mbed-protocol-manager/protoman_layer_coap.h"
#define TRACE_GROUP  "CoAP"
#include "include/protoman_internal.h"

static int layer_read(struct protoman_layer_s *layer, struct protoman_io_header_s *operation);
static int layer_write(struct protoman_layer_s *layer, struct protoman_io_header_s *operation);

static int _do_init(struct protoman_layer_s *layer);
static int _do_read(struct protoman_layer_s *layer);
static int _do_write(struct protoman_layer_s *layer);

static const struct protoman_layer_callbacks_s callbacks = {
    NULL,
    &layer_read,
    &layer_write,
    &protoman_generic_layer_event,
    &protoman_generic_layer_free,
    &_do_init,
    NULL,
    &_do_read,
    &_do_write,
    NULL
};

sn_coap_options_list_s *protoman_coap_alloc_options(protoman_layer_id_t id, sn_coap_hdr_s *header)
{
    struct protoman_layer_s *layer = id;
    struct protoman_layer_coap_s *layer_coap = (struct protoman_layer_coap_s *)layer;
    return sn_coap_parser_alloc_options(layer_coap->coap, header);
}

void protoman_coap_free_msg_mem(protoman_layer_id_t id, sn_coap_hdr_s *header)
{
    struct protoman_layer_s *layer = id;
    struct protoman_layer_coap_s *layer_coap = (struct protoman_layer_coap_s *)layer;
    sn_coap_parser_release_allocated_coap_msg_mem(layer_coap->coap, header);
}

static void *coap_malloc(uint16_t size)
{
    return PROTOMAN_MALLOC(size);
}

static void coap_free(void *ptr)
{
    PROTOMAN_FREE(ptr);
}

static int8_t wrapper_coap_rx(sn_coap_hdr_s *coap_header, sn_nsdl_addr_s *some_addr, void *param)
{
    struct protoman_layer_s *layer = param;
    struct protoman_s *protoman = layer->protoman;
    struct protoman_layer_coap_s *layer_coap = (struct protoman_layer_coap_s *)layer;

    if (NULL != layer_coap->resend_coap_hdr) {
        protoman_err("Application didn't read previous COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED msg");
        return -1; /* return value not checked https://github.com/ARMmbed/mbed-coap/blob/64570782a465af7c5eb4e2a245ab88e5bce56bcb/source/sn_coap_protocol.c#L773 */
    }

    layer_coap->resend_coap_hdr = coap_header;
    protoman_event(protoman, layer, PROTOMAN_EVENT_DATA_AVAIL, PROTOMAN_EVENT_PRIORITY_LOW, 0);

    return 0; /* return value not checked https://github.com/ARMmbed/mbed-coap/blob/64570782a465af7c5eb4e2a245ab88e5bce56bcb/source/sn_coap_protocol.c#L773 */
}

/* In mbed-coap wrapper_coap_tx() is used to send data to be sent */
static uint8_t wrapper_coap_tx(uint8_t *buf, uint16_t len, sn_nsdl_addr_s *addr, void *ctx_in)
{
    struct protoman_layer_s *layer = ctx_in;
    struct protoman_s *protoman = layer->protoman;

    protoman_verbose("");

    /* TODO mbed-coap doesn't check return value
     * https://github.com/ARMmbed/mbed-coap/blob/12c87e057e0c6fef523457cd04651fdc9412901f/source/sn_coap_protocol.c#L782
     * https://github.com/ARMmbed/mbed-coap/blob/12c87e057e0c6fef523457cd04651fdc9412901f/source/sn_coap_protocol.c#L974
     * https://github.com/ARMmbed/mbed-coap/blob/12c87e057e0c6fef523457cd04651fdc9412901f/source/sn_coap_protocol.c#L1619
     * https://github.com/ARMmbed/mbed-coap/blob/12c87e057e0c6fef523457cd04651fdc9412901f/source/sn_coap_protocol.c#L1706
     * https://github.com/ARMmbed/mbed-coap/blob/12c87e057e0c6fef523457cd04651fdc9412901f/source/sn_coap_protocol.c#L1873
     * https://github.com/ARMmbed/mbed-coap/blob/12c87e057e0c6fef523457cd04651fdc9412901f/source/sn_coap_protocol.c#L1989
     */

    if (NULL != layer->tx_buf) {
        protoman_verbose("ignoring write from CoAP library as own buffer is full");
        return 0; /* CoAP doesn't check or have any error values for tx */
    }

    layer->tx_buf = protoman_tx_alloc(protoman, len);
    if (NULL == layer->tx_buf) {
        protoman_warn("failed to allocate enough memory for CoAP TX request");
        return 0; /* CoAP doesn't check or have any error values for tx */
    }

    protoman_verbose("CoAP tx succeeded, copied %"PRIu16" bytes to self", len);
    memcpy(layer->tx_buf, buf, len);
    layer->tx_len = len;
    layer->tx_offset = 0;

    protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
    return 0;
}

void protoman_add_layer_coap(struct protoman_s *protoman, struct protoman_layer_s *layer)
{
    struct protoman_layer_coap_s *layer_coap = (struct protoman_layer_coap_s *)layer;

    layer->name = "CoAP"; // must be set before first print from this layer

    protoman_debug("");

    layer->callbacks = &callbacks;

    /* TODO get this address frm socket layer */
    memset(&layer_coap->dummy_addr, 0, sizeof(sn_nsdl_addr_s));
    layer_coap->dummy_addr.type = SN_NSDL_ADDRESS_TYPE_IPV4;
    layer_coap->dummy_addr.port = 5684;
    layer_coap->dummy_addr.addr_len = 4;
    layer_coap->dummy_addr.addr_ptr = PROTOMAN_MALLOC(4);
    layer_coap->dummy_addr.addr_ptr[0] = 127;
    layer_coap->dummy_addr.addr_ptr[1] = 0;
    layer_coap->dummy_addr.addr_ptr[2] = 0;
    layer_coap->dummy_addr.addr_ptr[3] = 1;

    protoman_add_layer(protoman, layer);
}

/* TODO _do_read() seems like common function for protoman */
static int _do_read(struct protoman_layer_s *layer)
{
    struct protoman_s *protoman = layer->protoman;
    struct protoman_layer_coap_s *layer_coap = (struct protoman_layer_coap_s *)layer;

    protoman_verbose("");

    if (NULL != layer->rx_buf) {
        protoman_verbose("layer->rx_buf still not processed");
        return PROTOMAN_STATE_RETVAL_WAIT; /* Data is not read yet, dont do anything */
    }

    /* Allocate memory for read operation */
    layer->rx_buf = protoman_rx_alloc(protoman, protoman->config.mtu);
    if (NULL == layer->rx_buf) {
        protoman_warn("failed to allocate layer->rx_buf");
        return PROTOMAN_STATE_RETVAL_AGAIN;
    }

    /* Get data from underlaying layer */
    struct protoman_io_bytes_s op_bytes;
    op_bytes.header.type = PROTOMAN_IO_BYTES;
    op_bytes.buf = layer->rx_buf;
    op_bytes.len = protoman->config.mtu;
    int retval = protoman_layer_read_next(layer, (struct protoman_io_header_s *)&op_bytes);

    /* Parse read error */
    if (retval < 0) {
        switch (retval) {
            case PROTOMAN_ERR_WOULDBLOCK:
                protoman_verbose("protoman_layer_read_next() returned PROTOMAN_ERR_WOULDBLOCK");
                protoman_rx_free(protoman, layer->rx_buf);
                layer->rx_buf = NULL;
                return PROTOMAN_STATE_RETVAL_WAIT;
            case PROTOMAN_ERR_NOMEM:
                protoman_warn("protoman_layer_read_next() returned PROTOMAN_ERR_NOMEM");
                protoman_rx_free(protoman, layer->rx_buf);
                layer->rx_buf = NULL;
                return PROTOMAN_STATE_RETVAL_AGAIN;
            case PROTOMAN_ERR_WRONG_IO_TYPE:
                protoman_err("protoman_layer_read_next() returned PROTOMAN_ERR_WRONG_IO_TYPE");
                protoman_rx_free(protoman, layer->rx_buf);
                layer->rx_buf = NULL;
                return PROTOMAN_STATE_RETVAL_ERROR;
            default:
                protoman_err("protoman_layer_read_next() returned unknown value %d", retval);
                protoman_rx_free(protoman, layer->rx_buf);
                layer->rx_buf = NULL;
                return PROTOMAN_STATE_RETVAL_ERROR;
        }
    }

    /* Read was OK */
    layer->rx_len = retval;
    layer->rx_offset = 0;

    /* CoAP parse */
    layer_coap->rx_coap_hdr = sn_coap_protocol_parse(layer_coap->coap, &layer_coap->dummy_addr, layer->rx_len, layer->rx_buf, layer);

    /* Clear incoming data buffer from memory */
    memset(layer->rx_buf, 0, layer->rx_len);

    /* Message parsed you can free it now */
    protoman_rx_free(protoman, layer->rx_buf);
    layer->rx_buf = NULL;

    /* CoAP header parsing failed */
    if (NULL == layer_coap->rx_coap_hdr) {
        protoman_warn("sn_coap_protocol_parse() failed with NULL");
        return PROTOMAN_STATE_RETVAL_WAIT; /* Trash message but keep going */
    }

    /* Don't pass empty ACKs to application */
    if (COAP_MSG_TYPE_ACKNOWLEDGEMENT == layer_coap->rx_coap_hdr->msg_type && COAP_MSG_CODE_EMPTY == layer_coap->rx_coap_hdr->msg_code) {
        protoman_verbose("received empty CoAP ACK no use to pass it to application"); /* already processed by sn_coap_protocol_parse() above */
        sn_coap_parser_release_allocated_coap_msg_mem(layer_coap->coap, layer_coap->rx_coap_hdr);
        layer_coap->rx_coap_hdr = NULL;
        return PROTOMAN_STATE_RETVAL_WAIT;
    }

    /* Data available in (layer_coap->rx_coap_hdr) CoAP layer */
    protoman_event(protoman, layer, PROTOMAN_EVENT_DATA_AVAIL, PROTOMAN_EVENT_PRIORITY_LOW, 0);
    return PROTOMAN_STATE_RETVAL_WAIT;
}

static int _do_write(struct protoman_layer_s *layer)
{
    struct protoman_s *protoman = layer->protoman;
    struct protoman_layer_coap_s *layer_coap = (struct protoman_layer_coap_s *)layer;

    protoman_verbose("");

    /* No data */
    if (NULL == layer->tx_buf) {
        protoman_verbose("no data in layer->tx_buf to process");
        return PROTOMAN_STATE_RETVAL_WAIT;
    }

    /* Write data to next layer */
    struct protoman_io_bytes_s op_bytes;
    op_bytes.header.type = PROTOMAN_IO_BYTES;
    op_bytes.buf = layer->tx_buf + layer->tx_offset;
    op_bytes.len = layer->tx_len - layer->tx_offset;
    int retval = protoman_layer_write_next(layer, (struct protoman_io_header_s *)&op_bytes);

    /* Error translation */
    if (retval < 0) {
        switch (retval) {
            case PROTOMAN_ERR_WOULDBLOCK:
                protoman_verbose("protoman_layer_write_next() returned PROTOMAN_ERR_WOULDBLOCK");
                /* No PROTOMAN_EVENT_RUN scheduled here as there should be PROTOMAN_EVENT_DATA_AVAIL
                 * or PROTOMAN_EVENT_DATA_WRITTEN coming from below layer */
                return PROTOMAN_STATE_RETVAL_WAIT;

            case PROTOMAN_ERR_NOMEM:
                protoman_warn("protoman_layer_write_next() returned PROTOMAN_ERR_NOMEM");
                protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 10);
                return PROTOMAN_STATE_RETVAL_AGAIN;

            case PROTOMAN_ERR_WRONG_IO_TYPE:
                protoman_err("protoman_layer_write_next() returned PROTOMAN_ERR_WRONG_IO_TYPE");
                return PROTOMAN_STATE_RETVAL_ERROR;

            default:
                protoman_err("protoman_layer_write_next() returned unknown value %d", retval);
                protoman_tx_free(protoman, layer->tx_buf);
                return PROTOMAN_STATE_RETVAL_ERROR;
        }
    }

    layer->tx_offset += retval;

    /* Was all data sent? */
    if ((int)layer->tx_offset == layer->tx_len) {
        protoman_verbose("write done, wrote %d of %zu bytes to next layer", retval, layer->tx_len);
        protoman_tx_free(protoman, layer->tx_buf);
        layer->tx_buf = NULL;
        layer->tx_len = 0;
        layer->tx_offset = 0;
    } else {
        protoman_verbose("write continue, wrote %d of %zu bytes to next layer", retval, layer->tx_len);
        protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
    }

    /* CoAP resends */
    if (-1 == sn_coap_protocol_exec(layer_coap->coap, layer_coap->coap_time)) {
        protoman_err("sn_coap_protocol_exec() failed");
        return PROTOMAN_STATE_RETVAL_ERROR;
    }

    return PROTOMAN_STATE_RETVAL_WAIT;
}

static int _do_init(struct protoman_layer_s *layer)
{
    struct protoman_layer_coap_s *layer_coap = (struct protoman_layer_coap_s *)layer;

    protoman_verbose("");

    layer_coap->coap = sn_coap_protocol_init(coap_malloc, coap_free, &wrapper_coap_tx, &wrapper_coap_rx);

    return PROTOMAN_STATE_RETVAL_FINISHED;
}

static int layer_read(struct protoman_layer_s *layer, struct protoman_io_header_s *operation)
{
    struct protoman_layer_coap_s *layer_coap = (struct protoman_layer_coap_s *)layer;
    struct protoman_io_coap_s *op = (struct protoman_io_coap_s *)operation;

    protoman_verbose("");

    /* Check given IO type */
    if (PROTOMAN_IO_COAP != op->header.type) {
        protoman_err("PROTOMAN_ERR_WRONG_IO_TYPE");
        return PROTOMAN_ERR_WRONG_IO_TYPE;
    }

    /* If re-sending failed return that header */
    if (NULL != layer_coap->resend_coap_hdr) {
        protoman_verbose("returning re-send header");
        op->coap_header = layer_coap->resend_coap_hdr;
        layer_coap->resend_coap_hdr = NULL; /* Freeing is now applications responsibility */
        return sn_coap_builder_calc_needed_packet_data_size(op->coap_header);
    }

    /* Check WOULDBLOCK */
    if (NULL != layer_coap->rx_coap_hdr) {
        protoman_verbose("WOULDBLOCK");
        op->coap_header = layer_coap->rx_coap_hdr;
        layer_coap->rx_coap_hdr = NULL; /* Freeing is now applications responsibility */
        return sn_coap_builder_calc_needed_packet_data_size(op->coap_header);
    }

    /* No data to return */
    return PROTOMAN_ERR_WOULDBLOCK;
}

static int layer_write(struct protoman_layer_s *layer, struct protoman_io_header_s *operation)
{
    struct protoman_s *protoman = layer->protoman;
    struct protoman_layer_coap_s *layer_coap = (struct protoman_layer_coap_s *)layer;
    struct protoman_io_coap_s *op = (struct protoman_io_coap_s *)operation;

    protoman_verbose("");

    /* Check given IO type */
    if (PROTOMAN_IO_COAP != op->header.type) {
        protoman_err("PROTOMAN_ERR_WRONG_IO_TYPE");
        return PROTOMAN_ERR_WRONG_IO_TYPE;
    }

    /* Check WOULDBLOCK */
    if (NULL != layer->tx_buf) {
        protoman_verbose("WOULDBLOCK");
        return PROTOMAN_ERR_WOULDBLOCK;
    }

    /*  Allocate and build message  */
    /* ---------------------------- */
    layer->tx_offset = 0;
    layer->tx_len = sn_coap_builder_calc_needed_packet_data_size(op->coap_header);
    layer->tx_buf = protoman_tx_alloc(protoman, layer->tx_len);
    if (NULL == layer->tx_buf) {
        protoman_warn("cannot allocate layer->tx_buf");
        return PROTOMAN_ERR_NOMEM;
    }

    int retval = sn_coap_protocol_build(layer_coap->coap, &layer_coap->dummy_addr, layer->tx_buf, op->coap_header, layer);
    switch (retval) {
        case -1:
            protoman_warn("sn_coap_protocol_build() had failure with CoAP header structure");
            PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer->tx_buf);
            protoman_tx_free(protoman, layer->tx_buf);
            return PROTOMAN_ERR_INVALID_INPUT;
        case -2:
            protoman_err("sn_coap_protocol_build() was given a NULL value");
            PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer->tx_buf);
            protoman_tx_free(protoman, layer->tx_buf);
            return PROTOMAN_ERR_INVALID_INPUT;
        case -3:
            protoman_warn("sn_coap_protocol_build() had failure with reset message");
            PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer->tx_buf);
            protoman_tx_free(protoman, layer->tx_buf);
            return PROTOMAN_ERR_INVALID_INPUT;
    }
    protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
    return 0;
}
