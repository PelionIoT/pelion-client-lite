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

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/*
 * Some functions can be inlined, and definitions are in protoman_layer.h.
 * Define PROTOMAN_FN before including it to generate external definitions.
 */
#define PROTOMAN_FN extern

#include "mbed-protocol-manager/protoman.h"
#include "mbed-protocol-manager/protoman_layer.h"
#define TRACE_GROUP  "Pgen" /* ProtocolManager Generic */
#include "include/protoman_internal.h"


static const struct protoman_layer_run_delays_s _generic_delays = {
    0,     /* do_init, called if _do_init() */
    200,   /* do_connect */
    10,    /* do_read */
    200,   /* do_write */
    0,     /* do_disconnect */
    200,   /* do_pause */
    200    /* do_resume */
};

#ifdef PROTOMAN_VERBOSE
void _protoman_layer_trace_error(struct protoman_layer_s *layer,
                                int protoman_error,
                                int specific_error,
                                const char *specific_error_str)
{
#ifdef PROTOMAN_ERROR_STRING
    protoman_verbose("setting protoman_error to %s and specific_error to %d (%s)", protoman_strerror(protoman_error), specific_error, specific_error_str);
#else
    (void)specific_error_str;
    protoman_verbose("setting protoman_error to %s and specific_error to %d", protoman_strerror(protoman_error), specific_error);
#endif // PROTOMAN_ERROR_STRING
}
#endif


/* Generated appropriate events upwards */
void protoman_layer_state_change(struct protoman_layer_s *layer, int new_state)
{
    struct protoman_s *protoman = layer->protoman;

    protoman_verbose("");

    /* Apply new state */
    int old_state = layer->current_state;
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

    protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);

    int event_id;
    switch (new_state) {
        case PROTOMAN_STATE_INITIALIZED:
            event_id = PROTOMAN_EVENT_INITIALIZED;
            break;
        case PROTOMAN_STATE_CONNECTED:
            event_id = PROTOMAN_EVENT_CONNECTED;
            break;
        case PROTOMAN_STATE_DISCONNECTED:
            event_id = PROTOMAN_EVENT_DISCONNECTED;
            break;
        case PROTOMAN_STATE_PAUSED:
            event_id = PROTOMAN_EVENT_PAUSED;
            break;
        case PROTOMAN_STATE_RESUMED:
            event_id = PROTOMAN_EVENT_RESUMED;
            break;
        case PROTOMAN_STATE_ERRORED:
            event_id = PROTOMAN_EVENT_ERROR;
            break;
        default:
            goto no_event;
    }
    protoman_event(protoman, layer, event_id, PROTOMAN_EVENT_PRIORITY_LOW, 0);

no_event:
    layer->current_state = new_state;
}

void protoman_generic_layer_event(struct protoman_layer_s *layer, int event_id)
{
    struct protoman_s *protoman = layer->protoman;

    protoman_verbose("%s", protoman_strevent(event_id));

    switch (event_id) {
        case PROTOMAN_EVENT_INITIALIZED:
        case PROTOMAN_EVENT_RUN:
        case PROTOMAN_EVENT_DATA_AVAIL:
        case PROTOMAN_EVENT_DATA_WRITTEN:
            /* break to layer_run() below */
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

        case PROTOMAN_EVENT_PAUSED:
            layer->target_state = PROTOMAN_STATE_PAUSED;
            break;

        case PROTOMAN_EVENT_RESUMED:
            layer->target_state = PROTOMAN_STATE_RESUMED;
            break;

        case PROTOMAN_EVENT_ERROR:
            return;

        default:
            protoman_err("not implemented event_id %d", event_id);
            layer->current_state = PROTOMAN_STATE_ERRORED;
            return;
    }
    protoman_generic_layer_run(layer);
}

void protoman_generic_layer_run(struct protoman_layer_s *layer)
{
    struct protoman_s *protoman = layer->protoman;
    int retval;

    /* Use generic delays if no layer specific delays are defined. */
    const struct protoman_layer_run_delays_s *delays = &_generic_delays;
    if (NULL != layer->delays){
        delays = layer->delays;
    }

    protoman_verbose("%s (>> %s)",
        protoman_strstate(layer->current_state),
        protoman_strstate(layer->target_state));

    uint32_t delay;

    switch (layer->current_state) {
        case PROTOMAN_STATE_INITIALIZING:
            if (NULL != layer->callbacks->state_do_init) {
                retval = layer->callbacks->state_do_init(layer);
                switch (retval) {
                    case PROTOMAN_STATE_RETVAL_FINISHED:
                        break;

                    case PROTOMAN_STATE_RETVAL_AGAIN:
                        delay = delays->do_init;
                        goto do_event;

                    case PROTOMAN_STATE_RETVAL_ERROR:
                    default:
                        protoman_err("state_do_init() returned %s (%d)", protoman_strstateretval(retval), retval);
                        protoman_layer_state_change(layer, PROTOMAN_STATE_ERRORING);
                        return;
                }
            }

            protoman_info("initialized");
            protoman_layer_state_change(layer, PROTOMAN_STATE_INITIALIZED);
            break;

        case PROTOMAN_STATE_CONNECTING:
            switch (layer->target_state) {
                case PROTOMAN_STATE_DISCONNECTED:
                    protoman_verbose("disconnecting");
                    protoman_layer_state_change(layer, PROTOMAN_STATE_DISCONNECTING);
                    return;
                case PROTOMAN_STATE_PAUSED:
                    /* Disconnecting when pausing while connecting was not finished */
                    protoman_debug("force disconnecting on pausing while connecting");
                    layer->target_state = PROTOMAN_STATE_DISCONNECTED;
                    protoman_layer_state_change(layer, PROTOMAN_STATE_DISCONNECTING);
                    return;
            }

            if (NULL != layer->callbacks->state_do_connect) {
                retval = layer->callbacks->state_do_connect(layer);
                switch (retval) {
                    case PROTOMAN_STATE_RETVAL_FINISHED:
                        break;

                    case PROTOMAN_STATE_RETVAL_AGAIN:
                        delay = delays->do_connect;
                        goto do_event;

                    case PROTOMAN_STATE_RETVAL_WAIT:
                        /* Do nothing and wait for PROTOMAN_EVENT_DATA_WRITTEN/AVAILABLE */
                        return;

                    case PROTOMAN_STATE_RETVAL_DISCONNECT:
                        layer->target_state = PROTOMAN_EVENT_DISCONNECTED;
                        protoman_layer_state_change(layer, PROTOMAN_STATE_DISCONNECTING);
                        return;

                    case PROTOMAN_STATE_RETVAL_ERROR:
                    default:
                        protoman_err("state_do_connect() returned %s (%d)", protoman_strstateretval(retval), retval);
                        protoman_layer_state_change(layer, PROTOMAN_STATE_ERRORING);
                        return;
                }
            }

            protoman_info("connected");
            protoman_layer_state_change(layer, PROTOMAN_STATE_CONNECTED);
            break;

        case PROTOMAN_STATE_RESUMED:
        case PROTOMAN_STATE_CONNECTED:
            switch (layer->target_state) {
                case PROTOMAN_STATE_DISCONNECTED:
                    protoman_verbose("disconnecting");
                    protoman_layer_state_change(layer, PROTOMAN_STATE_DISCONNECTING);
                    return;
                case PROTOMAN_STATE_PAUSED:
                    protoman_verbose("pausing");
                    protoman_layer_state_change(layer, PROTOMAN_STATE_PAUSING);
                    return;
            }

            /* Read */
            if (NULL != layer->callbacks->state_do_read) {
                retval = layer->callbacks->state_do_read(layer);
                switch (retval) {
                    case PROTOMAN_STATE_RETVAL_WAIT:
                        /* OK -- continue */
                        break;

                    case PROTOMAN_STATE_RETVAL_AGAIN:
                        protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW,
                                       delays->do_read);
                        break;

                    case PROTOMAN_STATE_RETVAL_DISCONNECT:
                        layer->target_state = PROTOMAN_EVENT_DISCONNECTED;
                        protoman_layer_state_change(layer, PROTOMAN_STATE_DISCONNECTING);
                        return;

                    case PROTOMAN_STATE_RETVAL_ERROR:
                    default:
                        if (PROTOMAN_ERR_CONNECTION_CLOSED == layer->protoman_error) {
                            protoman_info("state_do_read() connection closed");
                        } else {
                            protoman_err("state_do_read() returned %s (%d)", protoman_strstateretval(retval), retval);
                        }
                        protoman_layer_state_change(layer, PROTOMAN_STATE_ERRORING);
                        return;
                }
            }

            /* Write */
            if (NULL != layer->callbacks->state_do_write) {
                retval = layer->callbacks->state_do_write(layer);
                switch (retval) {
                    case PROTOMAN_STATE_RETVAL_WAIT:
                        /* OK -- continue */
                        break;

                    case PROTOMAN_STATE_RETVAL_AGAIN:
                        protoman_verbose("state_do_write() returned %s, call again in %d ms",
                                         protoman_strstateretval(retval),
                                         (int)delays->do_write);
                        delay = delays->do_write;
                        goto do_event;

                    case PROTOMAN_STATE_RETVAL_DISCONNECT:
                        layer->target_state = PROTOMAN_EVENT_DISCONNECTED;
                        protoman_layer_state_change(layer, PROTOMAN_STATE_DISCONNECTING);
                        return;

                    case PROTOMAN_STATE_RETVAL_ERROR:
                    default:
                        protoman_err("state_do_write() returned %s (%d)", protoman_strstateretval(retval), retval);
                        protoman_layer_state_change(layer, PROTOMAN_STATE_ERRORING);
                        return;
                }
            }
            break;

        case PROTOMAN_STATE_DISCONNECTING:
            if (NULL != layer->callbacks->state_do_disconnect) {
                retval = layer->callbacks->state_do_disconnect(layer);
                switch (retval) {
                    case PROTOMAN_STATE_RETVAL_FINISHED:
                        break;

                    case PROTOMAN_STATE_RETVAL_AGAIN:
                        delay = delays->do_disconnect;
                        goto do_event;

                    case PROTOMAN_STATE_RETVAL_WAIT:
                        /* wait for PROTOMAN_EVENT_DATA_WRITTEN/AVAILABLE event */
                        return;

                    case PROTOMAN_STATE_RETVAL_ERROR:
                    default:
                        protoman_err("state_do_disconnect() returned %s (%d)", protoman_strstateretval(retval), retval);
                        protoman_layer_state_change(layer, PROTOMAN_STATE_ERRORING);
                        return;
                }
            }

            protoman_info("disconnected");
            protoman_layer_state_change(layer, PROTOMAN_STATE_DISCONNECTED);
            break;

        case PROTOMAN_STATE_PAUSING:
            if (NULL != layer->callbacks->state_do_pause) {
                retval = layer->callbacks->state_do_pause(layer);
                switch (retval) {
                    case PROTOMAN_STATE_RETVAL_FINISHED:
                        break;

                    case PROTOMAN_STATE_RETVAL_AGAIN:
                        delay = delays->do_pause;
                        goto do_event;

                    case PROTOMAN_STATE_RETVAL_WAIT:
                        /* wait for PROTOMAN_EVENT_DATA_WRITTEN/AVAILABLE event */
                        return;

                    case PROTOMAN_STATE_RETVAL_ERROR:
                    default:
                        protoman_err("state_do_pause() returned %s (%d)", protoman_strstateretval(retval), retval);
                        protoman_layer_state_change(layer, PROTOMAN_STATE_ERRORING);
                        return;
                }
            }

            protoman_info("paused");
            protoman_layer_state_change(layer, PROTOMAN_STATE_PAUSED);
            break;

        case PROTOMAN_STATE_PAUSED:
            switch (layer->target_state) {
                case PROTOMAN_STATE_RESUMED:
                    protoman_verbose("resuming");
                    protoman_layer_state_change(layer, PROTOMAN_STATE_RESUMING);
                    break;
            }
            break;

        case PROTOMAN_STATE_RESUMING:
            if (layer->target_state == PROTOMAN_STATE_PAUSED) {
                protoman_verbose("pausing");
                protoman_layer_state_change(layer, PROTOMAN_STATE_PAUSING);
            } else if (layer->target_state == PROTOMAN_STATE_RESUMED) {
                if (NULL != layer->callbacks->state_do_resume) {
                    retval = layer->callbacks->state_do_resume(layer);
                    switch (retval) {
                        case PROTOMAN_STATE_RETVAL_FINISHED:
                            break;

                        case PROTOMAN_STATE_RETVAL_AGAIN:
                            delay = delays->do_resume;
                            goto do_event;

                        case PROTOMAN_STATE_RETVAL_WAIT:
                            /* wait for PROTOMAN_EVENT_DATA_WRITTEN/AVAILABLE event */
                            return;

                        case PROTOMAN_STATE_RETVAL_ERROR:
                        default:
                            protoman_err("state_do_resume() returned %s (%d)", protoman_strstateretval(retval), retval);
                            protoman_layer_state_change(layer, PROTOMAN_STATE_ERRORING);
                            return;
                    }
                }

                protoman_info("resumed");
                protoman_layer_state_change(layer, PROTOMAN_STATE_RESUMED);
            }
            break;

        case PROTOMAN_STATE_INITIALIZED:
        case PROTOMAN_STATE_DISCONNECTED:
            switch (layer->target_state) {
                case PROTOMAN_STATE_CONNECTED:
                    protoman_verbose("connecting");
                    protoman_layer_state_change(layer, PROTOMAN_STATE_CONNECTING);
                    break;

                case PROTOMAN_STATE_DISCONNECTED:
                    if (layer->current_state == PROTOMAN_STATE_INITIALIZED) {
                        protoman_verbose("disconnecting");
                        protoman_layer_state_change(layer, PROTOMAN_STATE_DISCONNECTING);
                    }
                    break;

                case PROTOMAN_STATE_PAUSED:
                    protoman_verbose("pausing");
                    protoman_layer_state_change(layer, PROTOMAN_STATE_PAUSING);
                    break;

                case PROTOMAN_STATE_RESUMED:
                    /* Connecting when resuming from initialized or disconnected state  */
                    protoman_debug("force connecting on resuming from %s", protoman_strstate(layer->current_state));
                    layer->target_state = PROTOMAN_STATE_CONNECTED;
                    protoman_layer_state_change(layer, PROTOMAN_STATE_CONNECTING);
                    break;
            }
            break;

        case PROTOMAN_STATE_ERRORING:
            switch (layer->target_state) {
                case PROTOMAN_STATE_PAUSED:
                    protoman_verbose("pausing");
                    protoman_layer_state_change(layer, PROTOMAN_STATE_PAUSING);
                    break;
                default:
                    if (PROTOMAN_ERR_CONNECTION_CLOSED == layer->protoman_error) {
                        protoman_info("PROTOMAN_STATE_ERRORING, connection closed");
                    } else {
                        protoman_err("PROTOMAN_STATE_ERRORING %s (%d)",
                                    protoman_strstateretval(protoman_get_layer_error(protoman)),
                                    protoman_get_layer_error(protoman));
                    }
                    protoman_layer_state_change(layer, PROTOMAN_STATE_ERRORED);
            }
            break;

        case PROTOMAN_STATE_ERRORED:
            break;

        default:
            protoman_err("unknown state: %d", layer->current_state);
            assert(false);
    }

    return;

do_event:
    protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, delay);
}

int protoman_generic_bytes_layer_write(struct protoman_layer_s *layer, struct protoman_io_header_s *operation)
{
    struct protoman_s *protoman = layer->protoman;
    struct protoman_io_bytes_s *op = (struct protoman_io_bytes_s *)operation;

    protoman_verbose("");

    /* Check given IO type */
    if (PROTOMAN_IO_BYTES != op->header.type && PROTOMAN_IO_ZEROCOPY != op->header.type) {
        protoman_err("PROTOMAN_LAYER_WRONG_IO_TYPE");
        return PROTOMAN_ERR_WRONG_IO_TYPE;
    }

    /* Check for NULL data */
    if (NULL == op->buf) {
        protoman_err("trying to write from NULL, PROTOMAN_ERR_INVALID_INPUT");
        return PROTOMAN_ERR_INVALID_INPUT;
    }

    /* Check WOULDBLOCK */
    if (NULL != layer->tx_buf) {
        protoman_verbose("PROTOMAN_LAYER_WOULDBLOCK");
        return PROTOMAN_ERR_WOULDBLOCK;
    }

    if (PROTOMAN_IO_ZEROCOPY == op->header.type) {

        layer->tx_buf = op->buf;

    } else {

        /* Allocate and copy incoming data */
        layer->tx_buf = protoman_tx_alloc(protoman, op->len);
        if (NULL == layer->tx_buf) {
            protoman_warn("PROTOMAN_ERR_NOMEM");
            return PROTOMAN_ERR_NOMEM;
        }

        memcpy(layer->tx_buf, op->buf, op->len);

    }

    PROTOMAN_DEBUG_PRINT_ALLOC(layer->name, op->len, layer->tx_buf);

    layer->tx_len = op->len;
    layer->tx_offset = 0;


    /* Schedule layer run event to process data (send) */
    protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
    return op->len;
}

int protoman_generic_bytes_layer_read(struct protoman_layer_s *layer, struct protoman_io_header_s *operation)
{
    struct protoman_s *protoman = layer->protoman;
    struct protoman_io_bytes_s *op = (struct protoman_io_bytes_s *)operation;
    size_t copy_len = 0;
    size_t data_avail;

    protoman_verbose("");

    /* Check given IO type */
    if (PROTOMAN_IO_BYTES != op->header.type && PROTOMAN_IO_ZEROCOPY != op->header.type) {
        protoman_err("PROTOMAN_LAYER_WRONG_IO_TYPE");
        return PROTOMAN_ERR_WRONG_IO_TYPE;
    }

    /* Check WOULDBLOCK */
    if (NULL == layer->rx_buf) {
        protoman_verbose("WOULDBLOCK");
        return PROTOMAN_ERR_WOULDBLOCK;
    }

    if (PROTOMAN_IO_ZEROCOPY == op->header.type) {
        op->buf = layer->rx_buf;
        layer->rx_buf = NULL;
        /* Schedule runtime for the layer now that the buffers are free. This is needed to read blocked data from below */
        protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
        return layer->rx_len;
    }

    /* Copy data to given place */
    copy_len = op->len;
    data_avail = layer->rx_len - layer->rx_offset;
    if (op->len > data_avail) {
        copy_len = data_avail;
    }

    /* Check for NULL destination */
    if (NULL == op->buf) {
        protoman_err("trying to read to NULL, PROTOMAN_ERR_INVALID_INPUT");
        return PROTOMAN_ERR_INVALID_INPUT;
    }

    /* Copy data to caller from internal buffer */
    memcpy(op->buf, layer->rx_buf + layer->rx_offset, copy_len);

    /* Clear incoming data buffer from memory */
    memset(layer->rx_buf + layer->rx_offset, 0, copy_len);
    layer->rx_offset += copy_len;

    /* Check if all data is read */
    if ((int)layer->rx_offset == layer->rx_len) {
        protoman_debug("read done, %d of %d bytes were read", (int)copy_len, (int)layer->rx_len);
        PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer->rx_buf);
        protoman_rx_free(protoman, layer->rx_buf);
        layer->rx_buf = NULL;

        /* Schedule runtime for the layer now that the buffers are free. This is needed to read blocked data from below */
        protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
    } else {
        /* TODO do we need to handle this partial read somehow here? */
        protoman_verbose("read partial, %d of %d bytes were read", (int)copy_len, (int)layer->rx_len);
    }

    /* Return copied bytes */
    return copy_len;
}

void protoman_generic_layer_free(struct protoman_layer_s *layer)
{
    protoman_verbose("");

    PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer->rx_buf);
    protoman_rx_free(layer->protoman, layer->rx_buf);
    layer->rx_buf = NULL;

    PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer->tx_buf);
    protoman_tx_free(layer->protoman, layer->tx_buf);
    layer->tx_buf = NULL;
}

ssize_t protoman_layer_write_next(struct protoman_layer_s *layer, struct protoman_io_header_s *operation)
{
    struct protoman_layer_s *next_layer = ns_list_get_next(&layer->protoman->layers, layer);

    protoman_verbose("write to %s layer", next_layer->name);

    return next_layer->callbacks->layer_write(next_layer, operation);
}

ssize_t protoman_layer_read_next(struct protoman_layer_s *layer, struct protoman_io_header_s *operation)
{
    struct protoman_layer_s *next_layer = ns_list_get_next(&layer->protoman->layers, layer);

    protoman_verbose("read from %s layer", next_layer->name);

    return next_layer->callbacks->layer_read(next_layer, operation);
}
