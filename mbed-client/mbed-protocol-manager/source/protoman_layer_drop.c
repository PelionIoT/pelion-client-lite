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
#include "mbed-protocol-manager/protoman_layer_drop.h"
#define TRACE_GROUP  "Pdrp"
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

void protoman_add_layer_drop(struct protoman_s *protoman, struct protoman_layer_s *layer)
{
    struct protoman_layer_drop_s *layer_drop = (struct protoman_layer_drop_s *)layer;
#ifdef MBED_CONF_MBED_TRACE_ENABLE
    layer->name = "Drop"; // must be set before first print from this layer
#else
    layer->name = NULL;
#endif

    protoman_debug("");

    layer->callbacks = &callbacks;
    layer->no_statemachine = true;
    layer->config = &layer_drop->config;

    protoman_add_layer(protoman, layer);
}

static bool _drop_by_drop_count(struct protoman_layer_s *layer, struct protoman_drop_entry_s *entry)
{
    if (entry->packet_drops < 0) {
        /* Negative count, don't drop */
        protoman_debug("all dropped");
        return false;
    } else if (entry->packet_drops == 0) {
        /* 0 means infinite dropping */
    } else if (entry->packet_drops == 1) {
        /* Last drop, jump to -1 to disable dropping */
        protoman_verbose("1 left");
        entry->packet_drops = -1;
    } else {
        protoman_verbose("%zd left", entry->packet_drops);
        entry->packet_drops--;
    }
    return true;
}

static bool _drop_by_packet_skips(struct protoman_layer_s *layer, struct protoman_drop_entry_s *entry)
{
    /* entry->packet_skips counts to 0 and then returns true */
    if (entry->packet_skips) {
        protoman_verbose("%zu [%s] packets still to skip", entry->packet_skips, mbed_trace_array(entry->match_buf, entry->match_len));
        entry->packet_skips--;
        return false;
    }
    return true;
}

static bool _drop_by_match(struct protoman_layer_s *layer, struct protoman_io_bytes_s *operation, struct protoman_drop_entry_s *entry)
{
    /* No match pattern defined -> eligible for dropping */
    if (entry->match_len == 0) {
        return true;
    }

    /* If packet length is not zero and packet length does not match actual packet length, it cannot be dropped */
    if (entry->packet_len != 0 && entry->packet_len != operation->len) {
        return false;
    }

    /* Check if comparison can be done */
    if ((entry->match_len + entry->match_offset) > operation->len) {
        /* memcmp would overflow */
        protoman_verbose("memcmp would overflow (%zu > %zu)", entry->match_len + entry->match_offset, operation->len);
        return false;
    }

    /* Check if content matches */
    if (0 != memcmp(entry->match_buf, operation->buf + entry->match_offset, entry->match_len)) {
        return false;
    }

    /* Packet length and content matched -> drop */
    return true;
}

static bool _drop_packet(struct protoman_layer_s *layer, struct protoman_io_bytes_s *operation, struct protoman_drop_entries_s *entries)
{
    struct protoman_drop_entry_s *entry;
    bool drop_by_content = false;
    bool drop_by_skips = false;
    bool drop_by_count = false;

    for (size_t i = 0; i < entries->count; i++) {
        entry = &entries->list[i];

        /* Not a match? */
        drop_by_content = _drop_by_match(layer, operation, entry);
        if (!drop_by_content) {
            continue;
        }

        /* Not yet skipped enough of matched packets? */
        drop_by_skips = _drop_by_packet_skips(layer, entry);
        if (!drop_by_skips) {
            continue;
        }

        /* Dropped enough packets? */
        drop_by_count = _drop_by_drop_count(layer, entry);
        if (!drop_by_count) {
            continue;
        }

        /* match found, drop packet */
        protoman_warn("dropping content=%s [%s], skips=%s, count=%s",
            drop_by_content ? "true" : "false",
            mbed_trace_array(operation->buf, operation->len),
            drop_by_skips ? "true" : "false",
            drop_by_count ? "true" : "false");
        return true;
    }
    protoman_verbose("not dropping content=%s, skips=%s, count=%s",
        drop_by_content ? "true" : "false",
        drop_by_skips ? "true" : "false",
        drop_by_count ? "true" : "false");
    return false;
}

static int layer_write(struct protoman_layer_s *layer, struct protoman_io_header_s *operation)
{
    struct protoman_config_drop_s *config = layer->config;
    struct protoman_io_bytes_s *byte_op = (struct protoman_io_bytes_s *) operation;

    protoman_verbose("");

    if (_drop_packet(layer, (struct protoman_io_bytes_s *) operation, &config->tx)) {
        protoman_event(layer->protoman, layer, PROTOMAN_EVENT_DATA_WRITTEN, PROTOMAN_EVENT_PRIORITY_LOW, 0);
        return byte_op->len; /* fake succesfull write */
    }
    return protoman_layer_write_next(layer, operation);
}

static int layer_read(struct protoman_layer_s *layer, struct protoman_io_header_s *operation)
{
    struct protoman_config_drop_s *config = layer->config;

    protoman_verbose("");

    /* Read from below */
    int retval = protoman_layer_read_next(layer, operation);

    /* Something was read, filter it */
    if (retval > 0) {
        if (_drop_packet(layer, (struct protoman_io_bytes_s *) operation, &config->rx)) {
            return PROTOMAN_ERR_WOULDBLOCK; /* fake no data available */
        }
    }
    return retval;
}
