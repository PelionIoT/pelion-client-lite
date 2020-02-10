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

#include "mbed-protocol-manager/protoman_config.h"

#ifndef PROTOMAN_OFFLOAD_TLS
#include <stdio.h>
#include <string.h>

#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"

#include "mbed-protocol-manager/protoman.h"
#include "mbed-protocol-manager/protoman_layer.h"
#include "mbed-protocol-manager/protoman_layer_mbedtls.h"
#define TRACE_GROUP  "mTLS"
#include "include/protoman_internal.h"
#include "include/protoman_layer_mbedtls_sslkeylog.h"


/* If the compiler doesn't for some reason optimize unused functions
 * out of the binary, don't even build these functions to the binary */
#ifdef PROTOMAN_SSLKEYLOG

void _sslkeylog_snapshot_client_random(struct protoman_layer_s *layer)
{
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *) layer;
    mbedtls_ssl_context *ssl_context = &layer_mbedtls_common->ssl;

    /* Handshake completed, store connection number */
    if (MBEDTLS_SSL_HANDSHAKE_OVER == layer_mbedtls_common->ssl.state) {
        layer_mbedtls_common->sslkeylog_connection_id++;
        protoman_verbose("handshake %d over detected", layer_mbedtls_common->sslkeylog_connection_id);
        goto exit;
    }

    /* Check transition from MBEDTLS_SSL_CLIENT_HELLO to MBEDTLS_SSL_SERVER_HELLO */
    if (MBEDTLS_SSL_SERVER_HELLO != layer_mbedtls_common->ssl.state ||
        MBEDTLS_SSL_CLIENT_HELLO != layer_mbedtls_common->sslkeylog_previous_ssl_state) {
        goto exit;
    }

    /* Transition detected */
    protoman_verbose("CLIENT_HELLO -> SERVER_HELLO transition detected");
    memcpy(layer_mbedtls_common->sslkeylog_client_random, ssl_context->handshake->randbytes, SSLKEYLOG_CLIENT_RANDOM_SIZE);

exit:
    layer_mbedtls_common->sslkeylog_previous_ssl_state = layer_mbedtls_common->ssl.state;
}

void _sslkeylog_snapshot_master_secret(struct protoman_layer_s *layer)
{
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *) layer;
    mbedtls_ssl_context *ssl_context = &layer_mbedtls_common->ssl;
    int retval;

    protoman_verbose("comparing %p with %p",
        layer_mbedtls_common->sslkeylog_master_secret,
        ssl_context->session->master);

    /* Check for changes to determine renegotiation */
    protoman_verbose("layer_mbedtls_common->sslkeylog_master_secret = %s",
        mbed_trace_array(layer_mbedtls_common->sslkeylog_master_secret, SSLKEYLOG_MASTER_SECRET_SIZE));
    protoman_verbose("ssl_context->session->master = %s",
        mbed_trace_array(ssl_context->session->master, SSLKEYLOG_MASTER_SECRET_SIZE));
    retval = (int)memcmp(layer_mbedtls_common->sslkeylog_master_secret, ssl_context->session->master, SSLKEYLOG_MASTER_SECRET_SIZE);
    if (0 == retval) {
        return;
    }

    protoman_verbose("change detected");
    memcpy(layer_mbedtls_common->sslkeylog_master_secret, ssl_context->session->master, SSLKEYLOG_MASTER_SECRET_SIZE);

    /* Update NSS key log file entry string */
    _sslkeylog_update_entry(layer);

#ifdef PROTOMAN_FILE_IO
    /* Write entry to file */
    protoman_verbose("writing entry to file");
    _sslkeylog_update_file(layer);
#endif

    /* Print to debug log -- print as error to make it obivious that it is security breakage to print it */
    protoman_err("dumping mbedTLS secret keys: %s", layer_mbedtls_common->sslkeylog_entry);
}

void _sslkeylog_update_file(struct protoman_layer_s *layer)
{
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *) layer;
    FILE *fid;
    int retval;

    /* Create fname */
#ifdef PROTOMAN_SSLKEYLOG_FANCY_FILENAME
    char fname[32]; /* sslkeylog_0xffff0000_12.txt */
    retval = snprintf(fname, sizeof(fname), "sslkeylog_%p_%d.txt", layer, layer_mbedtls_common->sslkeylog_connection_id);
    if (retval < 0 || retval == sizeof(fname)) {
        tr_err("_sslkeylog_update_file(), failed to create capture filename");
        return;
    }
#else
    char fname[] = "sslkeylog.txt";
#endif

    /* Open capture file */
    fid = fopen(fname, "a");
    if (NULL == fid) {
        tr_err("_sslkeylog_update_file(), failed to open sslkeylog.txt");
        return;
    }

    /* Write contents */
    retval = fwrite(layer_mbedtls_common->sslkeylog_entry, sizeof(char), strlen(layer_mbedtls_common->sslkeylog_entry), fid);
    if (retval != strlen(layer_mbedtls_common->sslkeylog_entry)) {
        tr_err("_sslkeylog_update_file(), failed to write entry");
    }

    /* Close capture file */
    fclose(fid);
}

void _sslkeylog_update_entry(struct protoman_layer_s *layer)
{
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *) layer;

    /*  Format a NSS key log entry
     *   https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
     * ======================== */
    int retval;
    int offset = 0;

    /* write <Label> */
    const char label[] = "CLIENT_RANDOM ";
    retval = snprintf(layer_mbedtls_common->sslkeylog_entry + offset, SSLKEYLOG_ENTRY_LEN - offset, label);
    if (retval < 0 || retval != strlen(label)) {
        tr_err("_sslkeylog_update_entry(), failed to write <Label>");
        return;
    }
    offset += retval;

    /* write <ClientRandom> */
    for (int i = 0; i < SSLKEYLOG_CLIENT_RANDOM_SIZE; i++) {
        retval = snprintf(layer_mbedtls_common->sslkeylog_entry + offset, SSLKEYLOG_ENTRY_LEN - offset,
            "%02x", layer_mbedtls_common->sslkeylog_client_random[i]);
        if (retval < 0 || retval != 2) {
            tr_err("_sslkeylog_update_entry(), failed to write <ClientRandom>[%d]", i);
            return;
        }
        offset += retval;
    }

    /* write <space > */
    retval = snprintf(layer_mbedtls_common->sslkeylog_entry + offset, SSLKEYLOG_ENTRY_LEN - offset, " ");
    if (retval < 0 || retval != 1) {
        tr_err("_sslkeylog_update_entry(), failed to write <space>");
        return;
    }
    offset += retval;

    /*  write <Secret> */
    for (int i = 0; i < SSLKEYLOG_MASTER_SECRET_SIZE; i++) {
        retval = snprintf(layer_mbedtls_common->sslkeylog_entry + offset, SSLKEYLOG_ENTRY_LEN - offset,
            "%02x", layer_mbedtls_common->sslkeylog_master_secret[i]);
        if (retval < 0 || retval != 2) {
            tr_err("_sslkeylog_update_entry(), failed to write <Secret>[%d]", i);
            return;
        }
        offset += retval;
    }

    /* write <newline> */
    retval = snprintf(layer_mbedtls_common->sslkeylog_entry + offset, SSLKEYLOG_ENTRY_LEN - offset, "\n");
    if (retval < 0 || retval != 1) {
        tr_err("_sslkeylog_update_entry(), failed to write <newline>");
        return;
    }
    offset += retval;

    /* sanity check offset */
    if (offset != SSLKEYLOG_ENTRY_LEN - 1) { /* -1 for \0 */
        tr_err("_sslkeylog_update_entry(), length calculation error");
    }
}
#endif // PROTOMAN_SSLKEYLOG
#endif
