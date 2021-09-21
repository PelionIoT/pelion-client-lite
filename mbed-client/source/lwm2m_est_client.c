/*
 * Copyright (c) 2020 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "est_defs.h"
#include "dmc_connect_api.h"
#include "lwm2m_req_handler.h"
#include "common_functions.h"

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>


#ifdef MBED_CLIENT_DISABLE_EST_FEATURE
#undef MBED_CLIENT_DISABLE_EST_FEATURE // I need the prototypes anyway
#endif

#include "lwm2m_est_client.h"

/**
 * Internal context structure
 */
struct enrollment_context_s {
    est_enrollment_result_cb   result_cb;
    uint8_t                    *data;
    size_t                     data_size;
    void*                      context;
};

#define EST_SEN_LWM2M                "est/sen"
#define EST_SEN_LWM2M_LEN            8
#define EST_SEN_URI_FORMAT           "est/%.*s/sen"
#define EST_CERT_CHAIN_VERSION       1

/**
 * Generate CoAP URI for EST
 * \param cert_name Name of the certificate to request, or NULL if LwM2M device certificate is requested.
 * \return pointer to a URI string, or NULL on failure
 */
static char* make_est_uri(const char *cert_name);
static void est_data_cb(const uint8_t *buffer, size_t buffer_size, size_t total_size, bool last_block, void *context);
static void est_error_cb(get_data_req_error_t error_code, void *context);
static struct cert_chain_context_s* est_parse_cert_chain(uint8_t *cert_chain_data, uint16_t cert_chain_data_len);

est_status_e est_request_enrollment(const char *cert_name,
                                    uint8_t *csr,
                                    const size_t csr_length,
                                    est_enrollment_result_cb result_cb,
                                    void *context)
{
    if (csr == NULL || csr_length == 0 || result_cb == NULL) {
        return EST_STATUS_INVALID_PARAMETERS;
    }

    lwm2m_interface_t *interface = pdmc_connect_get_interface();
    if (!interface) {
        return EST_STATUS_INVALID_PARAMETERS;
    }
    endpoint_t *endpoint = &interface->endpoint;
    if (!endpoint) {
        return EST_STATUS_INVALID_PARAMETERS;
    }

    struct enrollment_context_s *ctx = (struct enrollment_context_s*)malloc(sizeof(struct enrollment_context_s));
    if (ctx == NULL) {
        return EST_STATUS_MEMORY_ALLOCATION_FAILURE;
    }

    char *uri = make_est_uri(cert_name);
    if (uri == NULL) {
      free(ctx);
      return EST_STATUS_MEMORY_ALLOCATION_FAILURE;
    }

    ctx->result_cb = result_cb;
    ctx->context = context;
    ctx->data = NULL;
    ctx->data_size = 0;

    req_handler_send_data_request(endpoint, GENERIC_DOWNLOAD, COAP_MSG_CODE_REQUEST_POST,
                                  uri, 0, false,
                                  est_data_cb, est_error_cb,
                                  ctx, csr, csr_length);
    free(uri);

    return EST_STATUS_SUCCESS;
}

void est_free_context(struct cert_chain_context_s *context)
{
    if (context) {
        struct cert_context_s *next = context->certs;
        while (next) {
            struct cert_context_s *tmp = next->next;
            // Free each cert context, no need to free the cert data in
            // next->cert because it points inside context->cert_data_context
            // which is free'd last
            free(next);
            next = tmp;
        }
        free(context->cert_data_context);
        free(context);
    }
}

static char* make_est_uri(const char *cert_name)
{
    if (cert_name == NULL) {
        // LwM2M certificate
        char *s = calloc(1, EST_SEN_LWM2M_LEN);
        if (!s) {
            return NULL;
        }
        return strcpy(s, EST_SEN_LWM2M);
    } else {
        char *uri = NULL;
        size_t uri_len = 0;
        size_t name_len = strlen(cert_name);

        // The ".*s" needs a int argument, which likely has smaller max value than size_t, so let's check
        // value before casting to avoid theoretical integer wrapping and undefined behavior in snprintf().
        if (name_len <= INT_MAX) {
            // User certificate
            uri_len = snprintf(NULL, 0, EST_SEN_URI_FORMAT, (int)name_len, cert_name);
            uri_len++; // For null terminator
            uri = calloc(uri_len, sizeof(char));
            if (uri != NULL) {
                (void)snprintf(uri, uri_len, EST_SEN_URI_FORMAT, (int)name_len, cert_name);
            }
        }
        return uri;
    }
}

static void est_data_cb(const uint8_t *buffer, size_t buffer_size, size_t total_size, bool last_block, void *context)
{
    struct enrollment_context_s *enrollment_context = context;
    (void)total_size;
    assert(enrollment_context);

    // Append new buffer to payload
    size_t new_size = enrollment_context->data_size + buffer_size;
    uint8_t *new_buffer = malloc(new_size);
    if (!new_buffer) {
        // Memory error!
        // TODO: Log this
        return;
    }

    // Copy old data to start of buffer
    if (enrollment_context->data) {
        memcpy(new_buffer, enrollment_context->data, enrollment_context->data_size);
        free(enrollment_context->data);
    }

    // Copy new data to buffer
    memcpy(new_buffer + enrollment_context->data_size, buffer, buffer_size);
    enrollment_context->data = new_buffer;
    enrollment_context->data_size = new_size;

    if (last_block) {
        struct cert_chain_context_s *cert_ctx = est_parse_cert_chain(enrollment_context->data, enrollment_context->data_size);
        if (cert_ctx != NULL) {
            enrollment_context->result_cb(EST_ENROLLMENT_SUCCESS, cert_ctx, enrollment_context->context);
        } else {
            enrollment_context->result_cb(EST_ENROLLMENT_FAILURE, NULL, enrollment_context->context);
        }
        free(enrollment_context);
    }
}

static void est_error_cb(get_data_req_error_t error_code, void *context)
{
    struct enrollment_context_s *enrollment_context = context;
    assert(enrollment_context);
    enrollment_context->result_cb(EST_ENROLLMENT_FAILURE, NULL, enrollment_context->context);
    free(enrollment_context);
}

static struct cert_chain_context_s* est_parse_cert_chain(uint8_t *cert_chain_data, uint16_t cert_chain_data_len)
{
    assert(cert_chain_data);
    assert(cert_chain_data_len > 0);

    uint8_t *ptr = cert_chain_data;
    struct cert_chain_context_s *context = malloc(sizeof(struct cert_chain_context_s));

    if (context != NULL) {
        bool success = true;
        context->cert_data_context = ptr;
        uint8_t version = *ptr++;
        context->chain_length = *ptr++;
        struct cert_context_s **next_context_ptr = &context->certs;

        // Check if unknown version
        if (version != EST_CERT_CHAIN_VERSION) {
            success = false;
        }

        // Check overflow
        if (success && ptr - cert_chain_data > cert_chain_data_len) {
            success = false;
            context->chain_length = 0;
        }

        if (success) {
            for (int i = 0; i < context->chain_length; i++) {
                // Parse certificate length (2 bytes)
                uint16_t cert_len = common_read_16_bit(ptr);
                ptr += 2;
                // Check overflow
                if (ptr - cert_chain_data > cert_chain_data_len) {
                    success = false;
                    break;
                }

                // Allocate new certificate context
                *next_context_ptr = malloc(sizeof(struct cert_context_s));
                if (*next_context_ptr == NULL) {
                    // Error
                    success = false;
                    break;
                }

                // Set cert pointer to correct position in data
                (*next_context_ptr)->cert_length = cert_len;
                (*next_context_ptr)->cert = ptr;

                ptr += cert_len;

                // Check overflow
                if (ptr - cert_chain_data > cert_chain_data_len) {
                    // TODO: Log this
                    success = false;
                    free(*next_context_ptr);
                    break;
                }

                next_context_ptr = &((*next_context_ptr)->next);
            }
            *next_context_ptr = NULL;
        }

        if (!success) {
            est_free_context(context);
            context = NULL;
        }
    }

    return context;
}
