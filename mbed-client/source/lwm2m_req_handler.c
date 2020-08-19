/*
 * Copyright (c) 2017 ARM Limited. All rights reserved.
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

#include <string.h>

#include "lwm2m_req_handler.h"
#include "lwm2m_endpoint.h"
#include "sn_coap_protocol_internal.h"
#include "lwm2m_heap.h"
#include "randLIB.h"
#include "token_generator.h"
#include "mbed-trace/mbed_trace.h"
#include "eventOS_event_timer.h"

// Client Lite internal data structure for keeping track of a single CoAP GET request.

typedef struct get_data_request_s {
    get_data_cb         on_get_data_cb;
    get_data_error_cb   on_get_data_error_cb;
    size_t              received_size;
    uint32_t            msg_token;
    char                *uri_path;
    void                *context;
    bool                async_req;
    bool                resend;
    DownloadType        download_type;
#ifndef MBED_CLIENT_DISABLE_EST_FEATURE
    sn_coap_msg_code_e  msg_code;
    uint8_t             *payload;
    uint16_t            payload_len;
#endif
    ns_list_link_t      link;
} get_data_request_t;

typedef NS_LIST_HEAD(get_data_request_t, link) get_data_request_list_t;

static get_data_request_list_t get_request_list;
static bool initialized = false;
int32_t download_retry_time = 0;

static void get_handler_init(endpoint_t *endpoint);
static bool get_handler_is_response_to_get_req(const sn_coap_hdr_s *coap_header, get_data_request_t **get_data);

static uint8_t      firmware_download_uri[]   = {'f', 'w'}; /* Path for firmware update. */
static uint8_t      generic_download_uri[]    = {'d', 'o', 'w', 'n', 'l', 'o', 'a', 'd'}; /* Path for generic download. */

#define FIRMWARE_DOWNLOAD_LEN           2
#define GENERIC_DOWNLOAD_LEN            8

#define TRACE_GROUP "getH"

static void timer_cb(void *param)
{
    endpoint_t *endpoint = (endpoint_t*)param;
    req_handler_send_message(endpoint);
}

void req_handler_send_data_request(endpoint_t *endpoint,
                                       DownloadType type,
                                       sn_coap_msg_code_e msg_code,
                                       const char *uri,
                                       const size_t offset,
                                       const bool async,
                                       get_data_cb data_cb,
                                       get_data_error_cb error_cb,
                                       void *context,
                                       uint8_t *payload,
                                       uint16_t payload_len)
{
    tr_debug("req_handler_send_data_request - uri: %s, offset: %lu", uri, (unsigned long)offset);

    get_data_request_t *data_request = NULL;

    get_handler_init(endpoint);

    // Check the duplicate items
    ns_list_foreach(get_data_request_t, data, &get_request_list) {
        if ((strcmp(uri, data->uri_path) == 0) && (offset == data->received_size)) {
            data_request = data;
            break;
        }
    }

    // Create new item
    if (!data_request) {
        download_retry_time = 0;
        data_request = (get_data_request_t*)lwm2m_alloc(sizeof(get_data_request_t));
        if (data_request == NULL) {
            error_cb(FAILED_TO_ALLOCATE_MEMORY, context);
            return;
        }
        data_request->resend = true;
        data_request->context = context;
        data_request->async_req = async;
        data_request->received_size = offset;
        data_request->download_type = type;
        data_request->uri_path = (char*)lwm2m_alloc(strlen(uri) + 1);
        if (data_request->uri_path == NULL) {
            lwm2m_free(data_request);
            error_cb(FAILED_TO_ALLOCATE_MEMORY, context);
            return;
        }

        strcpy(data_request->uri_path, uri);
        data_request->on_get_data_cb = data_cb;
        data_request->on_get_data_error_cb = error_cb;
#ifndef MBED_CLIENT_DISABLE_EST_FEATURE
        data_request->msg_code = msg_code;
        data_request->payload = payload;
        data_request->payload_len = payload_len;
#endif
        // Store to list so we can match the response
        ns_list_add_to_end(&get_request_list, data_request);

        data_request->msg_token = generate_token();
    }

    send_queue_request(endpoint, SEND_QUEUE_REQUEST);
}

void req_handler_send_message(endpoint_t *endpoint)
{
    sn_coap_hdr_s req_message;
    int endpoint_status;
    get_data_request_t *data_request = NULL;

    get_handler_init(endpoint);

    // Check the duplicate items
    ns_list_foreach(get_data_request_t, data, &get_request_list) {
        if (data->resend) {
            data_request = data;
            break;
        }
    }

    if (!data_request) {
        send_queue_sent(endpoint, true);
        return;
    }

    // Fill CoAP message fields
    req_message.msg_type = COAP_MSG_TYPE_CONFIRMABLE;
#ifndef MBED_CLIENT_DISABLE_EST_FEATURE
    req_message.msg_code = data_request->msg_code;
    req_message.payload_len = data_request->payload_len;
    req_message.payload_ptr = data_request->payload;
#else
    req_message.msg_code = COAP_MSG_CODE_REQUEST_GET;
    req_message.payload_len = 0;
    req_message.payload_ptr = NULL;
#endif
    if (data_request->msg_token == 0) {
        data_request->msg_token = generate_token();
    }
    req_message.token_ptr = (uint8_t*)&data_request->msg_token;
    req_message.token_len = sizeof(data_request->msg_token);
    req_message.content_format = COAP_CT_NONE;
    req_message.msg_id = 0;
    req_message.coap_status = COAP_STATUS_OK;
    req_message.options_list_ptr = NULL;

    if (sn_coap_parser_alloc_options(endpoint->coap, &req_message) == NULL) {
        tr_error("req_handler_send_message - sn_coap_parser_alloc_options Allocation failed, return retry later");
        endpoint->coap->sn_coap_protocol_free(req_message.options_list_ptr);
        send_queue_sent(endpoint, true);
        return;
    }

    // Add block number
    req_message.options_list_ptr->block2 = 0;
    if (data_request->received_size > 0) {
        req_message.options_list_ptr->block2 = ((data_request->received_size / endpoint->coap->sn_coap_block_data_size) << 4);
    }
    // Add block size
    req_message.options_list_ptr->block2 |= sn_coap_convert_block_size(endpoint->coap->sn_coap_block_data_size);

#ifndef MBED_CLIENT_DISABLE_EST_FEATURE
    if (data_request->msg_code == COAP_MSG_CODE_REQUEST_GET) {
        // In GET we use hardcoded uri path('fw' or 'download') since the actual binary path will be part of
        // proxy uri option
        if (data_request->download_type == FIRMWARE_DOWNLOAD) {
            req_message.uri_path_len = FIRMWARE_DOWNLOAD_LEN;
            req_message.uri_path_ptr = firmware_download_uri;
        } else {
            req_message.uri_path_len = GENERIC_DOWNLOAD_LEN;
            req_message.uri_path_ptr = generic_download_uri;
        }

        // Add download path
        req_message.options_list_ptr->proxy_uri_len = (uint16_t)strlen(data_request->uri_path);
        req_message.options_list_ptr->proxy_uri_ptr = (uint8_t*)data_request->uri_path;
    } else {
        // POST or PUT request, URI path goes directly to CoAP header.
        req_message.uri_path_len = strlen(data_request->uri_path);
        req_message.uri_path_ptr = (uint8_t *) data_request->uri_path;
    }
#else // MBED_CLIENT_DISABLE_EST_FEATURE
    // In GET we use hardcoded uri path('fw' or 'download') since the actual binary path will be part of
    // proxy uri option
    if (data_request->download_type == FIRMWARE_DOWNLOAD) {
        req_message.uri_path_len = FIRMWARE_DOWNLOAD_LEN;
        req_message.uri_path_ptr = firmware_download_uri;
    } else {
        req_message.uri_path_len = GENERIC_DOWNLOAD_LEN;
        req_message.uri_path_ptr = generic_download_uri;
    }

    // Add download path
    req_message.options_list_ptr->proxy_uri_len = (uint16_t)strlen(data_request->uri_path);
    req_message.options_list_ptr->proxy_uri_ptr = (uint8_t*)data_request->uri_path;
#endif // MBED_CLIENT_DISABLE_EST_FEATURE
    endpoint_status = endpoint_send_coap_message(endpoint, NULL, &req_message);

    endpoint->coap->sn_coap_protocol_free(req_message.options_list_ptr);

    if (endpoint_status == ENDPOINT_STATUS_OK) {
        // Message is successfully sent, no need for resend.
        data_request->resend = false;
    } else if (endpoint_status == ENDPOINT_STATUS_ERROR_MEMORY_FAILED) {
        data_request->on_get_data_error_cb(FAILED_TO_ALLOCATE_MEMORY, data_request->context);
        ns_list_remove(&get_request_list, data_request);
        lwm2m_free(data_request);
        send_queue_sent(endpoint, true);
    }
}

static void get_handler_init(endpoint_t *endpoint)
{
    if (!initialized) {
        ns_list_init(&get_request_list);

        // We will take care of sending the next GET request
        sn_coap_protocol_handle_block2_response_internally(endpoint->coap, false);

        initialized = true;
    }
}

void req_handler_destroy(void)
{
    req_handler_free_request_list(NULL, false, FAILED_TO_SEND_MSG);
    initialized = false;
}

bool req_handler_handle_response(endpoint_t *endpoint, const sn_coap_hdr_s *coap_header)
{

    get_data_request_t *get_data_req;
    size_t total_size = 0;

    if (!get_handler_is_response_to_get_req(coap_header, &get_data_req)) {
        return false;
    }

    tr_debug("req_handler_handle_response - msg code %d", coap_header->msg_code);

    send_queue_sent(endpoint, true);

    if (coap_header->options_list_ptr) {
        if (coap_header->options_list_ptr->use_size2) {
            total_size = coap_header->options_list_ptr->size2;
        }
    } else {
        total_size = coap_header->payload_len;
    }

    bool last_block = true;
    if (coap_header->options_list_ptr &&
        coap_header->options_list_ptr->block2 != -1 &&
        coap_header->options_list_ptr->block2 & 0x08) {
        // Not last block if block2 is set (blockwised transfer) and more bit is set
        last_block = false;
    }

    if (coap_header->msg_code == COAP_MSG_CODE_RESPONSE_CONTENT &&
        coap_header->coap_status != COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED) {

        req_handler_free_request_list(coap_header, false, FAILED_TO_SEND_MSG);

        get_data_req->received_size += coap_header->payload_len;
        get_data_req->on_get_data_cb(coap_header->payload_ptr,
                                    coap_header->payload_len,
                                    total_size,
                                    last_block,
                                    get_data_req->context);

        // In sync mode, call next GET automatically until all blocks have been received
        if (get_data_req->async_req == false) {
            if (coap_header->options_list_ptr && (coap_header->options_list_ptr->block2 & 0x08)) {
#ifndef MBED_CLIENT_DISABLE_EST_FEATURE
                req_handler_send_data_request(endpoint,
                                                get_data_req->download_type,
                                                get_data_req->msg_code,
                                                get_data_req->uri_path,
                                                get_data_req->received_size,
                                                get_data_req->async_req,
                                                get_data_req->on_get_data_cb,
                                                get_data_req->on_get_data_error_cb,
                                                get_data_req->context,
                                                get_data_req->payload,
                                                get_data_req->payload_len);
#else
                req_handler_send_data_request(endpoint,
                                                get_data_req->download_type,
                                                COAP_MSG_CODE_REQUEST_GET,
                                                get_data_req->uri_path,
                                                get_data_req->received_size,
                                                get_data_req->async_req,
                                                get_data_req->on_get_data_cb,
                                                get_data_req->on_get_data_error_cb,
                                                get_data_req->context,
                                                NULL,
                                                0);
#endif
            }
        }
    } else {

        if (coap_header->coap_status == COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED ||
            coap_header->coap_status == COAP_STATUS_BUILDER_BLOCK_SENDING_FAILED) {
            // Give an error to the endpoint and wait for it to reconnect.
            endpoint_send_event(endpoint, ENDPOINT_EVENT_ERROR_REREGISTER, coap_header->coap_status);
            return true;

        } else if (coap_header->msg_code == COAP_MSG_CODE_RESPONSE_SERVICE_UNAVAILABLE) {
            tr_debug("req_handler_handle_response - msg code COAP_MSG_CODE_RESPONSE_SERVICE_UNAVAILABLE");
            bool retry = true;

            if (!download_retry_time) {
                // Range is from 1 to 10 seconds
                download_retry_time = randLIB_get_random_in_range(1, 10);
            } else {
                download_retry_time *= 2;

                if (download_retry_time > MAX_RECONNECT_TIMEOUT) {
                    tr_error("req_handler_handle_response - file download failed, retry completed");
                    req_handler_free_request_list(coap_header, true, FAILED_TO_SEND_MSG);
                    retry = false;
                }
            }

            if (retry) {
                if (eventOS_timeout_ms(timer_cb, download_retry_time * 1000, (void*)endpoint) == NULL) {
                    tr_error("req_handler_handle_response - failed to create a timer");
                    req_handler_free_request_list(coap_header, true, FAILED_TO_SEND_MSG);
                } else {
                    get_data_req->resend = true;
                    tr_debug("req_handler_handle_response - continue file download after % "PRId32" (s)", download_retry_time);
                }
            }

            return true;

        } else {
            req_handler_free_request_list(coap_header, true, FAILED_TO_SEND_MSG);
        }

    }

    lwm2m_free(get_data_req->uri_path);
    lwm2m_free(get_data_req);

    // Remove sent blockwise message(GET request) from the linked list.
    sn_coap_protocol_remove_sent_blockwise_message(endpoint->coap, coap_header->msg_id);

    return true;

}

void req_handler_free_request_list(const sn_coap_hdr_s *coap_header, bool call_error_cb, get_data_req_error_t error_code)
{
    if (initialized) {
        // Clean up whole list
        if (coap_header == NULL) {
            ns_list_foreach_safe(get_data_request_t, data, &get_request_list) {
                if (call_error_cb) {
                    data->on_get_data_error_cb(error_code, data->context);
                }
                ns_list_remove(&get_request_list, data);
                lwm2m_free(data->uri_path);
                lwm2m_free(data);
            }

        // Clean just one item from the list
        } else {
            ns_list_foreach(get_data_request_t, data, &get_request_list) {
                if (coap_header->token_len == sizeof(data->msg_token) && memcmp(coap_header->token_ptr, &data->msg_token, sizeof(data->msg_token)) == 0) {
                    if (call_error_cb) {
                        data->on_get_data_error_cb(error_code, data->context);
                    }

                    ns_list_remove(&get_request_list, data);
                    // Object itself is freed in req_handler_handle_response() after callback has been completed
                    return;
                }
            }
        }
    }
}

static bool get_handler_is_response_to_get_req(const sn_coap_hdr_s *coap_header, get_data_request_t **get_data)
{
    ns_list_foreach(get_data_request_t, data, &get_request_list) {
        if (coap_header->token_len == sizeof(data->msg_token) && memcmp(coap_header->token_ptr, &data->msg_token, sizeof(data->msg_token)) == 0) {
            *get_data = data;
            return true;
        }
    }
    return false;
}

void req_handler_set_resend_status(void)
{
    if (!initialized) {
        return;
    }

    ns_list_foreach(get_data_request_t, data, &get_request_list) {
        data->resend = true;
    }
}

void req_handler_send_pending_request(endpoint_t *endpoint)
{
    if (!initialized) {
        return;
    }

    ns_list_foreach(get_data_request_t, data, &get_request_list) {
        if (data->resend) {
            send_queue_request(endpoint, SEND_QUEUE_REQUEST);
            return;
        }
    }

}
