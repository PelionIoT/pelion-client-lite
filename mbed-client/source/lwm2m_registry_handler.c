/*
 * Copyright (c) 2017 - 2018 ARM Limited. All rights reserved.
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

#include "lwm2m_callback_handler.h"
#include "lwm2m_constants.h"
#include "lwm2m_endpoint.h"
#include "lwm2m_heap.h"
#include "lwm2m_notifier.h"
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
#include "lwm2m_registry.h"
#include "lwm2m_registry_meta.h"
#endif
#include "lwm2m_registry_handler.h"
#include "tlvserializer.h"
#include "eventOS_event.h"
#include "mbed-trace/mbed_trace.h"

#include <assert.h>
#include <stdio.h> // snprintf
#include <stdlib.h>
#include <string.h>

/* Defines */
#define TRACE_GROUP "RegH"

static uint8_t parse_registry_path(const uint8_t* buf, size_t len, registry_path_t* path);
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
static char *registry_path_to_string(const registry_path_t* path);
static bool send_callback_data(const registry_path_t *path, const sn_coap_hdr_s* header, const uint8_t type);
static sn_coap_hdr_s* handle_get_request(const registry_path_t* path, endpoint_t* endpoint, sn_coap_hdr_s* received_coap_header);
static sn_coap_hdr_s* handle_put_request(const registry_path_t* path, endpoint_t *endpoint, sn_coap_hdr_s* received_coap_header);
static sn_coap_hdr_s* handle_delete_request(const registry_path_t* path, endpoint_t *endpoint, sn_coap_hdr_s* received_coap_header);
#endif
static sn_coap_hdr_s* handle_execute_request(const registry_path_t* path, endpoint_t *endpoint,
                                             sn_coap_hdr_s* received_coap_header,
                                             sn_nsdl_addr_s *address, int* execute_value_updated);
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
static sn_coap_msg_code_e read_attribute_value(const char *query, const char *query_end, uint32_t *int_value, float *float_value, bool *available);
#endif

static bool handle_coap_notification_response(registry_t* registry, sn_coap_hdr_s *received_coap_header, registry_notification_status_t notification_status);

static sn_coap_hdr_s* handle_unsupported_request(endpoint_t *endpoint,
                                                 sn_coap_hdr_s* received_coap_header)
{
    sn_coap_hdr_s *coap_response = sn_coap_build_response(endpoint->coap, received_coap_header, COAP_MSG_CODE_RESPONSE_CHANGED);
    if (!coap_response) {
        return NULL;
    }
    coap_response->msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
    return coap_response;
}
#endif

static uint8_t parse_registry_path(const uint8_t* buf, size_t len, registry_path_t* path)
{
    char uri[MAX_VALUE_LENGTH];

    if (len > MAX_VALUE_LENGTH - 1) {
        // uri buffer is too big - it must fit in MAX_VALUE_LENGTH bytes with a terminating nul
        return 0;
    }

    memcpy(uri, buf, len);
    uri[len] = '\0';

    /* uri may contain 0-3 slashes, and uses the following format:
     * "1" is object 1
     * "1/2" is instance 2 of object 1
     * "1/2/3" is resource 3 of instance 2 of object 1
     * "1/2/3/4" is resource instance 4 of resource 3 of object instance 2 of object 1
     * Maximum value for one integer part is 65535.
     */

    /* keep track of the next slash position */

    char* slashpos = strchr(uri, '/');
    /* first char cannot be slash */
    if (slashpos == uri) {
        return 0;
    }

    /* pointer to the end of the path string */
    const char* pathend = uri + strlen(uri);
    /* current position in the path */
    const char* pathpos = uri;
    /* which part of the path we are currently working on */
    unsigned pathpart = 0;

    for (; pathpart < 4 && pathpos < pathend; pathpart++) {
        /* from current position to either next slash or end of string, we should be able to parse an integer */
        long temp_path_item = strtol(pathpos, &slashpos, 10);

        /* negative numbers are not supported */
        if (temp_path_item < 0) {
            return 0;
        }

        unsigned path_item = (unsigned) temp_path_item;

        /* too large values are discarded as well */
        if (path_item > 65535) {
            return 0;
        }

        /* empty value not accepted */
        if (slashpos == pathpos) {
            return 0;
        }

        switch (pathpart) {
            case REGISTRY_PATH_OBJECT: path->object_id = (uint16_t) path_item; break;
            case REGISTRY_PATH_OBJECT_INSTANCE: path->object_instance_id = (uint16_t) path_item; break;
            case REGISTRY_PATH_RESOURCE: path->resource_id = (uint16_t) path_item; break;
            case REGISTRY_PATH_RESOURCE_INSTANCE: path->resource_instance_id = (uint16_t) path_item; break;
        }

        /* jump over the next slash char position for next round */
        pathpos = slashpos ? slashpos + 1 : pathend;

        /* number of path parts (starting at 0) corresponds to the path type in the struct */
        path->path_type = pathpart;
    }


    /* final check: we should not have any trailing data once the valid stuff is parsed */
    if (slashpos != pathend) {
        return 0;
    }

    return pathpart;
}

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
static char *registry_path_to_string(const registry_path_t* path)
{
    /* four uint16_t fields, three slashes and terminating null byte */
    const size_t PATH_MAX_LENGTH = 5 * 4 + 3 + 1;
    char* pathstr = (char *) lwm2m_alloc(PATH_MAX_LENGTH);
    int len = 0;
    if (pathstr) {
        switch (path->path_type) {
            case REGISTRY_PATH_OBJECT:
                len = snprintf(pathstr, PATH_MAX_LENGTH, "/%u", path->object_id);
                break;
            case REGISTRY_PATH_OBJECT_INSTANCE:
                len = snprintf(pathstr, PATH_MAX_LENGTH, "/%u/%u", path->object_id, path->object_instance_id);
                break;
            default:
                tr_error("registry_path_to_string - unsupported path!");
                assert(0);
                break;
        }

        // This is pointless actually, as we definitely know and control the max output string length.
        assert(len < (int)PATH_MAX_LENGTH);

        (void)len; // remove compiler warning on release builds
    }

    return pathstr;
}

static sn_coap_hdr_s* handle_get_request(const registry_path_t* path, endpoint_t* endpoint, sn_coap_hdr_s* received_coap_header)
{

    sn_coap_hdr_s *coap_response;
    uint32_t payload_len = 0;
    registry_callback_t callback;
    registry_tlv_serialize_status_t serializer_status;

    coap_response = sn_coap_build_response(endpoint->coap, received_coap_header, COAP_MSG_CODE_RESPONSE_CONTENT);

    if (!coap_response || !received_coap_header) {
        return NULL;
    }

    if (path->path_type == REGISTRY_PATH_OBJECT || path->path_type == REGISTRY_PATH_OBJECT_INSTANCE) {
        const lwm2m_object_meta_definition_t *objdef;
        if (registry_meta_get_object_definition(path->object_id, &objdef) == REGISTRY_STATUS_OK) {
            if ((received_coap_header->options_list_ptr) &&
                (received_coap_header->options_list_ptr->accept != COAP_CT_NONE)) {
                coap_response->content_format = received_coap_header->options_list_ptr->accept;

                // Only TLV format accepted in this level
                if ((coap_response->content_format != COAP_CONTENT_OMA_TLV_TYPE_OLD) &&
                    (coap_response->content_format != COAP_CONTENT_OMA_TLV_TYPE)) {
                    coap_response->msg_code = COAP_MSG_CODE_RESPONSE_UNSUPPORTED_CONTENT_FORMAT;
                    return coap_response;
                }
            } else {
                coap_response->content_format = (sn_coap_content_format_e) COAP_CONTENT_OMA_TLV_TYPE;
            }
        } else {
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_NOT_FOUND;
            return coap_response;
        }
    }

    // Check that GET is actually allowed if the requested item can limit operations.
    else if (path->path_type == REGISTRY_PATH_RESOURCE || path->path_type == REGISTRY_PATH_RESOURCE_INSTANCE) {
        const lwm2m_resource_meta_definition_t *resdef;
        if (registry_meta_get_resource_definition(path->object_id, path->resource_id, &resdef) == REGISTRY_STATUS_OK) {

            if (!(resdef->operations & LWM2M_RESOURCE_OPERATIONS_R)) {

                coap_response->msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
                return coap_response;

            } else if ((received_coap_header->options_list_ptr) &&
                       (received_coap_header->options_list_ptr->accept != COAP_CT_NONE)) {

                coap_response->content_format = received_coap_header->options_list_ptr->accept;

                // Accept only text/plain and TLV formats
                if ((coap_response->content_format != COAP_CONTENT_OMA_TLV_TYPE_OLD) &&
                    (coap_response->content_format != COAP_CONTENT_OMA_TLV_TYPE) &&
#if MBED_CLIENT_ENABLE_SERIALIZE_PLAINTEXT
                    (coap_response->content_format != COAP_CONTENT_OMA_PLAIN_TEXT_TYPE) &&
#endif
                    (coap_response->content_format != COAP_CONTENT_OMA_OPAQUE_TYPE)) {

                    coap_response->msg_code = COAP_MSG_CODE_RESPONSE_UNSUPPORTED_CONTENT_FORMAT;
                    return coap_response;
                }

            } else if (((resdef->multiple == LWM2M_RESOURCE_SINGLE_INSTANCE) &&
                        (path->path_type == REGISTRY_PATH_RESOURCE)) ||
                        ((resdef->multiple == LWM2M_RESOURCE_MULTIPLE_INSTANCES) &&
                        (path->path_type == REGISTRY_PATH_RESOURCE_INSTANCE))) {

                    if (resdef->type == LWM2M_RESOURCE_TYPE_OPAQUE) {
                        coap_response->content_format = (sn_coap_content_format_e)COAP_CONTENT_OMA_OPAQUE_TYPE;
                    } else {
#if MBED_CLIENT_ENABLE_SERIALIZE_PLAINTEXT
                        // we can return a text representation for single resource values for non-opaque data types
                        coap_response->content_format = (sn_coap_content_format_e)COAP_CONTENT_OMA_PLAIN_TEXT_TYPE;
#else
                        coap_response->content_format = (sn_coap_content_format_e) COAP_CONTENT_OMA_TLV_TYPE;
#endif // MBED_CLIENT_ENABLE_SERIALIZE_PLAINTEXT
                    }

            } else {
                coap_response->content_format = (sn_coap_content_format_e) COAP_CONTENT_OMA_TLV_TYPE;
            }


        } else {

            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_NOT_FOUND;
            return coap_response;

        }
    }

    tr_debug("handle_get_request() - Request Content-Type %d", coap_response->content_format);

    registry_serialization_format_t format;
    if (coap_response->content_format == COAP_CONTENT_OMA_OPAQUE_TYPE) {
        format = REGISTRY_SERIALIZE_OPAQUE;
    } else {
#if MBED_CLIENT_ENABLE_SERIALIZE_PLAINTEXT
        if (coap_response->content_format == COAP_CONTENT_OMA_TLV_TYPE_OLD ||
            coap_response->content_format == COAP_CONTENT_OMA_TLV_TYPE) {
            format = REGISTRY_SERIALIZE_TLV;
        } else {
            format = REGISTRY_SERIALIZE_PLAINTEXT;
        }
#else
        format = REGISTRY_SERIALIZE_TLV;
#endif // MBED_CLIENT_ENABLE_SERIALIZE_PLAINTEXT
    }


    coap_response->payload_ptr = registry_serialize(&endpoint->registry, path, &payload_len, format, false, &serializer_status);
    coap_response->payload_len = payload_len;

    tr_debug("handle_get_request() - registry_serialize returned: %d", serializer_status);

    switch (serializer_status) {

        case REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND:
            if ((0 == coap_response->payload_len) &&
                (NULL == coap_response->payload_ptr) &&
                ((path->path_type == REGISTRY_PATH_OBJECT) || (path->path_type == REGISTRY_PATH_RESOURCE))) {

                // A zero-length response is required for non-instance paths if there is no actual data to be sent back.
                // XXX: Since we can't allocate 0 bytes realiably, one byte allocation is needed.
                coap_response->payload_ptr = lwm2m_alloc(1);
            }
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_NOT_FOUND;
            return coap_response;

        case REGISTRY_TLV_SERIALIZE_STATUS_NO_MEMORY:
        case REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR:
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR;
            return coap_response;

        case REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT:
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
            return coap_response;

        case REGISTRY_TLV_SERIALIZE_STATUS_OK:
            break;

    }

    coap_response->options_list_ptr = sn_coap_parser_alloc_options(endpoint->coap, coap_response);

    if (registry_get_max_age(&endpoint->registry, path, &coap_response->options_list_ptr->max_age) != REGISTRY_STATUS_OK) {
        tr_error("handle_get_request() could not read max_age from registry!");
        // XXX: setting the default here could be masking an actual error in registry
        coap_response->options_list_ptr->max_age = LWM2M_VALUE_CACHE_MAX_AGE;
    }


    if (received_coap_header->options_list_ptr) {

#if MBED_CLIENT_ENABLE_AUTO_OBSERVATION
        if ((received_coap_header->options_list_ptr->observe == 0 ||
             received_coap_header->options_list_ptr->observe == 1)
            && registry_is_auto_observable(&endpoint->registry, path)) {
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
            lwm2m_free(coap_response->payload_ptr);
            coap_response->payload_ptr = NULL;
            coap_response->payload_len = 0;
            return coap_response;
        }
#endif

        if (received_coap_header->options_list_ptr->observe == 0) {

            sn_coap_content_format_e content_type = COAP_CT_NONE;

            // Observe value is 0 means register for observation.

            tr_debug("M2MObject::handle_get_request - Put Resource under Observation");

            if ((received_coap_header->options_list_ptr) && (received_coap_header->options_list_ptr->accept != COAP_CT_NONE)) {
                content_type = coap_response->content_format;
            }

            coap_response->options_list_ptr->observe = notifier_start_observation(&endpoint->notifier,
                                                                                  path, received_coap_header->token_ptr,
                                                                                  received_coap_header->token_len,
                                                                                  content_type);

            if (registry_get_callback(&endpoint->registry, path, &callback) == REGISTRY_STATUS_OK) {
                callback(REGISTRY_CALLBACK_NOTIFICATION_STATUS, path, NULL, NULL, NOTIFICATION_STATUS_SUBSCRIBED, &endpoint->registry);
            }

            tr_debug("M2MObject::handle_get_request - Observation Number %" PRId32, coap_response->options_list_ptr->observe);


        } else if (received_coap_header->options_list_ptr->observe == 1) {

            // Observe value is 1 means unregister observation.

            tr_debug("M2MObject::handle_get_request - Stops Observation");

            notifier_stop_observation(&endpoint->notifier, path);
            // Stop observation will internally call the callback if needed.

            received_coap_header->options_list_ptr->observe = (-1);
        }

    }

    return coap_response;

}

#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
static sn_coap_msg_code_e read_attribute_value(const char *query, const char *query_end, uint32_t *int_value, float *float_value, bool *available)
{

    int64_t value64;
    char *value_end;

    if (query_end == query) {
        *available = 0;
        return COAP_MSG_CODE_RESPONSE_CHANGED;
    }

    *available = 1;

    if (int_value) {

        // In value is PMIN or PMAX, both must be positive values.

        value64 = strtoll(query, &value_end, 10);

        if (value64 < 0) {
            return COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
        }

        if (value64 > UINT32_MAX) {
            // UINT32_MAX is the longest value we can handle for PMIN/PMAX
            *int_value = UINT32_MAX;
        } else {
            *int_value = value64;
        }

    } else {
        *float_value = strtof(query, &value_end);
    }

    if (query == value_end) {
        return COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
    }

    return COAP_MSG_CODE_RESPONSE_CHANGED;

}

sn_coap_msg_code_e read_observation_attributes(registry_t* registry, const registry_path_t* path, const char *query)
{

    registry_observation_parameters_t parameters = {0};
    sn_coap_msg_code_e status = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
    registry_status_t registry_status;
    const char *value_start = NULL;
    const char *name_start = query;
    const char *cursor = query;
    size_t query_len = strlen(query);
    bool available;

    registry_status = registry_get_observation_parameters(registry, path, &parameters);

    if (registry_status != REGISTRY_STATUS_OK && registry_status != REGISTRY_STATUS_NO_DATA) {
        return COAP_MSG_CODE_RESPONSE_NOT_FOUND;
    }

    /* stuff that comes in looks like "pmin=20&pmax=30". we start by tokenizing that from each '&' discovered, until end of line is reached. */

    while (cursor != NULL && (*cursor) != '\0') {

        status = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;

        /* look for the next & or EOS */
        const char *amp_or_eos = strchr(cursor, '&');
        if (!amp_or_eos) {
            /* okay, this is the last query param, set end of token to end of string */
            amp_or_eos = query + query_len;
        }

        /* now that we know where to stop looking, we can split the argument into key and value parts at '=' */
        const char *equals_char = strchr(cursor, '=');
        if (equals_char < amp_or_eos) {
            /* value and key can still be zero-length! */
            if (equals_char == cursor || (equals_char + 1) == amp_or_eos) {
                return COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
            }
        }

        /* at this point, cursor should point to start of key, equals_char should to the equals char and
         * amp_or_eos to the end of the value of current argument
         */

        value_start = equals_char + 1;
        name_start = cursor;

        if(value_start - name_start < 3) {

            tr_err("read_observation_attributes() bad request");
            status = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;

        } else if (!strncmp("gt=", name_start, value_start - name_start)) {
            if (path->path_type == REGISTRY_PATH_RESOURCE ||
                path->path_type == REGISTRY_PATH_RESOURCE_INSTANCE) {
                status = read_attribute_value(value_start, amp_or_eos, NULL, &parameters.gt, &available);
                parameters.available.gt = available;
                tr_info("observation_attributes gt %f", parameters.gt);
            }

        } else if (!strncmp("lt=", name_start, value_start - name_start)) {
            if (path->path_type == REGISTRY_PATH_RESOURCE ||
                path->path_type == REGISTRY_PATH_RESOURCE_INSTANCE) {
                status = read_attribute_value(value_start, amp_or_eos, NULL, &parameters.lt, &available);
                parameters.available.lt = available;
                tr_info("observation_attributes lt %f", parameters.lt);
            }

        } else if (!strncmp("st=", name_start, value_start - name_start)) {
            if (path->path_type == REGISTRY_PATH_RESOURCE ||
                path->path_type == REGISTRY_PATH_RESOURCE_INSTANCE) {
                status = read_attribute_value(value_start, amp_or_eos, NULL, &parameters.st, &available);
                parameters.available.st = available;
                tr_info("observation_attributes st %f", parameters.st);
            }

        } else if (!strncmp("pmin=", name_start, value_start - name_start)) {
            status = read_attribute_value(value_start, amp_or_eos, &parameters.pmin, NULL, &available);
            parameters.available.pmin = available;
            tr_info("observation_attributes pmin %" PRIu32, parameters.pmin);

        } else if (!strncmp("pmax=", name_start, value_start - name_start)) {

            status = read_attribute_value(value_start, amp_or_eos, &parameters.pmax, NULL, &available);
            parameters.available.pmax = available;
            tr_info("observation_attributes pmax %" PRIu32, parameters.pmax);

        } else {
            tr_err("read_observation_attributes() looped bad request");
            status = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
        }

        if (status != COAP_MSG_CODE_RESPONSE_CHANGED) {
            break;
        }

        /* move to next query param or end of line */
        if (amp_or_eos < query + query_len) {
            /* jump over the '&' char */
            amp_or_eos++;
        }
        cursor = amp_or_eos;

    }

    if (status == COAP_MSG_CODE_RESPONSE_CHANGED) {
        tr_debug("read_observation_attributes() response changed");
        if (parameters.available.pmax && parameters.available.pmin && parameters.pmax < parameters.pmin) {
            tr_err("read_observation_attributes() bad request (changed pmin)");
            return COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
        }

        if (parameters.available.lt && parameters.available.gt && parameters.lt >= parameters.gt) {
            tr_err("read_observation_attributes() bad request (changed lt/gt)");
            return COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
        }

        if (parameters.available.lt && parameters.available.gt && parameters.available.st  && ((2 * parameters.st) + parameters.lt) >= parameters.gt) {
            tr_err("read_observation_attributes() bad request (all)");
            return COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
        }

        registry_status = registry_set_observation_parameters(registry, path, &parameters);

        if (registry_status != REGISTRY_STATUS_OK) {
            tr_err("read_observation_attributes() bad request (registry set failed): %d", registry_status);
            status = COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR;
        } else {
            notifier_parameters_changed(registry->notifier, path);
        }

    }

    return status;

}
#endif //MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS

static sn_coap_hdr_s* handle_put_request(const registry_path_t* path, endpoint_t *endpoint, sn_coap_hdr_s* received_coap_header)
{

    registry_tlv_serialize_status_t status;
    registry_callback_t callback;
    sn_coap_hdr_s * coap_response;
    const lwm2m_resource_meta_definition_t* resdef;
    bool bootstrap = (endpoint_last_message_sent(endpoint) == ENDPOINT_MSG_BOOTSTRAP);

    coap_response = sn_coap_build_response(endpoint->coap, received_coap_header, COAP_MSG_CODE_RESPONSE_CHANGED);

    if (!coap_response) {
        return NULL;
    }

    coap_response->msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;

    if (!received_coap_header) {
        return coap_response;
    }

    /* Check if Server wants to change observation parameters. */
    if (received_coap_header->options_list_ptr &&
        received_coap_header->options_list_ptr->uri_query_ptr) {

#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
        tr_debug("handle_put_request() options list and query present");

        // create a null terminated string to read_observation_attributes()
        char *query = lwm2m_alloc_string_copy(received_coap_header->options_list_ptr->uri_query_ptr,
                                              received_coap_header->options_list_ptr->uri_query_len);
        if (!query) {
            // COAP_MSG_CODE_RESPONSE_BAD_REQUEST
            return coap_response;
        }

        coap_response->msg_code = read_observation_attributes(&endpoint->registry, path, query);

        lwm2m_free(query);
        tr_debug("handle_put_request() read_observation_attributes() returned: %d", coap_response->msg_code);
#else
        tr_debug("handle_put_request() MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS not enabled coap returns: returned: %d", coap_response->msg_code);
#endif


        return coap_response;

    }

    /* the other option is that Server wants to replace some data in our objects/resources */

    // If not in bootstrap mode PUT not allowed at object.
    if (!bootstrap && path->path_type < REGISTRY_PATH_OBJECT_INSTANCE) {
        coap_response->msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
        return coap_response;
    }

    if (path->path_type == REGISTRY_PATH_RESOURCE || path->path_type == REGISTRY_PATH_RESOURCE_INSTANCE) {

        if (registry_meta_get_resource_definition(path->object_id, path->resource_id, &resdef) != REGISTRY_STATUS_OK) {
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_NOT_FOUND;
            return coap_response;
        }

        if (!(resdef->operations & LWM2M_RESOURCE_OPERATIONS_W)) {

            // Operation is not allowed.
            tr_error("M2MObjectInstance::handle_put_request() - COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED");
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
            return coap_response;
        }

    }

    if ((path->path_type == REGISTRY_PATH_RESOURCE && resdef->multiple) ||
        path->path_type <= REGISTRY_PATH_OBJECT_INSTANCE) {

        if (received_coap_header->content_format == COAP_CT_NONE) {
            received_coap_header->content_format = (sn_coap_content_format_e)COAP_CONTENT_OMA_TLV_TYPE;
        }

        if(COAP_CONTENT_OMA_TLV_TYPE != received_coap_header->content_format &&
           COAP_CONTENT_OMA_TLV_TYPE_OLD != received_coap_header->content_format) {
            tr_error("M2MObjectInstance::handle_put_request() - COAP_MSG_CODE_RESPONSE_UNSUPPORTED_CONTENT_FORMAT");
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_UNSUPPORTED_CONTENT_FORMAT;
            return coap_response;

        }

    } else if (COAP_CONTENT_OMA_TLV_TYPE != received_coap_header->content_format &&
            COAP_CONTENT_OMA_TLV_TYPE_OLD != received_coap_header->content_format &&
#if MBED_CLIENT_ENABLE_DESERIALIZE_PLAINTEXT
            COAP_CONTENT_OMA_PLAIN_TEXT_TYPE != received_coap_header->content_format &&
#endif
            COAP_CT_NONE != received_coap_header->content_format) {
        tr_error("M2MObjectInstance::handle_put_request() - COAP_MSG_CODE_RESPONSE_UNSUPPORTED_CONTENT_FORMAT");
        coap_response->msg_code = COAP_MSG_CODE_RESPONSE_UNSUPPORTED_CONTENT_FORMAT;
        return coap_response;
    }

    tr_debug("handle_put_request() - Request Content-Type %d", received_coap_header->content_format);

    if (!received_coap_header->payload_ptr) {
        coap_response->msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
        return coap_response;
    }

    // Note that in Bootstrap Write the PUT operation updates resources instead of replacing.
    if (COAP_CONTENT_OMA_TLV_TYPE == received_coap_header->content_format ||
        COAP_CONTENT_OMA_TLV_TYPE_OLD == received_coap_header->content_format) {

        /* We were told that the data is in TLV format */
        status = registry_deserialize(&endpoint->registry, path, received_coap_header->payload_ptr, received_coap_header->payload_len, bootstrap ? REGISTRY_OPERATION_UPDATE : REGISTRY_OPERATION_REPLACE);

#if MBED_CLIENT_ENABLE_DESERIALIZE_PLAINTEXT
    } else {

        /* by default, we are expecting plain text value */
        coap_response->content_format = (sn_coap_content_format_e)COAP_CONTENT_OMA_PLAIN_TEXT_TYPE;
        status = registry_deserialize_text_resource_instance(&endpoint->registry, path, (const char *)received_coap_header->payload_ptr, received_coap_header->payload_len, bootstrap ? REGISTRY_OPERATION_UPDATE : REGISTRY_OPERATION_REPLACE);
#endif
    }

    switch (status) {
        case REGISTRY_TLV_SERIALIZE_STATUS_OK:
            /* fetch callback function and call it, ignoring return value */
            if (registry_get_callback(&endpoint->registry, path, &callback) == REGISTRY_STATUS_OK) {
                if (!send_callback_data(path, received_coap_header, REGISTRY_CALLBACK_VALUE_UPDATED)) {
                    coap_response->msg_code = COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR;
                    return coap_response;
                }
            }
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_CHANGED;
            break;
        case REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND:
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_NOT_FOUND;
            break;
        case REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR:
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
            break;
        case REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT:
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
            break;
        case REGISTRY_TLV_SERIALIZE_STATUS_NO_MEMORY:
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR;
            break;
        default:
            break;
    }

    return coap_response;

}


static sn_coap_hdr_s* handle_delete_request(const registry_path_t* path, endpoint_t *endpoint, sn_coap_hdr_s* received_coap_header)
{
// This feature is mandatory for bootstrap
#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    sn_coap_hdr_s * coap_response;

    tr_debug("handle_delete_request()");

    coap_response = sn_coap_build_response(endpoint->coap, received_coap_header, COAP_MSG_CODE_RESPONSE_CHANGED);

    if (!coap_response) {
        return NULL;
    }

    coap_response->msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;

    if (!received_coap_header) {
        return coap_response;
    }

    // The “Delete” operation is used for LwM2M Server to delete an Object Instance within the LwM2M Client.
    // TODO! Only in Bootstrap Interface, Delete operation MAY target to “/” URI to delete all the existing Object Instances - except LwM2M Bootstrap - Server Account
    if (path->path_type != REGISTRY_PATH_OBJECT_INSTANCE &&
        (endpoint_last_message_sent(endpoint) != ENDPOINT_MSG_BOOTSTRAP || path->object_id != 0)) {
        coap_response->msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
        return coap_response;
    }

    //TODO: Check if the server has rights to delete this...
    if (REGISTRY_STATUS_OK != registry_remove_object(&endpoint->registry, path, REGISTRY_REMOVE) &&
            (path->path_type != REGISTRY_PATH_OBJECT || path->object_id != 0)) {
        coap_response->msg_code = COAP_MSG_CODE_RESPONSE_NOT_FOUND;
        return coap_response;
    }

    coap_response->msg_code = COAP_MSG_CODE_RESPONSE_DELETED;

    return coap_response;
#else
    (void)path;
    return handle_unsupported_request(endpoint, received_coap_header);
#endif //MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
}

#endif // !defined(MBED_CLOUD_CLIENT_DISABLE_REGISTRY)

static sn_coap_hdr_s* handle_execute_request(const registry_path_t* path, endpoint_t *endpoint,
                                             sn_coap_hdr_s* received_coap_header,
                                             sn_nsdl_addr_s *address, int* execute_value_updated)
{

    sn_coap_hdr_s * coap_response;
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    const lwm2m_resource_meta_definition_t* resdef;
    registry_callback_t callback;
#endif

    tr_debug("handle_execute_request()");

    coap_response = sn_coap_build_response(endpoint->coap, received_coap_header, COAP_MSG_CODE_RESPONSE_CHANGED);

    if (!coap_response) {
        return NULL;
    }

    if (!received_coap_header) {
        coap_response->msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
        return coap_response;
    }

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    if (registry_meta_get_resource_definition(path->object_id, path->resource_id, &resdef) != REGISTRY_STATUS_OK) {
        coap_response->msg_code = COAP_MSG_CODE_RESPONSE_NOT_FOUND;
        return coap_response;
    }

    if (!(resdef->operations & LWM2M_RESOURCE_OPERATIONS_E) || path->path_type != REGISTRY_PATH_RESOURCE) {
        coap_response->msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
        return coap_response;
    }
#endif

    /* only plaintext values are supported at the moment */
    if(received_coap_header->content_format != COAP_CT_TEXT_PLAIN && received_coap_header->content_format != COAP_CT_NONE) {
        coap_response->msg_code = COAP_MSG_CODE_RESPONSE_UNSUPPORTED_CONTENT_FORMAT;
        return coap_response;
    }

    if (endpoint->confirmable_response.pending) {
        coap_response->msg_code = COAP_MSG_CODE_RESPONSE_FORBIDDEN;
        return coap_response;
    }

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    /* check if a callback exists, and queue for calling it if it does */
    if (registry_get_callback(&endpoint->registry, path, &callback) == REGISTRY_STATUS_OK) {
        if (send_callback_data(path, received_coap_header, REGISTRY_CALLBACK_EXECUTE)) {
            endpoint->confirmable_response.pending = true;
            coap_response->msg_code = COAP_MSG_CODE_EMPTY;
            endpoint_send_coap_message(endpoint, address, coap_response);
            *execute_value_updated = 1;
        } else {
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR;
        }
#else
    /* check if callback exists, and pass the request on for further processing if it does */
    coap_req_cb *callback = endpoint_get_coap_request_callback(endpoint, path->object_id);
    if (callback) {
        coap_response = callback(path, endpoint, received_coap_header, address, coap_response, execute_value_updated);
#endif
    } else {
        coap_response->msg_code = COAP_MSG_CODE_RESPONSE_NOT_FOUND;
    }

    return coap_response;

}

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
static sn_coap_hdr_s* handle_create_request(registry_path_t* path, endpoint_t *endpoint,
                                            sn_coap_hdr_s* received_coap_header,
                                            sn_nsdl_addr_s *address, int* execute_value_updated)
{
#ifdef MBED_CLIENT_ENABLE_DYNAMIC_CREATION
    sn_coap_hdr_s * coap_response;
    registry_tlv_serialize_status_t status;
    char *object_path;

    tr_debug("handle_create_request()");

    coap_response = sn_coap_build_response(endpoint->coap, received_coap_header, COAP_MSG_CODE_RESPONSE_CHANGED);

    if (!coap_response) {
        return NULL;
    }

    if (!received_coap_header) {
        coap_response->msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
        return coap_response;
    }

    tr_debug("handle_create_request() - Request Content-Type %d", received_coap_header->content_format);


    if (!received_coap_header->payload_ptr) {
        coap_response->msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
        return coap_response;
    }

    if (received_coap_header->content_format == COAP_CT_NONE) {
        received_coap_header->content_format = (sn_coap_content_format_e)COAP_CONTENT_OMA_TLV_TYPE;
    }

    if ((COAP_CONTENT_OMA_TLV_TYPE != received_coap_header->content_format) &&
        (COAP_CONTENT_OMA_TLV_TYPE_OLD != received_coap_header->content_format)) {

        coap_response->msg_code = COAP_MSG_CODE_RESPONSE_UNSUPPORTED_CONTENT_FORMAT;
        return coap_response;
    }

    /* We were told that the data is in TLV format */

    /* create new instance */
    if (registry_add_instance(&endpoint->registry, path) != REGISTRY_STATUS_OK) {
        coap_response->msg_code = COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR;
        return coap_response;
    }

    /* new instance was created, path contains the information*/
    status = registry_deserialize(&endpoint->registry, path, received_coap_header->payload_ptr, received_coap_header->payload_len, REGISTRY_OPERATION_UPDATE);

    switch(status) {
        case REGISTRY_TLV_SERIALIZE_STATUS_OK:
            /* Stuff was deserialized into registry properly, Client needs to report the object instance back to Server */
            coap_response->options_list_ptr = sn_coap_parser_alloc_options(endpoint->coap, coap_response);

            if (!coap_response->options_list_ptr) {
                coap_response->msg_code = COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR;
                return coap_response;
            }

            object_path = registry_path_to_string(path);
            if (!object_path) {
                coap_response->msg_code = COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR;
                return coap_response;
            }

            coap_response->options_list_ptr->location_path_len = strlen(object_path);
            coap_response->options_list_ptr->location_path_ptr = (uint8_t*)object_path;

            /* fetch callback function and call it, ignoring return value */
            registry_callback_t callback;
            if (registry_get_callback(&endpoint->registry, path, &callback) == REGISTRY_STATUS_OK) {
                if (!send_callback_data(path, received_coap_header, REGISTRY_CALLBACK_VALUE_UPDATED)) {
                    coap_response->msg_code = COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR;
                    return coap_response;
                }
            }
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
            break;
        case REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND:
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_NOT_FOUND;
            break;
        case REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR:
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
            break;
        case REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT:
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
            break;
        case REGISTRY_TLV_SERIALIZE_STATUS_NO_MEMORY:
            coap_response->msg_code = COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_TOO_LARGE;
            break;
        default:
            break;
    }

    return coap_response;
#else
    (void)path;
    return handle_unsupported_request(endpoint, received_coap_header);
#endif //MBED_CLIENT_ENABLE_DYNAMIC_CREATION
}
#endif // !defined(MBED_CLOUD_CLIENT_DISABLE_REGISTRY)

static sn_coap_hdr_s* handle_post_request(registry_path_t* path, endpoint_t *endpoint,
                                          sn_coap_hdr_s* received_coap_header,
                                          sn_nsdl_addr_s *address, int* execute_value_updated)
{


    if (path->path_type == REGISTRY_PATH_RESOURCE) {

        return handle_execute_request(path, endpoint, received_coap_header, address, execute_value_updated);

    }
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
     else if (path->path_type == REGISTRY_PATH_OBJECT || path->path_type == REGISTRY_PATH_OBJECT_INSTANCE) {
        return handle_create_request(path, endpoint, received_coap_header, address, execute_value_updated);
    }
#endif

    return NULL;

}

void handle_coap_request(endpoint_t *endpoint,
                         sn_coap_hdr_s *received_coap_header,
                         sn_nsdl_addr_s *address)
{

    int execute_value_updated = 0;
    sn_coap_hdr_s *coap_response = NULL;
    sn_coap_msg_code_e msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST; // 4.00
    registry_path_t regpath;
    uint8_t regpath_depth;

    regpath_depth = parse_registry_path(received_coap_header->uri_path_ptr, received_coap_header->uri_path_len, &regpath);

    if (received_coap_header->coap_status == COAP_STATUS_PARSER_BLOCKWISE_ACK ||
        received_coap_header->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVING) {
        tr_debug("endpoint_handle_response() ignoring block as COAP should handle it.");
        //TODO: Add possibility for application to handle the blocks.
        return;
    }

    tr_debug("handle_coap_request() - resource_name %.*s",  received_coap_header->uri_path_len, received_coap_header->uri_path_ptr);

    if (regpath_depth > 0) {
        /* now we need to figure out if the request type matches the path type */
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
        if (COAP_MSG_CODE_REQUEST_GET == received_coap_header->msg_code) {
            coap_response = handle_get_request(&regpath, endpoint, received_coap_header);
        } else if (COAP_MSG_CODE_REQUEST_PUT == received_coap_header->msg_code) {
            coap_response = handle_put_request(&regpath, endpoint, received_coap_header);
        } else if (COAP_MSG_CODE_REQUEST_DELETE == received_coap_header->msg_code) {
            coap_response = handle_delete_request(&regpath, endpoint, received_coap_header);
        } else
#endif
        if (COAP_MSG_CODE_REQUEST_POST == received_coap_header->msg_code) {
            if (regpath.path_type == REGISTRY_PATH_RESOURCE_INSTANCE) {
                msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
            } else {
                coap_response = handle_post_request(&regpath, endpoint,
                                                          received_coap_header,
                                                          address, &execute_value_updated);
                //TODO: block transfer...
            }
        }
#ifdef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
        else {
            // only execute requests are supported without registry
            msg_code = COAP_MSG_CODE_RESPONSE_NOT_FOUND; // 4.04
        }
#endif
    } else {
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
        if (COAP_MSG_CODE_REQUEST_POST == received_coap_header->msg_code &&
            0 == memcmp(received_coap_header->uri_path_ptr, "bs", received_coap_header->uri_path_len)) {
            msg_code = COAP_MSG_CODE_RESPONSE_CHANGED;
            tr_info("handle_coap_request() Sending event ENDPOINT_EVENT_BOOTSTRAP_READY");
            endpoint_send_event(endpoint, ENDPOINT_EVENT_BOOTSTRAP_READY, received_coap_header->coap_status);
        } else
#endif
        {
            tr_warn("handle_coap_request() - Path parsing failed.");
            msg_code = COAP_MSG_CODE_RESPONSE_NOT_FOUND; // 4.04
        }
    }

    if (!coap_response) {
        coap_response = sn_coap_build_response(endpoint->coap,
                                               received_coap_header,
                                               msg_code);
    }

    if (coap_response && (execute_value_updated == 0)) {

        tr_debug("handle_coap_request() - response code: %d", coap_response->msg_code);
        endpoint_send_coap_message(endpoint, address, coap_response);

        lwm2m_free(coap_response->payload_ptr);
    }

    // TODO: implement blockwise receiver

    sn_coap_parser_release_allocated_coap_msg_mem(endpoint->coap, coap_response);
}

bool handle_coap_response(endpoint_t* endpoint, sn_coap_hdr_s *received_coap_header)
{
    registry_callback_t callback;

    if (received_coap_header->msg_id == endpoint->confirmable_response.msg_id) {

        if (received_coap_header->coap_status == COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED) {
            endpoint_send_event(endpoint, ENDPOINT_EVENT_ERROR_TIMEOUT, received_coap_header->coap_status);
        }
        endpoint->confirmable_response.pending = false;
        endpoint->confirmable_response.msg_id = 0;
        if (endpoint->confirmable_response.notify_result) {
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
            if (registry_get_callback(&endpoint->registry, &endpoint->confirmable_response.path, &callback) == REGISTRY_STATUS_OK) {
                callback(REGISTRY_CALLBACK_EXECUTE, &endpoint->confirmable_response.path, NULL, NULL, NOTIFICATION_STATUS_DELIVERED, &endpoint->registry);
            }
#else
            callback = endpoint_get_object_callback(endpoint, endpoint->confirmable_response.path.object_id);
            if (callback) {
                callback(REGISTRY_CALLBACK_EXECUTE, &endpoint->confirmable_response.path, NULL, NULL, NOTIFICATION_STATUS_DELIVERED, endpoint);
            }
#endif
        }
        send_queue_sent(endpoint, true);

        return true;

    }

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    if (received_coap_header->msg_type == COAP_MSG_TYPE_RESET) {

        return handle_coap_notification_response(&endpoint->registry, received_coap_header, NOTIFICATION_STATUS_UNSUBSCRIBED);

    } else if (received_coap_header->msg_type == COAP_MSG_TYPE_ACKNOWLEDGEMENT || received_coap_header->coap_status == COAP_STATUS_BUILDER_BLOCK_SENDING_DONE) {

        return handle_coap_notification_response(&endpoint->registry, received_coap_header, NOTIFICATION_STATUS_DELIVERED);

    } else if (received_coap_header->coap_status == COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED || received_coap_header->coap_status == COAP_STATUS_BUILDER_BLOCK_SENDING_FAILED) {

        if (handle_coap_notification_response(&endpoint->registry, received_coap_header, NOTIFICATION_STATUS_SEND_FAILED)) {
            endpoint_send_event(endpoint, ENDPOINT_EVENT_ERROR_TIMEOUT, received_coap_header->coap_status);
        }

    }
#else
    if (received_coap_header->coap_status == COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED) {
        callback = endpoint_get_object_callback(endpoint, endpoint->confirmable_response.path.object_id);
        if (callback) {
            callback(REGISTRY_CALLBACK_EXECUTE, &endpoint->confirmable_response.path, NULL, NULL, NOTIFICATION_STATUS_SEND_FAILED, endpoint);
        }
        endpoint_send_event(endpoint, ENDPOINT_EVENT_ERROR_TIMEOUT, received_coap_header->coap_status);
    }
#endif

    return false;

}

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
static bool handle_coap_notification_response(registry_t* registry, sn_coap_hdr_s *received_coap_header, registry_notification_status_t notification_status)
{

    registry_callback_t callback;

    if (registry->notifier->message_id != received_coap_header->msg_id) {
        return false;
    }

    // On block case we only wait for block status.
    if (registry->notifier->block_notify && NOTIFICATION_STATUS_UNSUBSCRIBED != notification_status &&
        received_coap_header->coap_status != COAP_STATUS_BUILDER_BLOCK_SENDING_DONE &&
        received_coap_header->coap_status != COAP_STATUS_BUILDER_BLOCK_SENDING_FAILED) {
        return false;
    }

    if (NOTIFICATION_STATUS_UNSUBSCRIBED == notification_status) {

        notifier_stop_observation(registry->notifier, &registry->notifier->last_notified);
        // Stop observation will internally call the callback if needed.
        return true;

    }

    notifier_notification_sent(registry->notifier,
                               (notification_status == NOTIFICATION_STATUS_DELIVERED),
                               &registry->notifier->last_notified);

    if (registry_get_callback(registry, &registry->notifier->last_notified, &callback) == REGISTRY_STATUS_OK) {
        callback(REGISTRY_CALLBACK_NOTIFICATION_STATUS, &registry->notifier->last_notified, NULL, NULL, notification_status, registry);
    }

    return true;

}
#endif // !defined(MBED_CLOUD_CLIENT_DISABLE_REGISTRY)

void send_execute_response(const registry_path_t* path,
                           endpoint_t *endpoint,
                           const uint8_t *token,
                           const uint8_t token_length,
                           const sn_coap_msg_code_e msg_code)
{
    send_final_response(path, endpoint, token, token_length, msg_code, false);
}

void send_final_response(const registry_path_t* path,
                           endpoint_t *endpoint,
                           const uint8_t *token,
                           const uint8_t token_length,
                           const sn_coap_msg_code_e msg_code,
                           const bool notify_result)
{
    assert(token_length <= MAX_TOKEN_SIZE);

    memcpy(endpoint->confirmable_response.token, token, token_length);
    endpoint->confirmable_response.token_length = token_length;
    endpoint->confirmable_response.msg_code = msg_code;
    endpoint->confirmable_response.pending = true;
    memcpy(&endpoint->confirmable_response.path, path, sizeof(registry_path_t));
    endpoint->confirmable_response.notify_result = notify_result;

    send_queue_request(endpoint, SEND_QUEUE_RESPONSE);
}

void response_message_send(endpoint_t *endpoint)
{
    sn_coap_hdr_s coap_response;
    registry_callback_t callback;

    memset(&coap_response, 0, sizeof(sn_coap_hdr_s));

    coap_response.msg_type = COAP_MSG_TYPE_CONFIRMABLE;
    coap_response.msg_code = endpoint->confirmable_response.msg_code;

    coap_response.token_ptr = endpoint->confirmable_response.token;
    coap_response.token_len = endpoint->confirmable_response.token_length;

    coap_response.payload_ptr = NULL;
    coap_response.payload_len = 0;

    if (ENDPOINT_STATUS_OK != endpoint_send_coap_message(endpoint, NULL, &coap_response)) {
        tr_error("execute_response_message_send(), endpoint_send_coap_message() failed");
        send_queue_sent(endpoint, true);
        endpoint->confirmable_response.pending = false;
        endpoint->confirmable_response.msg_id = 0;
        if (endpoint->confirmable_response.notify_result) {
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
            if (registry_get_callback(&endpoint->registry, &endpoint->confirmable_response.path, &callback) == REGISTRY_STATUS_OK) {
                callback(REGISTRY_CALLBACK_EXECUTE, &endpoint->confirmable_response.path, NULL, NULL, NOTIFICATION_STATUS_SEND_FAILED, &endpoint->registry);
            }
#else
            callback = endpoint_get_object_callback(endpoint, endpoint->confirmable_response.path.object_id);
            if (callback) {
                callback(REGISTRY_CALLBACK_EXECUTE, &endpoint->confirmable_response.path,  NULL, NULL, NOTIFICATION_STATUS_SEND_FAILED, endpoint);
            }
#endif
        }

    } else {
        endpoint->confirmable_response.msg_id = coap_response.msg_id;
    }

    lwm2m_free(coap_response.payload_ptr);
}

bool send_callback_data(const registry_path_t *path,
                        const sn_coap_hdr_s *received_coap_header,
                        const uint8_t type)
{
    callback_data_t *callback_data = lwm2m_alloc(sizeof(callback_data_t));

    if (!callback_data) {
        return false;
    }

    // Copy token
    assert(received_coap_header->token_len <= sizeof(callback_data->cb_token.token));

    callback_data->cb_token.token_size = received_coap_header->token_len;
    memcpy(&callback_data->cb_token.token, received_coap_header->token_ptr, received_coap_header->token_len);

    // Copy data
    callback_data->cb_opaque_data = lwm2m_alloc(received_coap_header->payload_len + sizeof(registry_data_opaque_t));
    if (!callback_data->cb_opaque_data) {
        lwm2m_free(callback_data);
        return false;
    }

    callback_data->cb_opaque_data->size = received_coap_header->payload_len;
    memcpy(callback_data->cb_opaque_data->data, received_coap_header->payload_ptr, received_coap_header->payload_len);
    callback_data->cb_value.generic_value.data.opaque_data = callback_data->cb_opaque_data;

    // Copy path
    memcpy(&callback_data->path, path, sizeof(registry_path_t));

    callback_handler_send_event(callback_data, type);
    return true;
}
