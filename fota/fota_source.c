// ----------------------------------------------------------------------------
// Copyright 2018-2019 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#include "fota/fota_base.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#include "fota/fota_source.h"
#include "fota/fota_source_defs.h"
#include "fota/fota_crypto_defs.h"
#include "fota/fota_status.h"
#include "fota/fota_internal.h"
#include "fota/fota_event_handler.h"

#include "mbed-client/lwm2m_endpoint.h"
#include "mbed-client/lwm2m_get_req_handler.h"
#include "device-management-client/lwm2m_registry_handler.h"

#include <stdlib.h>

#define PROTOCOL_VERSION 3

static endpoint_t *endpoint = 0;
static registry_t *registry;

const int64_t default_int_val = -1;

static bool initialized = false;
static report_sent_callback_t g_on_sent_callback = NULL;
static report_sent_callback_t g_on_failure_callback = NULL;

static registry_path_t execute_path = { 0 };
static registry_callback_token_t execute_token = { 0 };

static void cleanup(void)
{

}


static registry_status_t got_manifest_callback(registry_callback_type_t type,
                                               const registry_path_t *path,
                                               const registry_callback_token_t *token,
                                               const registry_object_value_t *value,
                                               const registry_notification_status_t status,
                                               registry_t *registry)
{
    registry_status_t callback_status = REGISTRY_STATUS_OK;
    sn_coap_msg_code_e response = COAP_MSG_CODE_RESPONSE_CHANGED;
    fota_state_e fota_state = fota_is_ready(value->generic_value.data.opaque_data->data,
                                            value->generic_value.data.opaque_data->size);
    switch (fota_state) {
        case FOTA_STATE_IDLE: {
            registry_path_t res_path;

            registry_set_path(&res_path, FOTA_SOURCE_PACKAGE_OBJECT_ID, 0, FOTA_SOURCE_STATE_RESOURCE_ID,
                              0, REGISTRY_PATH_RESOURCE);
            if (REGISTRY_STATUS_OK != registry_set_value_int(registry, &res_path, default_int_val)) {
                FOTA_DBG_ASSERT(!"registry_set_value_int failed");
            }

            registry_set_path(&res_path, FOTA_SOURCE_PACKAGE_OBJECT_ID, 0, FOTA_SOURCE_UPDATE_RESULT_RESOURCE_ID,
                              0, REGISTRY_PATH_RESOURCE);
            if (REGISTRY_STATUS_OK != registry_set_value_empty(registry, &res_path, true)) {
                FOTA_DBG_ASSERT(!"registry_set_value_empty failed");
            }

            memcpy(&execute_token, token, sizeof(execute_token));
            memcpy(&execute_path, path, sizeof(execute_path));

            fota_event_handler_defer_with_data(
                fota_on_manifest,
                value->generic_value.data.opaque_data->data,
                value->generic_value.data.opaque_data->size
            );
            break;
        }
        case FOTA_STATE_INVALID:
            FOTA_TRACE_ERROR("FOTA cannot handle manifest - rejecting");
            response = COAP_MSG_CODE_RESPONSE_SERVICE_UNAVAILABLE;
            callback_status = REGISTRY_STATUS_ALREADY_EXISTS;
        // fallthrough
        default:
            send_final_response(
                path, registry->notifier->endpoint,
                token->token, token->token_size,
                response, false
            );
    }

    // Reset tainted buffer
    memset(value->generic_value.data.opaque_data->data, 0, value->generic_value.data.opaque_data->size);

    return callback_status;
}


void fota_source_send_manifest_received_ack(void)
{
    FOTA_ASSERT(execute_token.token_size);
    FOTA_DBG_ASSERT(endpoint);
    send_final_response(
        &execute_path, endpoint,
        execute_token.token, execute_token.token_size,
        COAP_MSG_CODE_RESPONSE_CHANGED, false
    );
    memset(&execute_token, 0, sizeof(execute_token));
    memset(&execute_path, 0,  sizeof(execute_path));
}


static registry_status_t notification_status(registry_callback_type_t type,
                                             const registry_path_t *path,
                                             const registry_callback_token_t *token,
                                             const registry_object_value_t *value,
                                             const registry_notification_status_t delivery_status,
                                             registry_t *registry)
{
    (void)token;
    (void)value;
    (void)registry;

    FOTA_TRACE_DEBUG(
        "Callback for resource: /%d/%d/%d status: %d type: %d",
        path->object_id,
        path->object_instance_id,
        path->resource_id,
        (int)delivery_status,
        (int)type
    );

    if (REGISTRY_CALLBACK_NOTIFICATION_STATUS != type) {
        return REGISTRY_STATUS_OK;
    }

    report_sent_callback_t callback = NULL;
    switch (delivery_status) {
        case NOTIFICATION_STATUS_DELIVERED:
            // Notification has been ACKed by server, complete to callback
            callback = g_on_sent_callback;
            break;
        case NOTIFICATION_STATUS_BUILD_ERROR:  // fall through
        case NOTIFICATION_STATUS_RESEND_QUEUE_FULL:  // fall through
        case NOTIFICATION_STATUS_SEND_FAILED:  // fall through
        case NOTIFICATION_STATUS_UNSUBSCRIBED:
            FOTA_TRACE_ERROR(
                "Received Notification delivery resource: /%d/%d/%d status: %d - ERROR!",
                path->object_id,
                path->object_instance_id,
                path->resource_id,
                delivery_status
            );
            callback = g_on_failure_callback;
            break;
        default:
            return REGISTRY_STATUS_OK;
    }


    g_on_sent_callback = NULL;
    g_on_failure_callback = NULL;
    if (callback) {
        callback();
    }
    return REGISTRY_STATUS_OK;
}

#if FOTA_SOURCE_COMPONENT_BACKWARD_COMPATIBILITY_MODE
/*
 * Converting binary array to hex string
 *
 * /param in[in] binary array to convert
 * /param input_size[in] binary array size
 * /param out[out] buffer should be allocated in calling function doubled size plus one for null termination.
 * /param output_size[in] output hex string length
 *
 */

static void bin_to_hex_string(const uint8_t *in, size_t input_size, uint8_t *out, size_t output_size)
{
    FOTA_DBG_ASSERT(in && out && input_size != 0 && (input_size * 2 + 1) == output_size);

    const uint8_t *p_in = in;
    const char *hex_arr = "0123456789ABCDEF";

    uint8_t *p_out = out;

    for (; p_in < in + input_size; p_out += 2, p_in++) {
        p_out[0] = hex_arr[(*p_in >> 4) & 0xF];
        p_out[1] = hex_arr[*p_in & 0xF];
    }

    p_out[0] = 0;
}
#endif

int fota_source_init(
    endpoint_t *in_endpoint,
    const uint8_t *vendor_id, uint32_t vendor_id_size,
    const uint8_t *class_id, uint32_t class_id_size,
#if FOTA_SOURCE_COMPONENT_BACKWARD_COMPATIBILITY_MODE
    const uint8_t *curr_fw_digest, uint32_t curr_fw_digest_size,
    uint64_t curr_fw_version,
#endif
    fota_source_state_e source_state)
{

#if FOTA_SOURCE_COMPONENT_BACKWARD_COMPATIBILITY_MODE
    uint8_t str_digest[FOTA_CRYPTO_HASH_SIZE * 2 + 1];
#endif

    if (initialized) {
        return FOTA_STATUS_SUCCESS;
    }

    endpoint = in_endpoint;
    registry = &endpoint->registry;
    registry_path_t path;

    // Create package resource /10252/0/1
    registry_set_path(&path, FOTA_SOURCE_PACKAGE_OBJECT_ID, 0, FOTA_SOURCE_PACKAGE_RESOURCE_ID,
                      0, REGISTRY_PATH_RESOURCE);
    if (REGISTRY_STATUS_OK != registry_set_value_empty(registry, &path, true) ||
            REGISTRY_STATUS_OK != registry_set_callback(registry, &path, got_manifest_callback)) {
        goto fail;
    }

    // Create state resource /10252/0/2
    registry_set_path(&path, FOTA_SOURCE_PACKAGE_OBJECT_ID, 0, FOTA_SOURCE_STATE_RESOURCE_ID,
                      0, REGISTRY_PATH_RESOURCE);
    if (REGISTRY_STATUS_OK != registry_set_value_int(registry, &path, source_state) ||
            REGISTRY_STATUS_OK != registry_set_callback(registry, &path, notification_status) ||
            REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
            REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {
        goto fail;
    }

    // Create update result resource /10252/0/3
    registry_set_path(&path, FOTA_SOURCE_PACKAGE_OBJECT_ID, 0, FOTA_SOURCE_UPDATE_RESULT_RESOURCE_ID,
                      0, REGISTRY_PATH_RESOURCE);
    if (REGISTRY_STATUS_OK != registry_set_value_int(registry, &path, default_int_val) ||
            REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
            REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {
        goto fail;
    }

    // Create protocol supported resource  /10255/0/0
    registry_set_path(&path, FOTA_SOURCE_UPDATE_OBJECT_ID, 0, FOTA_SOURCE_PROTOCOL_SUPP_RESOURCE_ID,
                      0, REGISTRY_PATH_RESOURCE);
    if (REGISTRY_STATUS_OK != registry_set_value_int(registry, &path, PROTOCOL_VERSION) ||
            REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
            REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {
        goto fail;
    }

    // Create vendor resource /10255/0/2
    registry_set_path(&path, FOTA_SOURCE_UPDATE_OBJECT_ID, 0, FOTA_SOURCE_VENDOR_RESOURCE_ID,
                      0, REGISTRY_PATH_RESOURCE);
    if (REGISTRY_STATUS_OK != registry_set_value_opaque_copy(registry, &path, vendor_id,
                                                             vendor_id_size) ||
            REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
            REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {
        goto fail;
    }

    // Create class resource  /10255/0/4
    registry_set_path(&path, FOTA_SOURCE_UPDATE_OBJECT_ID, 0, FOTA_SOURCE_CLASS_RESOURCE_ID,
                      0, REGISTRY_PATH_RESOURCE);
    if (REGISTRY_STATUS_OK != registry_set_value_opaque_copy(registry, &path, class_id,
                                                             class_id_size) ||
            REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
            REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {
        goto fail;
    }

#if FOTA_SOURCE_COMPONENT_BACKWARD_COMPATIBILITY_MODE
    // Create package name resource /10252/0/5
    FOTA_DBG_ASSERT(curr_fw_digest_size == FOTA_CRYPTO_HASH_SIZE);

    bin_to_hex_string(curr_fw_digest, FOTA_CRYPTO_HASH_SIZE, str_digest, FOTA_CRYPTO_HASH_SIZE * 2 + 1);

    registry_set_path(&path, FOTA_SOURCE_PACKAGE_OBJECT_ID, 0, FOTA_SOURCE_PKG_NAME_RESOURCE_ID,
                      0, REGISTRY_PATH_RESOURCE);
    if (REGISTRY_STATUS_OK != registry_set_value_string_copy(registry, &path, str_digest, FOTA_CRYPTO_HASH_SIZE * 2) ||
            REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
            REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {
        goto fail;
    }

    // Create package version resource /10252/0/6
    registry_set_path(&path, FOTA_SOURCE_PACKAGE_OBJECT_ID, 0, FOTA_SOURCE_PKG_VERSION_RESOURCE_ID,
                      0, REGISTRY_PATH_RESOURCE);

    if (REGISTRY_STATUS_OK != registry_set_value_int(registry, &path, curr_fw_version) ||
            REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
            REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {
        goto fail;
    }
#endif

    initialized = true;
    return FOTA_STATUS_SUCCESS;

fail:
    cleanup();
    return FOTA_STATUS_INTERNAL_ERROR;
}

int fota_source_add_component(unsigned int comp_id, const char *name, const char *sem_ver)
{
#if !FOTA_SOURCE_COMPONENT_BACKWARD_COMPATIBILITY_MODE
    registry_path_t path;

    // Create Component Identity resource /14/<comp_id>/0
    registry_set_path(&path, FOTA_SOURCE_SW_COMPONENT_OBJECT_ID, comp_id, FOTA_SOURCE_COMP_NAME_RESOURCE_ID,
                      0, REGISTRY_PATH_RESOURCE);
    if (REGISTRY_STATUS_OK != registry_set_value_string_copy(registry, &path, (uint8_t *) name, strlen(name) + 1) ||
            REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
            REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    // Create Component Version resource /14/<comp_id>/2
    registry_set_path(&path, FOTA_SOURCE_SW_COMPONENT_OBJECT_ID, comp_id, FOTA_SOURCE_COMP_VERSION_RESOURCE_ID,
                      0, REGISTRY_PATH_RESOURCE);
    if (REGISTRY_STATUS_OK != registry_set_value_string_copy(registry, &path, (uint8_t *) sem_ver, strlen(sem_ver) + 1) ||
            REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
            REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }
#endif
    return FOTA_STATUS_SUCCESS;
}

int fota_source_deinit(void)
{
    if (!initialized) {
        return FOTA_STATUS_SUCCESS;
    }

    cleanup();

    initialized = false;

    registry_path_t path;
    registry_set_path(&path, FOTA_SOURCE_PACKAGE_OBJECT_ID, 0, 0, 0, REGISTRY_PATH_OBJECT);
    registry_remove_object(registry, &path, REGISTRY_REMOVE);
    registry_set_path(&path, FOTA_SOURCE_UPDATE_OBJECT_ID, 0, 0, 0, REGISTRY_PATH_OBJECT);
    registry_remove_object(registry, &path, REGISTRY_REMOVE);
    registry_set_path(&path, FOTA_SOURCE_SW_COMPONENT_OBJECT_ID, 0, 0, 0, REGISTRY_PATH_OBJECT);
    registry_remove_object(registry, &path, REGISTRY_REMOVE);

    return FOTA_STATUS_SUCCESS;
}

static int report_int(int vlaue, int16_t resource_id, report_sent_callback_t on_sent, report_sent_callback_t on_failure)
{
    FOTA_DBG_ASSERT(!g_on_sent_callback);
    FOTA_DBG_ASSERT(!g_on_failure_callback);

    // must assign values before calling registry_set_value_int because of special way unit-tests are implemented
    g_on_sent_callback = on_sent;
    g_on_failure_callback = on_failure;

    registry_path_t path;
    registry_set_path(&path, FOTA_SOURCE_PACKAGE_OBJECT_ID, 0, resource_id,
                      0, REGISTRY_PATH_RESOURCE);
    FOTA_TRACE_DEBUG("Reporting resource: /%d/%d/%d: value: %d", path.object_id, path.object_instance_id, path.resource_id, vlaue);
    if (REGISTRY_STATUS_OK != registry_set_value_int(registry, &path, vlaue)) {
        g_on_sent_callback = NULL;
        g_on_failure_callback = NULL;
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    return FOTA_STATUS_SUCCESS;

}

int fota_source_report_state(fota_source_state_e state, report_sent_callback_t on_sent, report_sent_callback_t on_failure)
{
    return report_int((int)state, FOTA_SOURCE_STATE_RESOURCE_ID, on_sent, on_failure);  // 10252/0/2
}

int fota_source_report_update_result(int result)
{
    return report_int(result, FOTA_SOURCE_UPDATE_RESULT_RESOURCE_ID, NULL, NULL);  // 10252/0/3
}

static void data_req_callback(const uint8_t *buffer, size_t buffer_size, size_t total_size, bool last_block,
                              void *context)
{
    bool is_active = fota_is_active_update();
    if (is_active) {
        // removing const qualifier here allows FOTA the manipulation of fragment data in place (like encryption).
        // TODO: Need to decide whether this is legit. If so, all preceding LWM2M calls should also remove this qualifier.
        fota_on_fragment((uint8_t *)buffer, buffer_size);
    } else {
        FOTA_TRACE_ERROR("Fragment received ignored - FOTA not ready");
    }
}

static void data_req_error_callback(get_data_req_error_t error_code, void *context)
{
    bool is_active = fota_is_active_update();
    if (is_active) {
        fota_event_handler_defer_with_result(fota_on_fragment_failure, 0, (int32_t)error_code);
    } else {
        FOTA_TRACE_ERROR("Fragment received error ignored - FOTA not ready");
    }
}

int fota_source_firmware_request_fragment(const char *uri, uint32_t offset)
{
    get_handler_send_get_data_request(endpoint, FIRMWARE_DOWNLOAD, uri, offset, true, // TODO: verify async = True
                                      data_req_callback, data_req_error_callback, NULL);

    return FOTA_STATUS_SUCCESS;
}

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
