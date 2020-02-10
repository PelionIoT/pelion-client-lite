// ----------------------------------------------------------------------------
// Copyright 2019 ARM Ltd.
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
#ifndef RAM
#define RAM 1113
#endif

// default to RAM if not set and in developer mode
#if !defined(MBED_CONF_MBED_CLOUD_CLIENT_STORAGE_TYPE) && MBED_CONF_APP_DEVELOPER_MODE == 1
#define MBED_CONF_MBED_CLOUD_CLIENT_STORAGE_TYPE RAM
#endif

#define DEVICE_KEY_SIZE_IN_BYTES (128/8)

#if MBED_CONF_MBED_CLOUD_CLIENT_STORAGE_TYPE == RAM
#if !defined(MBED_CONF_APP_DEVELOPER_MODE) || MBED_CONF_APP_DEVELOPER_MODE == 0
error "RAM storage can only be used in developer mode"
#endif //!defined(MBED_CONF_APP_DEVELOPER_MODE)

// Note: this macro is needed on armcc to get the the limit macros like UINT16_MAX
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include "CloudClientStorage.h"
#include "mbed-trace/mbed_trace.h"
#include "protoman.h"
#include "lwm2m_constants.h"

#include <inttypes.h>
#include <string.h>

static const char *bootstrap_endpoint_name;
static size_t bootstrap_endpoint_name_len;
static const char *bootstrap_uri;
static size_t bootstrap_uri_len;
static char internal_endpoint_name[MAX_ALLOWED_STRING_LENGTH]; //No null-termination.
static size_t internal_endpoint_name_len;
static char lwm2m_uri[MAX_VALUE_LENGTH - 1]; //No null-termination.
static size_t lwm2m_uri_len;
static uint8_t rot[DEVICE_KEY_SIZE_IN_BYTES];
static size_t rot_len;

#if defined(PROTOMAN_SECURITY_ENABLE_PSK)
static const uint8_t *bootstrap_psk_secret;
static size_t bootstrap_psk_secret_len;
static const uint8_t *bootstrap_psk_id;
static size_t bootstrap_psk_id_len;
static uint8_t lwm2m_psk_secret[MAX_ALLOWED_PSK_SIZE];
static size_t lwm2m_psk_secret_len;
static uint8_t lwm2m_psk_id[MAX_ALLOWED_PSK_SIZE];
static size_t lwm2m_psk_id_len;
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
static const uint8_t *update_psk_id;
static size_t update_psk_id_len;
static const uint8_t *update_psk;
static size_t update_psk_len;
#endif
#endif //defined(PROTOMAN_SECURITY_ENABLE_PSK)

#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
static const uint8_t *bootstrap_device_certificate;
static size_t bootstrap_device_certificate_len;
static const uint8_t *bootstrap_device_private_key;
static size_t bootstrap_device_private_key_len;
static const uint8_t *bootstrap_ca_certificate;
static size_t bootstrap_ca_certificate_len;
static uint8_t *lwm2m_device_certificate;
static size_t lwm2m_device_certificate_len;
static uint8_t *lwm2m_device_private_key;
static size_t lwm2m_device_private_key_len;
static uint8_t *lwm2m_server_ca_certificate;
static size_t lwm2m_server_ca_certificate_len;
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
static const uint8_t *fingerprint;
static size_t fingerprint_len;
static const uint8_t *certificate;
static size_t certificate_len;
#endif


#ifdef PROTOMAN_USE_SSL_SESSION_RESUME
static uint8_t *ssl_session;
static size_t ssl_session_len;
#endif

#endif //defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)

#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
static uint8_t *vendor_id;
static size_t vendor_id_len;
static uint8_t *class_id;
static size_t class_id_len;
#endif


#define TRACE_GROUP "mClt"

ccs_status_e uninitialize_storage(void)
{
    ccs_status_e status;
    tr_debug("CloudClientStorage::uninitialize_storage");
    status = CCS_STATUS_SUCCESS;
    return status;
}

ccs_status_e initialize_storage(void)
{
    ccs_status_e status;
    tr_debug("CloudClientStorage::initialize_storage in RAM mode");
    status = CCS_STATUS_SUCCESS;
    initialize_developer_mode();
    return status;
}

ccs_status_e get_config_parameter(cloud_client_param key, uint8_t *buffer, const size_t buffer_size, size_t *value_length)
{
    ccs_status_e status;

    tr_debug("CloudClientStorage::get_config_parameter(), key: %d", key);

    void *source_buffer = NULL;
    size_t source_buffer_data_size;

    switch (key) {
        case LWM2M_SERVER_URI:
            source_buffer = lwm2m_uri;
            source_buffer_data_size = lwm2m_uri_len;
            break;
        case INTERNAL_ENDPOINT:
            source_buffer = internal_endpoint_name;
            source_buffer_data_size = internal_endpoint_name_len;
            break;
        case BOOTSTRAP_SERVER_URI:
            source_buffer = (void *)bootstrap_uri;
            source_buffer_data_size = bootstrap_uri_len;
            break;
        case ENDPOINT_NAME:
            source_buffer = (void *)bootstrap_endpoint_name;
            source_buffer_data_size = bootstrap_endpoint_name_len;
            break;
        case ROOT_OF_TRUST:
            source_buffer = rot;
            source_buffer_data_size = rot_len;
            break;
#if defined(PROTOMAN_SECURITY_ENABLE_PSK)
        case LWM2M_SERVER_PSK_IDENTITY:
            source_buffer = lwm2m_psk_id;
            source_buffer_data_size = lwm2m_psk_id_len;
            break;
        case LWM2M_SERVER_PSK_SECRET:
            source_buffer = lwm2m_psk_secret;
            source_buffer_data_size = lwm2m_psk_secret_len;
            break;
        case BOOTSTRAP_SERVER_PSK_IDENTITY:
            source_buffer = (void *)bootstrap_psk_id;
            source_buffer_data_size = bootstrap_psk_id_len;
            break;
        case BOOTSTRAP_SERVER_PSK_SECRET:
            source_buffer = (void *)bootstrap_psk_secret;
            source_buffer_data_size = bootstrap_psk_secret_len;
            break;
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
        case UPDATE_PSK_IDENTITY:
            source_buffer = (void *)update_psk_id;
            source_buffer_data_size = update_psk_id_len;
            break;
        case UPDATE_PSK_SECRET:
            source_buffer = (void *)update_psk;
            source_buffer_data_size = update_psk_len;
            break;
        case KEY_VENDOR_ID:
            source_buffer = (void *)vendor_id;
            source_buffer_data_size = vendor_id_len;
            break;
        case KEY_CLASS_ID:
            source_buffer = (void *)class_id;
            source_buffer_data_size = class_id_len;
            break;
#endif // MBED_CLOUD_CLIENT_SUPPORT_UPDATE
#endif //defined(PROTOMAN_SECURITY_ENABLE_PSK)
#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
        case LWM2M_DEVICE_CERTIFICATE:
            source_buffer = lwm2m_device_certificate;
            source_buffer_data_size = lwm2m_device_certificate_len;
            break;
        case LWM2M_SERVER_ROOT_CA_CERTIFICATE:
            source_buffer = lwm2m_server_ca_certificate;
            source_buffer_data_size = lwm2m_server_ca_certificate_len;
            break;
        case LWM2M_DEVICE_PRIVATE_KEY:
            source_buffer = lwm2m_device_private_key;
            source_buffer_data_size = lwm2m_device_private_key_len;
            break;
        case BOOTSTRAP_DEVICE_CERTIFICATE:
            source_buffer = (void *)bootstrap_device_certificate;
            source_buffer_data_size = bootstrap_device_certificate_len;
            break;
        case BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE:
            source_buffer = (void *)bootstrap_ca_certificate;
            source_buffer_data_size = bootstrap_ca_certificate_len;
            break;
        case BOOTSTRAP_DEVICE_PRIVATE_KEY:
            source_buffer = (void *)bootstrap_device_private_key;
            source_buffer_data_size = bootstrap_device_private_key_len;
            break;
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
        case UPDATE_VENDOR_ID:
            source_buffer = (void *)vendor_id;
            source_buffer_data_size = vendor_id_len;
            break;
        case UPDATE_CLASS_ID:
            source_buffer = (void *)class_id;
            source_buffer_data_size = class_id_len;
            break;
        case UPDATE_FINGERPRINT:
            source_buffer = (void *)fingerprint;
            source_buffer_data_size = fingerprint_len;
            break;
        case UPDATE_CERTIFICATE:
            source_buffer = (void *)certificate;
            source_buffer_data_size = certificate_len;
            break;
#endif // MBED_CLOUD_CLIENT_SUPPORT_UPDATE
#ifdef PROTOMAN_USE_SSL_SESSION_RESUME
        case SSL_SESSION_DATA:
            source_buffer = (void *)ssl_session;
            source_buffer_data_size = ssl_session_len;
            break;
#endif // PROTOMAN_USE_SSL_SESSION_RESUME
#endif // defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
        default:
            tr_error("get_config_parameter() no handling for key %d", key);
            status = CCS_STATUS_KEY_DOESNT_EXIST;
            goto done;
    }

    if (buffer_size < source_buffer_data_size) {
        tr_error("get_config_parameter() buffer too small");
        status = CCS_STATUS_MEMORY_ERROR;
    } else {
        *value_length = source_buffer_data_size;
        memcpy(buffer, source_buffer, source_buffer_data_size);
        status = CCS_STATUS_SUCCESS;
    }

done:
    tr_debug("CloudClientStorage::get_config_parameter(), ret: %d", status);
    return status;
}

ccs_status_e set_config_parameter(cloud_client_param key, const uint8_t *buffer, const size_t buffer_size)
{
    ccs_status_e status;

    tr_debug("CloudClientStorage::set_config_parameter(), key: %d", key);

    void *dest_buffer = NULL;
    size_t dest_buffer_max_size;
    size_t *dest_buffer_data_size_ptr;

    switch (key) {
        case LWM2M_SERVER_URI:
            dest_buffer = lwm2m_uri;
            dest_buffer_max_size = sizeof(lwm2m_uri);
            dest_buffer_data_size_ptr = &lwm2m_uri_len;
            break;
        case INTERNAL_ENDPOINT:
            dest_buffer = internal_endpoint_name;
            dest_buffer_max_size = sizeof(internal_endpoint_name);
            dest_buffer_data_size_ptr = &internal_endpoint_name_len;
            break;
        case ENDPOINT_NAME:
            // statically defined in the developer cert - just store the pointer and length and exit
            bootstrap_endpoint_name = (const char *)buffer;
            bootstrap_endpoint_name_len = buffer_size;
            status = CCS_STATUS_SUCCESS;
            goto done;
        case BOOTSTRAP_SERVER_URI:
            // statically defined in the developer cert - just store the pointer and length and exit
            bootstrap_uri = (const char *)buffer;
            bootstrap_uri_len = buffer_size;
            status = CCS_STATUS_SUCCESS;
            goto done;
        case ROOT_OF_TRUST:
            dest_buffer = rot;
            dest_buffer_max_size = sizeof(rot);
            dest_buffer_data_size_ptr = &rot_len;
            break;
#if defined(PROTOMAN_SECURITY_ENABLE_PSK)
        case LWM2M_SERVER_PSK_IDENTITY:
            dest_buffer = lwm2m_psk_id;
            dest_buffer_max_size = sizeof(lwm2m_psk_id);
            dest_buffer_data_size_ptr = &lwm2m_psk_id_len;
            break;
        case LWM2M_SERVER_PSK_SECRET:
            dest_buffer = lwm2m_psk_secret;
            dest_buffer_max_size = sizeof(lwm2m_psk_secret);
            dest_buffer_data_size_ptr = &lwm2m_psk_secret_len;
            break;
        case BOOTSTRAP_SERVER_PSK_IDENTITY:
            // statically defined in the developer cert - just store the pointer and length and exit
            bootstrap_psk_id = buffer;
            bootstrap_psk_id_len = buffer_size;
            status = CCS_STATUS_SUCCESS;
            goto done;
        case BOOTSTRAP_SERVER_PSK_SECRET:
            // statically defined in the developer cert - just store the pointer and length and exit
            bootstrap_psk_secret = buffer;
            bootstrap_psk_secret_len = buffer_size;
            status = CCS_STATUS_SUCCESS;
            goto done;
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
        case UPDATE_PSK_IDENTITY:
            // statically defined in the developer cert - just store the pointer and length and exit
            update_psk_id = buffer;
            update_psk_id_len = buffer_size;
            status = CCS_STATUS_SUCCESS;
            goto done;
        case UPDATE_PSK_SECRET:
            // statically defined in the developer cert - just store the pointer and length and exit
            update_psk = buffer;
            update_psk_len = buffer_size;
            status = CCS_STATUS_SUCCESS;
            goto done;
        case KEY_VENDOR_ID:
            // statically defined in the developer cert - just store the pointer and length and exit
            vendor_id = buffer;
            vendor_id_len = buffer_size;
            status = CCS_STATUS_SUCCESS;
            goto done;
        case KEY_CLASS_ID:
            // statically defined in the developer cert - just store the pointer and length and exit
            class_id = buffer;
            class_id_len = buffer_size;
            status = CCS_STATUS_SUCCESS;
            goto done;
#endif
#endif //defined(PROTOMAN_SECURITY_ENABLE_PSK)
#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
        case LWM2M_DEVICE_CERTIFICATE:
            lwm2m_free(lwm2m_device_certificate);
            lwm2m_device_certificate = lwm2m_alloc(buffer_size);
            if (!lwm2m_device_certificate) {
                tr_error("set_config_parameter() out of memory");
                status = CCS_STATUS_MEMORY_ERROR;
                goto done;
            }
            dest_buffer = lwm2m_device_certificate;
            dest_buffer_max_size = buffer_size;
            dest_buffer_data_size_ptr = &lwm2m_device_certificate_len;
            break;
        case LWM2M_SERVER_ROOT_CA_CERTIFICATE:
            lwm2m_free(lwm2m_server_ca_certificate);
            lwm2m_server_ca_certificate = lwm2m_alloc(buffer_size);
            if (!lwm2m_server_ca_certificate) {
                tr_error("set_config_parameter() out of memory");
                status = CCS_STATUS_MEMORY_ERROR;
                goto done;
            }
            dest_buffer = lwm2m_server_ca_certificate;
            dest_buffer_max_size = buffer_size;
            dest_buffer_data_size_ptr = &lwm2m_server_ca_certificate_len;
            break;
        case LWM2M_DEVICE_PRIVATE_KEY:
            lwm2m_free(lwm2m_device_private_key);
            lwm2m_device_private_key = lwm2m_alloc(buffer_size);
            if (!lwm2m_device_private_key) {
                tr_error("set_config_parameter() out of memory");
                status = CCS_STATUS_MEMORY_ERROR;
                goto done;
            }
            dest_buffer = lwm2m_device_private_key;
            dest_buffer_max_size = buffer_size;
            dest_buffer_data_size_ptr = &lwm2m_device_private_key_len;
            break;
        case BOOTSTRAP_DEVICE_CERTIFICATE:
            // statically defined in the developer cert - just store the pointer and length and exit
            bootstrap_device_certificate = buffer;
            bootstrap_device_certificate_len = buffer_size;
            status = CCS_STATUS_SUCCESS;
            goto done;
        case BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE:
            // statically defined in the developer cert - just store the pointer and length and exit
            bootstrap_ca_certificate = buffer;
            bootstrap_ca_certificate_len = buffer_size;
            status = CCS_STATUS_SUCCESS;
            goto done;
        case BOOTSTRAP_DEVICE_PRIVATE_KEY:
            // statically defined in the developer cert - just store the pointer and length and exit
            bootstrap_device_private_key = buffer;
            bootstrap_device_private_key_len = buffer_size;
            status = CCS_STATUS_SUCCESS;
            goto done;
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
        case UPDATE_FINGERPRINT:
            // statically defined in the developer cert - just store the pointer and length and exit
            fingerprint = buffer;
            fingerprint_len = buffer_size;
            status = CCS_STATUS_SUCCESS;
            goto done;
        case UPDATE_CERTIFICATE:
            // statically defined in the developer cert - just store the pointer and length and exit
            certificate = buffer;
            certificate_len = buffer_size;
            status = CCS_STATUS_SUCCESS;
            goto done;
        case UPDATE_VENDOR_ID:
            lwm2m_free(vendor_id);
            vendor_id = lwm2m_alloc(buffer_size);
            if (!vendor_id) {
                tr_error("set_config_parameter() out of memory");
                status = CCS_STATUS_MEMORY_ERROR;
                goto done;
            }
            dest_buffer = vendor_id;
            dest_buffer_max_size = buffer_size;
            dest_buffer_data_size_ptr = &vendor_id_len;
            break;
        case UPDATE_CLASS_ID:
            lwm2m_free(class_id);
            class_id = lwm2m_alloc(buffer_size);
            if (!class_id) {
                tr_error("set_config_parameter() out of memory");
                status = CCS_STATUS_MEMORY_ERROR;
                goto done;
            }
            dest_buffer = class_id;
            dest_buffer_max_size = buffer_size;
            dest_buffer_data_size_ptr = &class_id_len;
            break;
#endif
#ifdef PROTOMAN_USE_SSL_SESSION_RESUME
        case SSL_SESSION_DATA:
            lwm2m_free(ssl_session);
            ssl_session = lwm2m_alloc(buffer_size);
            if (!ssl_session) {
                tr_error("set_config_parameter() out of memory");
                status = CCS_STATUS_MEMORY_ERROR;
                goto done;
            }
            dest_buffer = ssl_session;
            dest_buffer_max_size = buffer_size;
            dest_buffer_data_size_ptr = &ssl_session_len;
            break;
#endif // PROTOMAN_USE_SSL_SESSION_RESUME
#endif
        default:
            tr_error("set_config_parameter() no handling for key %d", key);
            status = CCS_STATUS_KEY_DOESNT_EXIST;
            goto done;
    }

    if (buffer_size > dest_buffer_max_size) {
        tr_error("set_config_parameter() destination buffer is too small for key %d", key);
        status = CCS_STATUS_MEMORY_ERROR;
    } else {
        *dest_buffer_data_size_ptr = buffer_size;
        memcpy(dest_buffer, buffer, buffer_size);
        status = CCS_STATUS_SUCCESS;
    }

done:
    tr_debug("CloudClientStorage::set_config_parameter(), ret: %d", status);
    return status;
}

ccs_status_e remove_config_parameter(cloud_client_param key)
{
    return CCS_STATUS_SUCCESS;
}

ccs_status_e size_config_parameter(cloud_client_param key, size_t *size_out)
{
    ccs_status_e status;

    tr_debug("CloudClientStorage::size_config_parameter(), key: %d", key);

    status = CCS_STATUS_SUCCESS;
    switch (key) {
        case LWM2M_SERVER_URI:
            *size_out = lwm2m_uri_len;
            break;
        case INTERNAL_ENDPOINT:
            *size_out = internal_endpoint_name_len;
            break;
        case BOOTSTRAP_SERVER_URI:
            *size_out = bootstrap_uri_len;
            break;
        case ENDPOINT_NAME:
            *size_out = bootstrap_endpoint_name_len;
            break;
        case ROOT_OF_TRUST:
            *size_out = rot_len;
            break;
#if defined(PROTOMAN_SECURITY_ENABLE_PSK)
        case LWM2M_SERVER_PSK_IDENTITY:
            *size_out = lwm2m_psk_id_len;
            break;
        case LWM2M_SERVER_PSK_SECRET:
            *size_out = lwm2m_psk_secret_len;
            break;
        case BOOTSTRAP_SERVER_PSK_IDENTITY:
            *size_out = bootstrap_psk_id_len;
            break;
        case BOOTSTRAP_SERVER_PSK_SECRET:
            *size_out = bootstrap_psk_secret_len;
            break;
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
        case UPDATE_PSK_IDENTITY:
            *size_out = update_psk_id_len;
            break;
        case UPDATE_PSK_SECRET:
            *size_out = update_psk_len;
            break;
        case KEY_VENDOR_ID:
            *size_out = vendor_id_len;
            break;
        case KEY_CLASS_ID:
            *size_out = class_id_len;
            break;
#endif
#endif //defined(PROTOMAN_SECURITY_ENABLE_PSK)
#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
        case LWM2M_DEVICE_CERTIFICATE:
            *size_out = lwm2m_device_certificate_len;
            break;
        case LWM2M_SERVER_ROOT_CA_CERTIFICATE:
            *size_out = lwm2m_server_ca_certificate_len;
            break;
        case LWM2M_DEVICE_PRIVATE_KEY:
            *size_out = lwm2m_device_private_key_len;
            break;
        case BOOTSTRAP_DEVICE_CERTIFICATE:
            *size_out = bootstrap_device_certificate_len;
            break;
        case BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE:
            *size_out = bootstrap_ca_certificate_len;
            break;
        case BOOTSTRAP_DEVICE_PRIVATE_KEY:
            *size_out = bootstrap_device_private_key_len;
            break;
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
        case UPDATE_VENDOR_ID:
            *size_out = vendor_id_len;
            break;
        case UPDATE_CLASS_ID:
            *size_out = class_id_len;
            break;
        case UPDATE_FINGERPRINT:
            *size_out = fingerprint_len;
            break;
        case UPDATE_CERTIFICATE:
            *size_out = certificate_len;
            break;
#endif
#ifdef PROTOMAN_USE_SSL_SESSION_RESUME
        case SSL_SESSION_DATA:
            *size_out = ssl_session_len;
            break;
#endif // PROTOMAN_USE_SSL_SESSION_RESUME
#endif // defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
        default:
            tr_error("size_config_parameter() no handling for key %d", key);
            status = CCS_STATUS_KEY_DOESNT_EXIST;
    }

    tr_debug("CloudClientStorage::size_config_parameter(), ret: %d", status);
    return status;
}

#endif // MBED_CONF_MBED_CLOUD_CLIENT_STORAGE_TYPE == RAM
