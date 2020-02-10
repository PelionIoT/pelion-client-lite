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

#ifndef KVSTORE
#define KVSTORE 1111
#endif

#if MBED_CONF_MBED_CLOUD_CLIENT_STORAGE_TYPE == KVSTORE
// Note: this macro is needed on armcc to get the the limit macros like UINT16_MAX
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <inttypes.h>
#include <string.h>
#include "CloudClientStorage.h"
#include "mbed-trace/mbed_trace.h"
#ifdef TARGET_LIKE_MBED
#include "mbed.h"
#else
#include "BlockDevice.h"
using namespace mbed;
#endif
#include "kvstore_global_api.h"
#include <assert.h>

#define STR(x) #x
#define XSTR(x) STR(x)

#if MBED_CONF_MBED_CLOUD_CLIENT_STORAGE_RESET_DEV_CREDENTIALS
#define KVSTORE_LOCATION_PATH XSTR(MBED_CONF_STORAGE_DEFAULT_KV)
#endif


// Use same fields than FCC is using when injecting data to the kv store
#define FCC_BOOTSTRAP_DEVICE_PRIVATE_KEY pelion_wPrvKey_mbed.BootstrapDevicePrivateKey
#define FCC_BOOTSTRAP_SERVER_URI pelion_wCfgParam_mbed.BootstrapServerURI
#define FCC_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE pelion_wCrtae_mbed.BootstrapServerCACert
#define FCC_BOOTSTRAP_DEVICE_CERTIFICATE pelion_wCrtae_mbed.BootstrapDeviceCert
#define FCC_LWM2M_SERVER_URI pelion_wCfgParam_mbed.LwM2MServerURI
#define FCC_ENDPOINT_NAME pelion_wCfgParam_mbed.EndpointName
#define FCC_LWM2M_DEVICE_CERTIFICATE pelion_wCrtae_mbed.LwM2MDeviceCert
#define FCC_LWM2M_SERVER_ROOT_CA_CERTIFICATE pelion_wCrtae_mbed.LwM2MServerCACert
#define FCC_LWM2M_DEVICE_PRIVATE_KEY pelion_wPrvKey_mbed.LwM2MDevicePrivateKey
#define FCC_UPDATE_CERTIFICATE pelion_wCrtae_mbed.UpdateAuthCert
#define FCC_UPDATE_CLASS_ID pelion_wCfgParam_mbed.ClassId
#define FCC_UPDATE_VENDOR_ID pelion_wCfgParam_mbed.VendorId

#define KVSTORE_PATH(KEY_NAME) "/" XSTR(MBED_CONF_STORAGE_DEFAULT_KV) "/" XSTR(KEY_NAME)

#define TRACE_GROUP "mClt"

static ccs_status_e map_kvstore_result(int result);
static const char *get_kvstore_key(cloud_client_param key);

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
    tr_debug("CloudClientStorage::initialize_storage in KVStore mode");
    status = CCS_STATUS_SUCCESS;
#if MBED_CONF_APP_DEVELOPER_MODE == 1
// TODO: remove this from library.
#warning "Do not expect MCC to initialize certificates. Will be removed."
#if MBED_CONF_MBED_CLOUD_CLIENT_STORAGE_RESET_DEV_CREDENTIALS
    tr_info("CloudClientStorage::initialize_storage resetting KVStore");
    status = map_kvstore_result(kv_reset(KVSTORE_LOCATION_PATH));
    if (status != CCS_STATUS_SUCCESS) {
        tr_error("initialize_storage() failed: couldn't reset KVStore");
        return status;
    }
#endif
    initialize_developer_mode();
#endif
    return status;
}

ccs_status_e get_config_parameter(cloud_client_param key, uint8_t *buffer, const size_t buffer_size, size_t *value_length)
{
    ccs_status_e status;
    const char *key_name = get_kvstore_key(key);
    tr_debug("CloudClientStorage::get_config_parameter(), key name %s", key_name);
    int result = kv_get(key_name, (void *)buffer, buffer_size, value_length);
    status = map_kvstore_result(result);
    tr_debug("CloudClientStorage::get_config_parameter(), ret: %d", status);

    return status;
}

ccs_status_e set_config_parameter(cloud_client_param key, const uint8_t *buffer, const size_t buffer_size)
{
    ccs_status_e status;
    const char *key_name = get_kvstore_key(key);
    tr_debug("CloudClientStorage::set_config_parameter(), key name %s", key_name);

    int result = kv_set(key_name, (void *)buffer, buffer_size, 0);

    status = map_kvstore_result(result);
    tr_debug("CloudClientStorage::set_config_parameter(), ret: %d", status);

    return status;
}

ccs_status_e remove_config_parameter(cloud_client_param key)
{
    ccs_status_e status;
    const char *key_name = get_kvstore_key(key);
    tr_debug("remove_config_parameter, key name %s", key_name);

    int result = kv_remove(key_name);

    status = map_kvstore_result(result);
    tr_debug("remove_config_parameter, ret: %d", status);

    return status;
}

ccs_status_e size_config_parameter(cloud_client_param key, size_t *size_out)
{
    ccs_status_e status;
    const char *key_name = get_kvstore_key(key);
    tr_debug("CloudClientStorage::size_config_parameter(), key name %s", key_name);
    kv_info_t info;
    int result = kv_get_info(key_name, &info);
    *size_out = info.size;
    status = map_kvstore_result(result);
    tr_debug("CloudClientStorage::size_config_parameter(), ret: %d", status);

    return status;
}

static ccs_status_e map_kvstore_result(int result)
{
    ccs_status_e status = CCS_STATUS_ERROR;
    tr_debug("kvstore_result %d", (int)result);
    switch (result) {
        case MBED_SUCCESS:
            status = CCS_STATUS_SUCCESS;
            break;
        case MBED_ERROR_ITEM_NOT_FOUND:
            status = CCS_STATUS_KEY_DOESNT_EXIST;
            break;
        case MBED_ERROR_INVALID_DATA_DETECTED:
        case MBED_ERROR_INVALID_ARGUMENT:
        case MBED_ERROR_INVALID_SIZE:
        case MBED_ERROR_AUTHENTICATION_FAILED:
        case MBED_ERROR_RBP_AUTHENTICATION_FAILED:
            status = CCS_STATUS_VALIDATION_FAIL;
            break;
        case MBED_ERROR_MEDIA_FULL:
            status = CCS_STATUS_MEMORY_ERROR;
            break;
        case MBED_ERROR_READ_FAILED:
        case MBED_ERROR_WRITE_FAILED:
        case MBED_ERROR_FAILED_OPERATION:
            status = CCS_STATUS_ERROR;
            break;
    }
    return status;
}

static const char *get_kvstore_key(cloud_client_param key)
{
    const char *str;
    switch (key) {
        case BOOTSTRAP_SERVER_URI:
            str = KVSTORE_PATH(FCC_BOOTSTRAP_SERVER_URI);
            break;
        case ROOT_OF_TRUST:
            str = KVSTORE_PATH(ROOT_OF_TRUST);
            break;
        case LWM2M_SERVER_URI:
            str = KVSTORE_PATH(FCC_LWM2M_SERVER_URI);
            break;
        case INTERNAL_ENDPOINT:
            str = KVSTORE_PATH(INTERNAL_ENDPOINT);
            break;
        case ENDPOINT_NAME:
            str = KVSTORE_PATH(FCC_ENDPOINT_NAME);
            break;
#if defined(PROTOMAN_SECURITY_ENABLE_PSK)
        case BOOTSTRAP_SERVER_PSK_IDENTITY:
            str = KVSTORE_PATH(BOOTSTRAP_SERVER_PSK_IDENTITY);
            break;
        case BOOTSTRAP_SERVER_PSK_SECRET:
            str = KVSTORE_PATH(BOOTSTRAP_SERVER_PSK_SECRET);
            break;
        case LWM2M_SERVER_PSK_IDENTITY:
            str = KVSTORE_PATH(LWM2M_SERVER_PSK_IDENTITY);
            break;
        case LWM2M_SERVER_PSK_SECRET:
            str = KVSTORE_PATH(LWM2M_SERVER_PSK_SECRET);
            break;
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
        case UPDATE_PSK_IDENTITY:
            str = KVSTORE_PATH(UPDATE_PSK_IDENTITY);
            break;
        case UPDATE_PSK_SECRET:
            str = KVSTORE_PATH(UPDATE_PSK_SECRET);
            break;
        case KEY_VENDOR_ID:
            str = KVSTORE_PATH(KEY_VENDOR_ID);
            break;
        case KEY_CLASS_ID:
            str = KVSTORE_PATH(KEY_CLASS_ID);
            break;
#endif
#endif //defined(PROTOMAN_SECURITY_ENABLE_PSK)
#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
        case BOOTSTRAP_DEVICE_CERTIFICATE:
            str = KVSTORE_PATH(FCC_BOOTSTRAP_DEVICE_CERTIFICATE);
            break;
        case BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE:
            str = KVSTORE_PATH(FCC_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE);
            break;
        case BOOTSTRAP_DEVICE_PRIVATE_KEY:
            str = KVSTORE_PATH(FCC_BOOTSTRAP_DEVICE_PRIVATE_KEY);
            break;
        case LWM2M_DEVICE_CERTIFICATE:
            str = KVSTORE_PATH(FCC_LWM2M_DEVICE_CERTIFICATE);
            break;
        case LWM2M_SERVER_ROOT_CA_CERTIFICATE:
            str = KVSTORE_PATH(FCC_LWM2M_SERVER_ROOT_CA_CERTIFICATE);
            break;
        case LWM2M_DEVICE_PRIVATE_KEY:
            str = KVSTORE_PATH(FCC_LWM2M_DEVICE_PRIVATE_KEY);
            break;
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
        case UPDATE_VENDOR_ID:
            str = KVSTORE_PATH(FCC_UPDATE_VENDOR_ID);
            break;
        case UPDATE_CLASS_ID:
            str = KVSTORE_PATH(FCC_UPDATE_CLASS_ID);
            break;
        case UPDATE_FINGERPRINT:
            str = KVSTORE_PATH(UPDATE_FINGERPRINT);
            break;
        case UPDATE_CERTIFICATE:
            str = KVSTORE_PATH(FCC_UPDATE_CERTIFICATE);
            break;
#endif
#ifdef PROTOMAN_USE_SSL_SESSION_RESUME
        case SSL_SESSION_DATA:
            str = KVSTORE_PATH(SSL_SESSION_DATA);
            break;
#endif
#endif //defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
#ifdef USE_EXTERNAL_USER_STORAGE_PARAMETERS
        case USER_STORAGE_FIELD_0:
            str = KVSTORE_PATH(USER_STORAGE_FIELD_0);
            break;
        case USER_STORAGE_FIELD_1:
            str = KVSTORE_PATH(USER_STORAGE_FIELD_1);
            break;
        case USER_STORAGE_FIELD_2:
            str = KVSTORE_PATH(USER_STORAGE_FIELD_2);
            break;
        case USER_STORAGE_FIELD_3:
            str = KVSTORE_PATH(USER_STORAGE_FIELD_3);
            break;
        case USER_STORAGE_FIELD_4:
            str = KVSTORE_PATH(USER_STORAGE_FIELD_4);
            break;
        case USER_STORAGE_FIELD_5:
            str = KVSTORE_PATH(USER_STORAGE_FIELD_5);
            break;
        case USER_STORAGE_FIELD_6:
            str = KVSTORE_PATH(USER_STORAGE_FIELD_6);
            break;
        case USER_STORAGE_FIELD_7:
            str = KVSTORE_PATH(USER_STORAGE_FIELD_7);
            break;
        case USER_STORAGE_FIELD_8:
            str = KVSTORE_PATH(USER_STORAGE_FIELD_8);
            break;
#endif // USE_EXTERNAL_USER_STORAGE_PARAMETERS

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE
        case FOTA_ENCRYPTE_KEY:
            str = KVSTORE_PATH(FOTA_ENCRYPTE_KEY);
            break;
        case FOTA_SALT_KEY:
            str = KVSTORE_PATH(FOTA_SALT_KEY);
            break;
        case FOTA_MANIFEST_KEY:
            str = KVSTORE_PATH(FOTA_MANIFEST_KEY);
            break;
#endif // MBED_CLOUD_CLIENT_FOTA_ENABLE

        default:
            tr_error("CloudClientStorage::get_kvstore_key(), unknown key: %d", key);
            assert(false);
    }

    return str;
}

#ifdef RESET_STORAGE
ccs_status_e reset_storage(const char *kvstore_path)
{
    return map_kvstore_result(kv_reset(kvstore_path));
}
#endif // RESET_STORAGE



#endif // MBED_CONF_MBED_CLOUD_CLIENT_STORAGE_TYPE == KVSTORE
