// ----------------------------------------------------------------------------
// Copyright 2019-2020 ARM Ltd.
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
#ifndef KCM
#define KCM 1112
#endif
#if MBED_CONF_MBED_CLOUD_CLIENT_STORAGE_TYPE == KCM

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
#include "key_config_manager.h"
#include "storage_kcm.h"
#include <assert.h>
#define TRACE_GROUP "mClt"

static ccs_status_e map_kcm_result(kcm_status_e result)
{
    ccs_status_e status = CCS_STATUS_ERROR;
    tr_debug("kcm_result %" PRIu32 "", (uint32_t)result);
    switch (result) {
        case KCM_STATUS_SUCCESS:
            status = CCS_STATUS_SUCCESS;
            break;
        case KCM_STATUS_ITEM_NOT_FOUND:
            status = CCS_STATUS_KEY_DOESNT_EXIST;
            break;
        case KCM_STATUS_INVALID_PARAMETER:
            status = CCS_STATUS_VALIDATION_FAIL;
            break;
        case KCM_STATUS_OUT_OF_MEMORY:
            status = CCS_STATUS_MEMORY_ERROR;
            break;
        case KCM_STATUS_STORAGE_ERROR:
        case KCM_STATUS_FILE_EXIST:
        case KCM_STATUS_UNKNOWN_STORAGE_ERROR:
            status = CCS_STATUS_ERROR;
            break;
        default:
            status = CCS_STATUS_ERROR;
    }
    return status;
}

static void set_kcm_type(cloud_client_param key, kcm_item_type_e *kcm_type)
{
    *kcm_type = KCM_CONFIG_ITEM;

    if (strstr(key, "Cert") != NULL) {
        *kcm_type = KCM_CERTIFICATE_ITEM;
    }
    if (strstr(key, "PrivateKey") != NULL) {
        *kcm_type = KCM_PRIVATE_KEY_ITEM;
    }
    if (strstr(key, "PubKey") != NULL) {
        *kcm_type = KCM_PUBLIC_KEY_ITEM;
    }
    if (strstr(key, "UpdatePubKey") != NULL) {
        *kcm_type = KCM_CONFIG_ITEM;
    }
    return;
}

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

    status = map_kcm_result(storage_reset());

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
    kcm_item_type_e kcm_type;

    //set kcm item type
    set_kcm_type(key, &kcm_type);

    //Get item size
    status = map_kcm_result(kcm_item_get_data((const uint8_t *)key, strlen(key), kcm_type, buffer, buffer_size, value_length));
    tr_debug("CloudClientStorage::size_config_parameter(), ret: %d", status);

    return status;
}


ccs_status_e set_config_parameter(cloud_client_param key, const uint8_t *buffer, const size_t buffer_size)
{
    ccs_status_e status;
    kcm_item_type_e kcm_type;

    //set kcm item type
    set_kcm_type(key, &kcm_type);

    //Get item size
    status = map_kcm_result(kcm_item_store((const uint8_t *)key, strlen(key), kcm_type, true /*FACTROY*/, buffer, buffer_size, NULL));
    tr_debug("CloudClientStorage::set_config_parameter(), key name %s", key);

    return status;
}

ccs_status_e remove_config_parameter(cloud_client_param key)
{
    ccs_status_e status;
    kcm_item_type_e kcm_type;

    //set kcm item type
    set_kcm_type(key, &kcm_type);

    //Get item size
    status = map_kcm_result(kcm_item_delete((const uint8_t *)key, strlen(key), kcm_type));
    tr_debug("CloudClientStorage::remove_config_parameter(), key name %s", key);

    return status;
}

ccs_status_e size_config_parameter(cloud_client_param key, size_t *size_out)
{
    ccs_status_e status;
    kcm_item_type_e kcm_type;

    //set kcm item type
    set_kcm_type(key, &kcm_type);

    //Get item size
    status = map_kcm_result(kcm_item_get_data_size((const uint8_t *)key, strlen(key), kcm_type, size_out));
    tr_debug("CloudClientStorage::size_config_parameter(), ret: %d", status);

    return status;
}

#ifdef RESET_STORAGE
ccs_status_e reset_storage(const char *kvstore_path)
{
    return map_kcm_result(storage_reset());
}
#endif // RESET_STORAGE

#endif // MBED_CONF_MBED_CLOUD_CLIENT_STORAGE_TYPE == KCM
