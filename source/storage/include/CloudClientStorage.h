// ----------------------------------------------------------------------------
// Copyright 2016-2019 ARM Ltd.
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

#ifndef CLOUD_CLIENT_STORAGE_H
#define CLOUD_CLIENT_STORAGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#include MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#endif

#define ACCOUNT_ID                          "account_id"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef MBED_CLOUD_CLIENT_STORAGE_KEY_LIST_FILE
// MBED_CLOUD_CLIENT_STORAGE_KEY_LIST_FILE defines the `cloud_client_param` type and the keys needed by cloud client.
// It may also define additional application specific keys.
#include MBED_CLOUD_CLIENT_STORAGE_KEY_LIST_FILE
#else

typedef enum {
    BOOTSTRAP_SERVER_PSK_IDENTITY = 1,
    BOOTSTRAP_SERVER_PSK_SECRET = 2,
    BOOTSTRAP_SERVER_URI = 3,
    ROOT_OF_TRUST = 4,   // XXX: must match SOTP_TYPE_ROT in sotp.h used by bootloader
    LWM2M_SERVER_PSK_IDENTITY = 5,
    LWM2M_SERVER_PSK_SECRET = 6,
    LWM2M_SERVER_URI = 7,
    INTERNAL_ENDPOINT = 8,
    ENDPOINT_NAME = 9,
    UPDATE_PSK_IDENTITY = 10,
    UPDATE_PSK_SECRET = 11,
    KEY_VENDOR_ID = 12,
    KEY_CLASS_ID = 13,
    BOOTSTRAP_DEVICE_CERTIFICATE = 14,
    BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE = 15,
    BOOTSTRAP_DEVICE_PRIVATE_KEY = 16,
    LWM2M_DEVICE_CERTIFICATE = 17,
    LWM2M_SERVER_ROOT_CA_CERTIFICATE = 18,
    LWM2M_DEVICE_PRIVATE_KEY = 19,
    UPDATE_VENDOR_ID = 20,
    UPDATE_CLASS_ID = 21,
    UPDATE_FINGERPRINT = 22,
    UPDATE_CERTIFICATE = 23,
    SSL_SESSION_DATA = 24,

#if defined(USE_EXTERNAL_USER_STORAGE_PARAMETERS)
    USER_STORAGE_FIELD_0 = 25,
    USER_STORAGE_FIELD_1 = 26,
    USER_STORAGE_FIELD_2 = 27,
    USER_STORAGE_FIELD_3 = 28,
    USER_STORAGE_FIELD_4 = 29,
    USER_STORAGE_FIELD_5 = 30,
    USER_STORAGE_FIELD_6 = 31,
    USER_STORAGE_FIELD_7 = 32,
    USER_STORAGE_FIELD_8 = 33,
#endif // USE_EXTERNAL_USER_STORAGE_PARAMETERS

    FOTA_ENCRYPT_KEY = 34,
    FOTA_SALT_KEY = 35,
    FOTA_MANIFEST_KEY = 36,

} cloud_client_param;
#endif

typedef enum {
    CCS_STATUS_SUCCESS = 0,
    CCS_STATUS_MEMORY_ERROR = 1,
    CCS_STATUS_VALIDATION_FAIL = 2,
    CCS_STATUS_KEY_DOESNT_EXIST = 3,
    CCS_STATUS_ERROR = 4
} ccs_status_e;

/**
*  \brief Uninitializes the underlying storage handle.
*  \return CCS_STATUS_SUCCESS if success, else error number (mapped from SOTP)
*/
ccs_status_e uninitialize_storage(void);

/**
*  \brief Initializes the underlying storage handle.
*  \return CCS_STATUS_SUCCESS if success, else error code (mapped from SOTP)
*/
ccs_status_e initialize_storage(void);

/**
*  \brief Gets the stored value for the given key.
*  \param key, Key of stored item.
*  \param [in] buffer_size, Length of input buffer in bytes.
*  \param [in] buffer, Buffer to store data on (must be aligned to a 32 bit boundary).
*  \param [out] value_length, Actual length of returned data
*  \return CCS_STATUS_SUCCESS if success, else error code (mapped from SOTP)
*/
ccs_status_e get_config_parameter(cloud_client_param key, uint8_t *buffer, const size_t buffer_size, size_t *value_length);

/**
*  \brief Programs one item of data on storage, given type.
*  \param key, Key of stored item.
*  \param [in] buffer, Buffer containing data  (must be aligned to a 32 bit boundary).
*  \param [in] buffer_size, Item length in bytes.
*  \return CCS_STATUS_SUCCESS if success, else error code (mapped from SOTP)
*/
ccs_status_e set_config_parameter(cloud_client_param  key, const uint8_t *buffer, const size_t buffer_size);

/**
 * @brief Remove one of item by given key.
 *
 *  \param key, Key of stored item.
 *  \return CCS_STATUS_SUCCESS if success, else error code (mapped from SOTP)
 */
ccs_status_e remove_config_parameter(cloud_client_param  key);

/**
*  \brief Returns size of data stored on storage, given type.
*  \param key, Key of stored item.
*  \param [in] size_out, Length of input buffer in bytes.
*  \return CCS_STATUS_SUCCESS if success, else error code (mapped from SOTP)
*/
ccs_status_e size_config_parameter(cloud_client_param  key, size_t *size_out);

/**
 * \brief Function to get the device root of trust
 * \details The device root of trust should be a 128 bit value. It should never leave the device.
 *          It should be unique to the device. It should have enough entropy to avoid conentional
 *          entropy attacks. The porter should implement the following device signature to provide
 *          device root of trust on different platforms.
 *
 * \param key_buf buffer to be filled with the device root of trust.
 * \param length  length of the buffer provided to make sure no overflow occurs.
 *  \return 0 on success, non-zero on failure.
 */
int8_t mbed_cloud_client_get_rot_128bit(uint8_t *key_buf, uint32_t length);

/**
 * \brief Initializes storage from developer certificate
 * \details Private function that checks if storage contains bootstrap credentials and initializes
 *          them from the developer certificate if necessary. Called automatically if needed.
 */
ccs_status_e initialize_developer_mode(void);

#ifdef RESET_STORAGE
/**
 * \brief Remove all keys and related data from a storage.
 * \param partition Partition to be cleared.
 */
ccs_status_e reset_storage(const char *partition);
#endif // RESET_STORAGE

#ifdef __cplusplus
}
#endif
#endif // CLOUD_CLIENT_STORAGE_H
