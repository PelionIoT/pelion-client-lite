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

#ifndef __FOTA_NVM_H_
#define __FOTA_NVM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "fota/fota_base.h"
#include "fota/fota_crypto_defs.h"
#include "fota/fota_component.h"

#include <stddef.h>
#include <stdint.h>



#define FOTA_GUID_SIZE (128/8)

/*
 * Get class GUID from storage.
 * \param[out] buffer buffer for returning class GUID.
 *
 * \return FOTA_STATUS_SUCCESS on success.
 * \note class GUID buffer size must be exactly FOTA_GUID_SIZE.
 */
int fota_nvm_get_class_id(uint8_t buffer[FOTA_GUID_SIZE]);

/*
 * Get vendor GUID from storage.
 * \param[out] buffer buffer for returning vendor GUID.
 *
 * \return FOTA_STATUS_SUCCESS on success.
 * \note vendor GUID buffer size must be exactly FOTA_GUID_SIZE.
 */
int fota_nvm_get_vendor_id(uint8_t buffer[FOTA_GUID_SIZE]);

/*
 * Get FOTA certificate from storage.
 *
 * \param[out] buffer pointer to initialized to a buffer for returning certificate
 * \param[in] size buffer size.
 * \param[out] read_bytes amount of bytes read on successful read.
 *
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_nvm_get_update_certificate(uint8_t *buffer, size_t size, size_t *bytes_read);

/*
 * Get firmware encryption key from storage.
 * \param[out] buffer buffer for returning encryption key.
 *
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_nvm_fw_encryption_key_get(uint8_t buffer[FOTA_ENCRYPT_KEY_SIZE]);

/*
 * Set firmware encryption key in storage.
 * \param[in] buffer buffer with encryption key.
 *
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_nvm_fw_encryption_key_set(const uint8_t buffer[FOTA_ENCRYPT_KEY_SIZE]);

/*
 * Get salt used for generating FW candidate encryption key.
 *
 * \param[out] buffer buffer for returning salt.

 * \return FOTA_STATUS_SUCCESS on success.
 * \note buffer size expected to of the following size: FOTA_ENCRYPT_METADATA_SALT_LEN
 */
int fota_nvm_salt_get(uint8_t buffer[FOTA_ENCRYPT_METADATA_SALT_LEN]);

/*
 * Save salt used for generating FW candidate encryption key.
 *
 * \param[in] buffer buffer with salt.

 * \return FOTA_STATUS_SUCCESS on success
 * \note buffer size expected to of the following size: FOTA_ENCRYPT_METADATA_SALT_LEN
 */
int fota_nvm_salt_set(const uint8_t buffer[FOTA_ENCRYPT_METADATA_SALT_LEN]);

/*
 * Delete salt used for generating FW candidate encryption key.
 *
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_nvm_salt_delete(void);


/**
 * Get saved Pelion FOTA manifest.
 *
 * \param[out] buffer buffer for returning FOTA manifest.
 * \param[in]  buffer_size Buffer size available for reading the manifest.
 * \param[out] bytes_read  Actual manifest size.
 *
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_nvm_manifest_get(uint8_t *buffer, size_t size, size_t *bytes_read);

/**
 * Save Pelion FOTA manifest - used for resuming interrupted updates.
 *
 * \param[in] buffer buffer with FOTA manifest.
 * \param[in] buffer_size Buffer size.
 *
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_nvm_manifest_set(const uint8_t *buffer, size_t size);


/**
 * Delete Pelion FOTA stored manifest.
 *
 * \return FOTA_STATUS_SUCCESS on success.
 */

int fota_nvm_manifest_delete(void);

#ifdef MBED_CLOUD_DEV_UPDATE_ID

int fota_nvm_update_class_id_set(void);
int fota_nvm_update_vendor_id_set(void);

#endif

#ifdef MBED_CLOUD_DEV_UPDATE_CERT

int fota_nvm_update_cert_set(void);

#endif

/**
 * Save component version.
 *
 * \param[in]  comp_name Component name, should be at most FOTA_COMPONENT_MAX_NAME_SIZE including NULL termination
 * \param[in]  version   Component version (integer)
 *
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_nvm_comp_version_set(const char *comp_name, fota_component_version_t version);

/**
 * Get component version.
 *
 * \param[in]  comp_name Component name, should be at most FOTA_COMPONENT_MAX_NAME_SIZE including NULL termination
 * \param[out] version   Component version (integer)
 *
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_nvm_comp_version_get(const char *comp_name, fota_component_version_t *version);


#ifdef __cplusplus
}
#endif

#endif //__FOTA_NVM_H_
