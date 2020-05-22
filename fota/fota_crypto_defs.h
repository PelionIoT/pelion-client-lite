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

#ifndef __FOTA_CRYPTO_DEFS_H_
#define __FOTA_CRYPTO_DEFS_H_

#include "fota/fota_base.h"

#ifdef __cplusplus
extern "C" {
#endif


#define FOTA_ENCRYPT_KEY_SIZE 16 /*< AES-128 key size in bytes */

#define FOTA_ENCRYPT_METADATA_MAX_SIZE 8 /*< AES-CCM tag size in bytes */

#define FOTA_ENCRYPT_METADATA_START_SIZE 24
#define FOTA_ENCRYPT_METADATA_MAGIC ((uint32_t)(0x4a6ba649))
#define FOTA_ENCRYPT_METADATA_SALT_LEN FOTA_ENCRYPT_KEY_SIZE

#define FOTA_CRYPTO_HASH_SIZE  32  /*< SHA256 digest size in bytes*/

#if !defined(MBED_CLOUD_CLIENT_FOTA_ENCRYPT_BLOCK_SIZE)
/* Encryption block size used for encrypting FW candidate */
#define MBED_CLOUD_CLIENT_FOTA_ENCRYPT_BLOCK_SIZE 1024
#endif

typedef struct {
    uint32_t    encrypt_block_size;
} fota_encrypt_config_t;

#ifdef __cplusplus
}
#endif

#endif // __FOTA_CRYPTO_DEFS_H_
