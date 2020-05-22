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

#ifndef __FOTA_HEADER_INFO_H_
#define __FOTA_HEADER_INFO_H_

#include <stdint.h>
#include "fota/fota_base.h"
#include "fota/fota_crypto_defs.h"
#include "fota/fota_component_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION)
#define MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION 3
#endif

#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION >= 3)
#define FOTA_HEADER_HAS_CANDIDATE_READY 1
#else
#define FOTA_HEADER_HAS_CANDIDATE_READY 0
#endif

#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION >= 3)
#define FOTA_HEADER_SUPPORTS_ENCRYPTION 1
#else
#define FOTA_HEADER_SUPPORTS_ENCRYPTION 0
#endif

#define FOTA_FW_HEADER_MAGIC ((uint32_t)(0x5c0253a3))

#define FOTA_CANDIDATE_READY_MAGIC ((uint32_t)(0xfed54e01))

#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION == 3)
#if !defined(MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT)
#define MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT 1
#endif
#else
#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
#error MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT enabled only for header version 3
#endif
#endif

// Tells that we have a candidate ready
typedef struct {
    uint32_t magic;
    char comp_name[FOTA_COMPONENT_MAX_NAME_SIZE];
} fota_candidate_ready_header_t;

/*
 * FW header as found in flash.
 *
 * FW image is accompanied with header contaning image metadata.
 * The header is consumed by bootloader for verifying image integrity and by the Pelion FOTA
 * module for reporting current version details.
 */
typedef struct {
    uint32_t magic;                                 /*< Magic value */
    uint32_t fw_size;                               /*< FW size in bytes */
    uint64_t version;                               /*< FW version - timestamp */
    uint8_t digest[FOTA_CRYPTO_HASH_SIZE];          /*< FW image SHA256 digest */
    uint8_t precursor[FOTA_CRYPTO_HASH_SIZE];       /*< Only relevant for update candidate - contains previously installed FW SHA256 digest */
} fota_header_info_t;

size_t fota_get_header_size(void);
void fota_set_header_info_magic(fota_header_info_t *header_info);
int fota_deserialize_header(const uint8_t *buffer, size_t buffer_size, fota_header_info_t *header_info);
int fota_serialize_header(const fota_header_info_t *header_info, uint8_t *header_buf, size_t header_buf_size, size_t *header_buf_actual_size);

#ifdef __cplusplus
}
#endif

#endif // __FOTA_HEADER_INFO_H_
