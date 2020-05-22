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

#ifndef __FOTA_BLOCK_DEVICE_H_
#define __FOTA_BLOCK_DEVICE_H_

#include "fota/fota_base.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FOTA_INTERNAL_FLASH_BD      1
#define FOTA_CUSTOM_BD              2
#define FOTA_EXTERNAL_BD            3

// For testing purposes
int fota_bd_create(uint32_t size, uint32_t read_size, uint32_t prog_size,
                   uint32_t erase_size);

/*
 * Pelion FOTA block device initialize
 *
 * Block device is used for storing update candidate.
 *
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_bd_init(void);

/*
 * Pelion FOTA block device deinitialize
 *
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_bd_deinit(void);

/*
 * Pelion FOTA block device size getter
 * \return block device size. A positive value on success 0 otherwise.
 */
uint32_t fota_bd_size(void);

/*
 * Pelion FOTA block device read.
 *
 * \param[out] buffer Destination buffer to be filled. The buffer size must be greater or equal to size argument.
 * \param[in]  addr   Read address
 * \param[in]  size   Size to read in bytes, must be a multiple of the read block size
 * \return FOTA_STATUS_SUCCESS on success
 * \note If a failure occurs, it is not possible to determine how many bytes succeeded
 */
int fota_bd_read(void *buffer, uint32_t addr, uint32_t size);

/*
 * Pelion FOTA block device program.
 *
 * Programs block to a block device.
 * The blocks must have been erased prior to being programmed.
 *
 * \param[in] buffer Source buffer to be programed.
 * \param[in] addr   Address of block to begin writing to.
 * \param[in] size   Size to write in bytes, must be a multiple of the program block size
 * \return FOTA_STATUS_SUCCESS on success
 * \note If a failure occurs, it is not possible to determine how many bytes succeeded
 */
int fota_bd_program(const void *buffer, uint32_t addr, uint32_t size);

/*
 * Pelion FOTA block device erase.
 *
 * Erase blocks on a block device. Size must be a multiple of the erase block size.
 *
 * \param[in] addr Address of block to begin erasing.
 * \param[in] size Size to erase in bytes, must be a multiple of the erase block size.
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_bd_erase(uint32_t addr, uint32_t size);

/*
 * Pelion FOTA block device get the size of a readable block.
 *
 * \return The size of a readable block in bytes.
 */
uint32_t fota_bd_get_read_size(void);

/*
 * Pelion FOTA block device get the size of a programmable block.
 *
 * \return The size of a programmable block in bytes. A positive value on success 0 otherwise.
 */
uint32_t fota_bd_get_program_size(void);

/*
 * Pelion FOTA block device get the size of a erasable block given address.
 *
 * \param[in] addr Address of erasable block.
 * \return The size of an erasable block in bytes. A positive value on success 0 otherwise.
 */
uint32_t fota_bd_get_erase_size(uint32_t addr);

/*
 * Pelion FOTA block device get the value of storage when erased.
 *
 * \returns erase value.
 */
uint8_t fota_bd_get_erase_value(void);

#ifdef __cplusplus
}
#endif

#endif // __FOTA_BLOCK_DEVICE_H_
