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

#ifndef __FOTA_CURR_FW_H_
#define __FOTA_CURR_FW_H_

#include "fota/fota_base.h"
#include "fota_header_info.h"

#ifdef __cplusplus
extern "C" {
#endif

uint8_t *fota_curr_fw_get_app_start_addr(void);

uint8_t *fota_curr_fw_get_app_header_addr(void);

int fota_curr_fw_read_header(fota_header_info_t *header_info);

int fota_curr_fw_read(uint8_t *buf, uint32_t offset, uint32_t size, uint32_t *num_read);

#ifdef __cplusplus
}
#endif

#endif // __FOTA_CURR_FW_H_
