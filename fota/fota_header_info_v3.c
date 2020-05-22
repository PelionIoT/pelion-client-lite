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

#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include "fota/fota_header_info.h"
#include "fota/fota_status.h"


#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION == 3)

int fota_deserialize_header(const uint8_t *buffer, size_t buffer_size, fota_header_info_t *header_info)
{
    FOTA_DBG_ASSERT(sizeof(*header_info) <= buffer_size);
    memcpy(header_info, buffer, buffer_size);
    if (header_info->magic != FOTA_FW_HEADER_MAGIC) {
        FOTA_TRACE_ERROR("Invalid header in current installed firmware");
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    return FOTA_STATUS_SUCCESS;
}

int fota_serialize_header(const fota_header_info_t *header_info, uint8_t *header_buf, size_t header_buf_size, size_t *header_buf_actual_size)
{
    FOTA_DBG_ASSERT(sizeof(*header_info) <= header_buf_size);
    memcpy(header_buf, header_info, sizeof(*header_info));
    *header_buf_actual_size = sizeof(*header_info);

    return FOTA_STATUS_SUCCESS;
}

size_t fota_get_header_size(void)
{
    return sizeof(fota_header_info_t);
}

void fota_set_header_info_magic(fota_header_info_t *header_info)
{
    FOTA_DBG_ASSERT(header_info);
    header_info->magic = FOTA_FW_HEADER_MAGIC;
}

#endif

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
