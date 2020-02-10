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

#ifndef __DMC_CONNECT_UPDATE_H__
#define __DMC_CONNECT_UPDATE_H__

/*! \file dmc_update_api.h
* \brief Update-related Device Management Client API functions.
 */

#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE

#include "update-client-hub/update_client_hub.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Set an update authorization handler.
 * \param authorize_handler A handler to authorize the update.
 */
void pdmc_connect_update_set_authorize_handler(void (*authorize_handler)(int32_t request, uint64_t priority));

/**
 * \brief Set an update error handler.
 * \param error_handler A handler for update errors.
 */
void pdmc_connect_update_set_error_handler(void (*error_handler)(int32_t error));

/** 
 * \brief Set an update progress handler.
 * \param progress_handler A handler for the update progress status information.
 */
void pdmc_connect_update_set_progress_handler(void (*progress_handler)(uint32_t progress, uint32_t total));

#ifdef __cplusplus
}
#endif


#endif // MBED_CLOUD_CLIENT_SUPPORT_UPDATE

#endif //__DMC_CONNECT_UPDATE_H__

