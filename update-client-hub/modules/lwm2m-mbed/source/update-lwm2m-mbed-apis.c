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

#include "update-client-common/arm_uc_config.h"

#if defined (ARM_UC_ENABLE) && (ARM_UC_ENABLE == 1)
#include "update-lwm2m-mbed-apis.h"

#ifdef MBED_CONF_MBED_CLIENT_ENABLE_CPP_API

const ARM_UPDATE_MONITOR ARM_UCS_LWM2M_MONITOR = {
    .GetVersion           = ARM_UCS_LWM2M_MONITOR_GetVersion,
    .GetCapabilities      = ARM_UCS_LWM2M_MONITOR_GetCapabilities,
    .Initialize           = ARM_UCS_LWM2M_MONITOR_Initialize,
    .Uninitialize         = ARM_UCS_LWM2M_MONITOR_Uninitialize,

    .SendState            = ARM_UCS_LWM2M_MONITOR_SendState,
#if defined (OPTIMIZED_UC) && (OPTIMIZED_UC == 1)
    .SendUpdateResult     = ARM_UCS_LWM2M_MONITOR_SendUpdateResult,
#endif
    .SendName             = ARM_UCS_LWM2M_MONITOR_SendName,
    .SendVersion          = ARM_UCS_LWM2M_MONITOR_SendVersion,

    .SetBootloaderHash    = ARM_UCS_LWM2M_MONITOR_SetBootloaderHash,
    .SetOEMBootloaderHash = ARM_UCS_LWM2M_MONITOR_SetOEMBootloaderHash
};
#endif // #ifdef MBED_CONF_MBED_CLIENT_ENABLE_CPP_API

#if defined (OPTIMIZED_UC) && (OPTIMIZED_UC == 1)
const ARM_UPDATE_SOURCE ARM_UCS_LWM2M_SOURCE = {
    .GetVersion             = 0,
    .GetCapabilities        = 0,
    .Initialize             = ARM_UCS_LWM2M_SOURCE_Initialize,
    .Uninitialize           = ARM_UCS_LWM2M_SOURCE_Uninitialize,
#if (MAX_SOURCES == 1)
    .GetManifestDefaultCost = 0,
#else
    .GetManifestDefaultCost = ARM_UCS_LWM2M_SOURCE_GetManifestDefaultCost,
#endif
    .GetManifestURLCost     = 0,
    .GetFirmwareURLCost     = 0,
    .GetKeytableURLCost     = 0,
    .GetManifestDefault     = ARM_UCS_LWM2M_SOURCE_GetManifestDefault,
    .GetManifestURL         = 0,
    .GetFirmwareFragment    = ARM_UCS_LWM2M_SOURCE_GetFirmwareFragment,
    .GetKeytableURL         = 0
};
#else  // standard UC unneeded stuff
#error we_should_use_optimized_version
const ARM_UPDATE_SOURCE ARM_UCS_LWM2M_SOURCE = {
    .GetVersion             = ARM_UCS_LWM2M_SOURCE_GetVersion,
    .GetCapabilities        = ARM_UCS_LWM2M_SOURCE_GetCapabilities,
    .Initialize             = ARM_UCS_LWM2M_SOURCE_Initialize,
    .Uninitialize           = ARM_UCS_LWM2M_SOURCE_Uninitialize,
    .GetManifestDefaultCost = ARM_UCS_LWM2M_SOURCE_GetManifestDefaultCost,
    .GetManifestURLCost     = ARM_UCS_LWM2M_SOURCE_GetManifestURLCost,
    .GetFirmwareURLCost     = ARM_UCS_LWM2M_SOURCE_GetFirmwareURLCost,
    .GetKeytableURLCost     = ARM_UCS_LWM2M_SOURCE_GetKeytableURLCost,
    .GetManifestDefault     = ARM_UCS_LWM2M_SOURCE_GetManifestDefault,
    .GetManifestURL         = ARM_UCS_LWM2M_SOURCE_GetManifestURL,
    .GetFirmwareFragment    = ARM_UCS_LWM2M_SOURCE_GetFirmwareFragment,
    .GetKeytableURL         = ARM_UCS_LWM2M_SOURCE_GetKeytableURL
};
#endif

#endif // ARM_UC_ENABLE
