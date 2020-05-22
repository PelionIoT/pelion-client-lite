// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
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

#ifndef __FOTA_CONFIG_H_
#define __FOTA_CONFIG_H_

#if !defined(FOTA_UNIT_TEST)

// skip this include in Bootloader and unittest builds as the configurations are delivered by other means
#include "MbedCloudClientConfig.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#ifndef MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE
#error Block device type must be defined
#endif

#if !defined(MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE) || (MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE == 0)
#error Storage size should be defined and have a nonzero value
#endif

#endif // MBED_CLOUD_CLIENT_FOTA_ENABLE

#else  // external configuration - unit tests

#if !defined(MBED_CLOUD_CLIENT_FOTA_STORAGE_START_ADDR)
#define MBED_CLOUD_CLIENT_FOTA_STORAGE_START_ADDR 0
#endif

#if !defined(MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE)
#define MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE 0
#endif

#endif // defined(FOTA_UNIT_TEST)


#endif  // __FOTA_CONFIG_H_
