/*
 * Copyright (c) 2019 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CONNECTION_PROTOMAN_LAYERS_H
#define CONNECTION_PROTOMAN_LAYERS_H

#include "protoman.h"

#if defined(TARGET_LIKE_MBED) && defined(USE_PLATFORM_CODE_OVERRIDE_PROTOMAN) && (USE_PLATFORM_CODE_OVERRIDE_PROTOMAN == 1)

#include "connection_protoman_layers_override.h"

#else

#include "mbed-protocol-manager/platform/mbedos/protoman_layer_mbedos_socket.h"

/** \file connection_protoman_layer.h
 *  \brief Used for building protoman networking layers for MbedOS.
 */

#ifdef __cplusplus
extern "C" {
#endif

struct connection_s;

/**
 *  \brief Data structure for protoman networking layers for MbedOS.
 *
 *  \note Fields of this structure are only used internally by this module.
 */
typedef struct connection_protoman_layers_s {

    struct protoman_layer_s *protoman_layer_mbedos_socket; ///< protoman structure for mbedOS socket.

} connection_protoman_layers_t;

#ifdef __cplusplus
}
#endif

#endif

#endif //CONNECTION_PROTOMAN_LAYERS_H
