/*
 * PackageLicenseDeclared: Apache-2.0
 * Copyright (c) 2017-2018 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PROTOMAN_LAYER_MBEDOS_SOCKET_H
#define PROTOMAN_LAYER_MBEDOS_SOCKET_H

#include "stdlib.h"
#include "mbed-protocol-manager/protoman.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#if MBED_CONF_NSAPI_PRESENT

/**
 * @brief      Call C++ new from the C side. This is a bit of a workaround
 *             because the layer data was changed so that it's not owned by the
 *             protoman. This means that user of the protoman must allocate and
 *             free the Mbed OS socket layer structure.
 *
 * @return     Returns pointer to the layer on success and NULL on failure.
 */
extern void* protoman_layer_mbedos_socket_new(void);

/**
 * @brief      Call C++ delete from the C side.
 *
 * @param      layer  Pointer to the layer.
 */
extern void protoman_layer_mbedos_socket_delete(void *layer);

/**
 * @brief      Add Mbed OS socket layer to the given protoman stack.
 *
 * @param      protoman  Pointer to the protoman instance.
 * @param      layer     Pointer to the layer data structure.
 *
 * @return     Returns 0 on success and -1 if out of memory.
 */
extern int protoman_add_layer_mbedos_socket(struct protoman_s *protoman, struct protoman_layer_s *layer);

#endif // MBED_CONF_NSAPI_PRESENT

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // PROTOMAN_LAYER_MBEDOS_SOCKET_H
