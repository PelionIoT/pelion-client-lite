/*
 * Copyright (c) 2017 ARM Limited. All rights reserved.
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

#ifndef TLV_SERIALIZER_H
#define TLV_SERIALIZER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "lwm2m_registry.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct registry_tlv_s {
    const uint8_t  *tlv;
    uint32_t        tlv_size;
    uint32_t        offset;
    uint32_t        type;
    uint16_t        id;
    uint32_t        length;
} registry_tlv_t;


typedef enum {
    REGISTRY_TLV_SERIALIZE_STATUS_OK = 0,
    REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND = (-1),
    REGISTRY_TLV_SERIALIZE_STATUS_NO_MEMORY = (-2),
    REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT = (-3),
    REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR = (-4)
} registry_tlv_serialize_status_t;

typedef enum {
    REGISTRY_OPERATION_UPDATE = 1,
    REGISTRY_OPERATION_REPLACE = 2
} registry_tlv_serialize_operation_t;

typedef enum {
    REGISTRY_SERIALIZE_TLV = 1,
#if MBED_CLIENT_ENABLE_SERIALIZE_PLAINTEXT
    REGISTRY_SERIALIZE_PLAINTEXT = 2,
#endif
    REGISTRY_SERIALIZE_OPAQUE = 3
} registry_serialization_format_t;

/*
 * \brief Serializes registry data (objects, resources) recursively under the given path in OMA-TLV format.
 *
 * \param registry Registry instance
 * \param path Path to start serialization from
 * \param size Will contain the size of serialized data
 * \param format Which format to use (text/plain or TLV)
 * \param status Status of the operation is written to this variable before returning from call.
 *               It can be checked to see the reason for a failure.
 *               MUST be a valid pointer to registry_tlv_serialize_status_t.
 *
 * \return Pointer to serialized data, caller must free after use.
 */
uint8_t* registry_serialize(const registry_t *registry,
                            const registry_path_t *path,
                            uint32_t *size,
                            registry_serialization_format_t format,
                            bool dirty_only,
                            registry_tlv_serialize_status_t *status);

/*
 * \brief Deserializes registry contents from TLV data to given path as described in OMA LWM2M specification
 *
 * \param registry Registry object
 * \param path Registry path where data will be deserialized into
 * \param tlv Pointer to TLV data
 * \param tlv_size Size of TLV data
 * \param operation POST / PUT operation (different logical operation in registry)
 */
registry_tlv_serialize_status_t registry_deserialize(registry_t* registry,
                                                     const registry_path_t* path,
                                                     const uint8_t* tlv,
                                                     uint32_t tlv_size,
                                                     registry_tlv_serialize_operation_t operation);


#if MBED_CLIENT_ENABLE_DESERIALIZE_PLAINTEXT
// this is utilized form unit tests, so it is left public
registry_tlv_serialize_status_t registry_deserialize_text_resource_instance(registry_t* registry,
                                                                            const registry_path_t* path,
                                                                            const char* data,
                                                                            const uint32_t data_size,
                                                                            const registry_tlv_serialize_operation_t operation);

#endif // MBED_CLIENT_ENABLE_DESERIALIZE_PLAINTEXT


#ifdef __cplusplus
}
#endif

#endif // TLV_SERIALIZER_H
