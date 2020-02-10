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
#ifndef LWM2M_REGISTRY_STATIC_INTERNAL_H
#define LWM2M_REGISTRY_STATIC_INTERNAL_H

#include <inttypes.h>

typedef enum registry_static_internal_status {
    REGISTRY_STATIC_INTERNAL_STATUS_NO_DATA = 1,
    REGISTRY_STATIC_INTERNAL_STATUS_OK      = 0,
    REGISTRY_STATUS_INTERNAL_NOT_FOUND      = (-1),
    REGISTRY_STATUS_INTERNAL_NO_MEMORY      = (-2),
} registry_static_internal_status_t;

registry_static_internal_status_t registry_static_internal_get_object_definition(uint16_t object_id, const lwm2m_object_meta_definition_t** object_def);
registry_static_internal_status_t registry_static_internal_get_resource_definition(uint16_t object_id, uint16_t resource_id, const lwm2m_resource_meta_definition_t** resource_def);

#endif // LWM2M_REGISTRY_STATIC_INTERNAL_H
