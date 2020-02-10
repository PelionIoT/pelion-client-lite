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

#include <inttypes.h>
#include <stdlib.h>
#include "lwm2m_registry_meta.h"
#include "lwm2m_registry_static_internal.h"
#include "oma_lwm2m_object_defs.h"


registry_static_internal_status_t registry_static_internal_get_object_definition(uint16_t object_id, const lwm2m_object_meta_definition_t** object_def)
{
    for (int i=0; i < OMA_LWM2M_OBJECT_DEFS_SIZE; i++) {
        const lwm2m_object_meta_definition_t* temp_obj_def = &OMA_LWM2M_OBJECT_DEFS[i];
        if (object_id == temp_obj_def->id) {
            *object_def = &OMA_LWM2M_OBJECT_DEFS[i];
            return REGISTRY_STATIC_INTERNAL_STATUS_OK;
        }
    }
    return REGISTRY_STATUS_INTERNAL_NOT_FOUND;
}


registry_static_internal_status_t registry_static_internal_get_resource_definition(uint16_t object_id, uint16_t resource_id, const lwm2m_resource_meta_definition_t** resource_def)
{
    for (int obj_defs_index_cursor=0; obj_defs_index_cursor < OMA_LWM2M_OBJECT_DEFS_SIZE; obj_defs_index_cursor++) {

        const lwm2m_object_meta_definition_t* obj_def = &OMA_LWM2M_OBJECT_DEFS[obj_defs_index_cursor];

        if (object_id == obj_def->id) {

            for (int res_defs_cursor=0; res_defs_cursor < obj_def->resources_count; res_defs_cursor++) {

                const lwm2m_resource_meta_definition_t* res_def = &obj_def->resources.static_resources[res_defs_cursor];
                if (res_def->id == resource_id) {
                    *resource_def = &obj_def->resources.static_resources[res_defs_cursor];
                    return REGISTRY_STATIC_INTERNAL_STATUS_OK;
                }
            }
        }
    }
    return REGISTRY_STATUS_INTERNAL_NOT_FOUND;
}
