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

#ifndef LWM2M_REGISTRY_DYNAMIC_H
#define LWM2M_REGISTRY_DYNAMIC_H

#include "oma_lwm2m_object_defs.h"
#include "lwm2m_registry.h"
#include "ns_list.h"

#include <stdint.h>

/** \file lwm2m_registry_dynamic.h
 *  \brief Client Lite internal LwM2M Object registry dynamic metadata API.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Initialize the dynamic list.
 *
 */
void registry_dynamic_list_init(void);

/**
 * \brief Destroy the dynamic list.
 *
 */
void registry_dynamic_list_destroy(void);

/**
 * \brief Add an LwM2M Object into the list.
 *
 * \param object_id LwM2M Object ID.
 *
 * \return REGISTRY_STATUS_OK Object added into the list.
 * \return REGISTRY_STATUS_NO_MEMORY No memory to store Object.
 *
 */
registry_status_t registry_add_dynamic_object(const uint16_t object_id);

/**
 * \brief Retrieve an LwM2M Object definition.
 *
 * \param object_id LwM2M Object ID.
 * \param object_def Target pointer to a const Object definition.
 *
 * \return REGISTRY_STATUS_OK Object definition was successfully retrieved.
 * \return REGISTRY_STATUS_NOT_FOUND Object definition was not found.
 *
 */
registry_status_t registry_dynamic_get_object_definition(const uint16_t object_id, const lwm2m_object_meta_definition_t **object_def);

/**
 * \brief Add an LwM2M Resource.
 *
 * \param res_id Resource ID.
 * \param type Resource type.
 * \param resource_name Name of the Resource.
 * \param multiple Resource supports multiple Instances.
 * \param object Object pointer to store the Resource data.
 *
 * \return REGISTRY_STATUS_OK Object added into list.
 * \return ERGISTRY_STATUS_NO_MEMORY No memory to store a new Resource.
 *
 */
registry_status_t registry_add_dynamic_resource(const uint16_t res_id,
                                                const lwm2m_resource_meta_definition_types_t type,
                                                const char *resource_name,
                                                const lwm2m_resource_meta_definition_multiple_t multiple,
                                                const lwm2m_object_meta_definition_t *object);

/**
 * \brief Retrieve an LwM2M Object Resource definition.
 *
 * \param object_id LwM2M Object ID.
 * \param resource_id LwM2M Resource ID.
 * \param resource_def Target pointer to a const Resource definition.
 *
 * \return REGISTRY_STATUS_OK Resource definition was successfully retrieved.
 * \return REGISTRY_STATUS_NOT_FOUND Resource definition was not found.
 *
 */
registry_status_t registry_dynamic_get_resource_definition(uint16_t object_id,
                                                           uint16_t resource_id,
                                                           const lwm2m_resource_meta_definition_t **resource_def);

/**
 * \brief Set operations allowed to a Resource.
 *
 * \param path Resource path.
 * \param mode Access mode to set.
 *
 * \return REGISTRY_STATUS_OK Object definition was successfully retrieved.
 * \return REGISTRY_STATUS_NOT_FOUND Object definition was not found.
 *
 */
registry_status_t registry_dynamic_resource_set_operation_mode(registry_path_t path,
                                                               const lwm2m_resource_meta_definition_operations_t mode);

/**
 * \brief Removes the LwM2M Object definition from the list.
 *
 * \param object_id ID of the LwM2M Object to be removed.
 *
 */
void registry_dynamic_list_remove_object(const uint16_t object_id);

/**
 * \brief Removes the LwM2M Resource definition from the list.
 *
 * \param object_id LwM2M Object ID.
 * \param resource_id LwM2M Resource ID.
 *
 */
void registry_dynamic_list_remove_resource(const uint16_t object_id, const uint16_t resource_id);

#ifdef __cplusplus
}
#endif
#endif // LWM2M_REGISTRY_DYNAMIC_H
