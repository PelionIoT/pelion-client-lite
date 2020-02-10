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

#ifndef LWM2M_REGISTRY_META_H
#define LWM2M_REGISTRY_META_H

#include <stdint.h>
#include "lwm2m_types.h"
#ifdef MBED_CLIENT_ENABLE_DYNAMIC_CREATION
#include "ns_list.h"
#endif

/*! \file lwm2m_registry_meta.h
 *  \brief Client Lite internal LwM2M Object registry metadata API.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Multiple Object flag enumeration.
 */
typedef enum lwm2m_object_meta_definition_constants_multi {
    LWM2M_OBJECT_MULTIPLE_INSTANCES   = 1, ///< Multiple.
    LWM2M_OBJECT_SINGLE_INSTANCE      = 0 ///< Single.
} lwm2m_object_meta_definition_multiple_t;

/**
 * \brief Mandatory Object flag enumeration.
 */
typedef enum lwm2m_object_meta_definition_constants_mandatory {
    LWM2M_OBJECT_MANDATORY            = 1, ///< Mandatory.
    LWM2M_OBJECT_OPTIONAL             = 0 ///< Optional.
} lwm2m_object_meta_definition_mandatory_t;

/**
 * \brief Multiple Resource flag enumeration.
 */
typedef enum lwm2m_resource_meta_definition_constants_multi {
    LWM2M_RESOURCE_MULTIPLE_INSTANCES   = 1, ///< Multiple.
    LWM2M_RESOURCE_SINGLE_INSTANCE      = 0 ///< Single.
} lwm2m_resource_meta_definition_multiple_t;

/**
 * \brief Mandatory Resource flag enumeration.
 */
typedef enum lwm2m_resource_meta_definition_constants_mandatory {
    LWM2M_RESOURCE_MANDATORY            = 1, ///< Mandatory.
    LWM2M_RESOURCE_OPTIONAL             = 0 ///< Optional.
} lwm2m_resource_meta_definition_mandatory_t;

/**
 * \brief Permitted operations.
 */
typedef enum lwm2m_resource_meta_definition_constants_operations {

    LWM2M_RESOURCE_OPERATIONS_NONE      = 0x0, ///< No operations permitted from server.
    LWM2M_RESOURCE_OPERATIONS_R         = 0x1, ///< Read.
    LWM2M_RESOURCE_OPERATIONS_W         = 0x2, ///< Write.
    LWM2M_RESOURCE_OPERATIONS_RW        = 0x3, ///< Read and Write.
    LWM2M_RESOURCE_OPERATIONS_E         = 0x4  ///< Execute.
} lwm2m_resource_meta_definition_operations_t;

/**
 * \brief Possible LWM2M Resource types.
 */
typedef enum lwm2m_resource_meta_definition_constants_types {

    LWM2M_RESOURCE_TYPE_NONE            = 0, ///< No type.
    LWM2M_RESOURCE_TYPE_STRING          = 1, ///< String Resource.
    LWM2M_RESOURCE_TYPE_INTEGER         = 2, ///< 64-bit signed integer Resource.
    LWM2M_RESOURCE_TYPE_FLOAT           = 3, ///< Float Resource.
    LWM2M_RESOURCE_TYPE_BOOLEAN         = 4, ///< Boolean Resource.
    LWM2M_RESOURCE_TYPE_OPAQUE          = 5, ///< Opaque Resource.
    LWM2M_RESOURCE_TYPE_TIME            = 6, ///< Time Resource.
    LWM2M_RESOURCE_TYPE_OBJLNK          = 7 ///< Objlink Resource. \note Not properly supported.
} lwm2m_resource_meta_definition_types_t;

/**
 * \brief LwM2M Resource description.
 */
typedef struct lwm2m_resource_meta_definition {
    uint16_t id; ///< LWM2M Resource ID.
    lwm2m_resource_meta_definition_multiple_t multiple:1; ///< Multiple instances flag.
    lwm2m_resource_meta_definition_mandatory_t mandatory:1; ///< Mandatory instances flag.
    lwm2m_resource_meta_definition_operations_t operations:3; ///< Permitted operations flags.
    lwm2m_resource_meta_definition_types_t type:3; ///< Resource type.
    /* Resource name (null-terminated) */
#if MBED_CONF_MBED_CLIENT_REGISTER_RESOURCE_NAME
    const char * name; ///< Resource name, a null-terminated string.
#endif
} lwm2m_resource_meta_definition_t;

/** helper macro for creating resource metadata structures */
#if MBED_CONF_MBED_CLIENT_REGISTER_RESOURCE_NAME
#define LWM2M_RESOURCE_DEFINITION(id, multiple, mandatory, operations, type, description) \
    {id, multiple, mandatory, operations, type, description}
#else
#define LWM2M_RESOURCE_DEFINITION(id, multiple, mandatory, operations, type, description) \
    {id, multiple, mandatory, operations, type}
#endif

/** helper macro for creating object metadata structures */
#if MBED_CONF_MBED_CLIENT_REGISTER_RESOURCE_NAME
#define LWM2M_OBJECT_DEFINITION(id, multiple, mandatory, description, resource_count, resource_list) \
    {id, multiple, mandatory, description, resource_count, .resources.static_resources = resource_list}
#else
#define LWM2M_OBJECT_DEFINITION(id, multiple, mandatory, description, resource_count, resource_list) \
    {id, multiple, mandatory, resource_count, .resources.static_resources = resource_list}
#endif


#ifdef MBED_CLIENT_ENABLE_DYNAMIC_CREATION
/**
 * \brief Dynamic LwM2M Resource definitions are stored into a linked list.
 */
typedef struct lwm2m_dynamic_resource_definition {
    lwm2m_resource_meta_definition_t *resource; ///< Pointer to the resource.
    ns_list_link_t link; ///< Link.
} lwm2m_dynamic_resource_list_t;

typedef NS_LIST_HEAD(lwm2m_dynamic_resource_list_t, link) dynamic_resource_list_t;
#endif // MBED_CLIENT_ENABLE_DYNAMIC_CREATION

/**
 * \brief Union for keeping track of static or dynamic resource metadata objects.
 */
typedef union {
    const lwm2m_resource_meta_definition_t *static_resources;   ///< Array of resource IDs of this LwM2M Object.
#ifdef MBED_CLIENT_ENABLE_DYNAMIC_CREATION
    dynamic_resource_list_t *dynamic_resources;                 ///< Dynamic array of resource IDS of this LwM2M Object.
#endif
} lwm2m_resource_meta_definition_u;

// TODO: re-organize these to get rid of wasted space caused by padding
/**
 * \brief LwM2M Object description.
 */
typedef struct lwm2m_object_meta_definition {
    uint16_t id;                                            ///< LwM2M Object ID.
    lwm2m_object_meta_definition_multiple_t multiple:1;     ///< Flag: Are multiple Instances allowed?
    lwm2m_object_meta_definition_mandatory_t mandatory:1;   ///< Flag: Is an Instance mandatory or optional?
#if MBED_CONF_MBED_CLIENT_REGISTER_RESOURCE_NAME
    const char* name;                                       ///< Object name.
#endif
    // XXX: commented out ad merge conflict resolution: uint32_t name_length;
    uint16_t resources_count;                               ///< Number of LwM2M Resources (meta definitions) in this Object.
    lwm2m_resource_meta_definition_u resources;             ///< Pointer (union) to LwM2M Resource meta definitions.
} lwm2m_object_meta_definition_t;

/**
 * \brief Type for observable return value.
 */
typedef enum lwm2m_resource_observation_flags {
    LWM2M_RESOURCE_NOT_OBSERVABLE = 0, ///< Resource not observable.
    LWM2M_RESOURCE_OBSERVABLE     = 1 ///< Resource can be observed.
} lwm2m_resource_observation_flags_t;

/**
 * \brief Retrieve LwM2M Object definition.
 *
 * \param object_id LwM2M Object ID.
 * \param object_def Target pointer to a const Object definition.
 *
 * \return REGISTRY_STATUS_OK Object definition was succesfully retrieved.
 * \return REGISTRY_STATUS_NOT_FOUND Object definition was not found.
 *
 */
registry_status_t registry_meta_get_object_definition(uint16_t object_id, const lwm2m_object_meta_definition_t** object_def);


/**
 * \brief Retrieve LwM2M Object Resource definition.
 *
 * \param object_id LwM2M Object ID.
 * \param resource_id LwM2M Resource ID.
 * \param resource_def Target pointer to a const Resource definition.
 *
 * \return REGISTRY_STATUS_OK Resource definition was succesfully retrieved.
 * \return REGISTRY_STATUS_NOT_FOUND Resource definition was not found.
 *
 */
registry_status_t registry_meta_get_resource_definition(uint16_t object_id, uint16_t resource_id, const lwm2m_resource_meta_definition_t** resource_def);


/**
 * \brief Determine whether the Resource is observable.
 *
 * \param resource_def LwM2M Resource.
 *
 * \return LWM2M_RESOURCE_NOT_OBSERVABLE Resource is not observable.
 * \return LWM2M_RESOURCE_OBSERVABLE Resource is observable (has value, can change).
 */
lwm2m_resource_observation_flags_t registry_meta_is_resource_observable(const lwm2m_resource_meta_definition_t* resource_def);

#ifdef MBED_CLIENT_ENABLE_DYNAMIC_CREATION
/**
 * \brief Destroys the dynamic resource list
 */
void registry_meta_dynamic_list_destroy(void);


/**
 * \brief Set operation mode
 *
 * \param path URI path of the Resource.
 *
 * \return REGISTRY_STATUS_OK Value set.
 * \return REGISTRY_STATUS_NOT_FOUND Resource not found.
 */
registry_status_t registry_meta_set_operation_mode(registry_path_t path,
                                                   const lwm2m_resource_meta_definition_operations_t mode);
#endif // MBED_CLIENT_ENABLE_DYNAMIC_CREATION

#ifdef MBED_CLIENT_ENABLE_DYNAMIC_STATIC_CREATION
/**
 * \brief Register non-modifiable metadata for LwM2M Objects and their Resources.
 *
 * \param object_def Pointer to caller-owned Object definition structure.
 *
 * \return REGISTRY_STATUS_OK Definition was added to internal list.
 * \return REGISTRY_STATUS_NO_MEMORY Out of memory.
 * \return REGISTRY_STATUS_ALREADY_EXISTS Definition already exists in list.
 * \return REGISTRY_STATUS_INVALID_INPUT Bad arguments given.
 *
 */
registry_status_t registry_meta_add_object_definition(const lwm2m_object_meta_definition_t *object_def);

/**
 * \brief Unregister metadata for LwM2M Objects and their Resources.
 *
 * \note Must be called for every Object that was added using `registry_meta_add_object_definition()`.
 */
registry_status_t registry_meta_remove_object_definition(const lwm2m_object_meta_definition_t *object_def);

/**
 * \brief Clear the internal list of dynamically added non-modifiable Object definitions.
 */
void registry_meta_clear_object_definitions(void);
#endif // MBED_CLIENT_ENABLE_DYNAMIC_STATIC_CREATION

#ifdef __cplusplus
}
#endif
#endif // LWM2M_REGISTRY_META_H
