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

#include <stdlib.h>
#include "lwm2m_registry_meta.h"
#include "lwm2m_registry.h"
#include "lwm2m_registry_static_internal.h"
#include "lwm2m_heap.h"
#include "oma_lwm2m_object_defs.h"
#include "ns_list.h"
#include "mbed-trace/mbed_trace.h"

#ifdef MBED_CLIENT_ENABLE_DYNAMIC_CREATION
#include "lwm2m_registry_dynamic.h"
#endif

#define TRACE_GROUP "rmet"

#ifdef MBED_CLIENT_ENABLE_DYNAMIC_STATIC_CREATION
/* metadata about LWM2M Objects and Resources is also stored in a dynamic list where
 * application or internal modules can add their own objects instead of relying on the
 * dynamic object creation feature.
 */
typedef struct registry_meta_dynamic_static_object_definition {
    const lwm2m_object_meta_definition_t *object;
    ns_list_link_t link;
} registry_meta_dynamic_static_object_definition_list_t;

// Note: the list head is static data, but could also reside in the registry_t instance. that requires some interface changes though.
typedef NS_LIST_HEAD(registry_meta_dynamic_static_object_definition_list_t, link) lwm2m_meta_dynamic_static_object_list_t;
static lwm2m_meta_dynamic_static_object_list_t registry_meta_dynamic_static_definitions_list = NS_LIST_INIT(registry_meta_dynamic_static_definitions_list);

static registry_status_t registry_meta_get_dynamic_static_object_definition(uint16_t object_id, const lwm2m_object_meta_definition_t** object_def);
static registry_status_t registry_meta_get_dynamic_static_resource_definition(uint16_t object_id, uint16_t resource_id, const lwm2m_resource_meta_definition_t **resource_def);
#endif // MBED_CLIENT_ENABLE_DYNAMIC_STATIC_CREATION

registry_status_t registry_meta_get_object_definition(uint16_t object_id, const lwm2m_object_meta_definition_t** object_def) {

    if (registry_static_internal_get_object_definition(object_id, object_def) == REGISTRY_STATIC_INTERNAL_STATUS_OK) {
        return REGISTRY_STATUS_OK;
    }
#ifdef MBED_CLIENT_ENABLE_DYNAMIC_CREATION
    else if (registry_dynamic_get_object_definition(object_id, object_def) == REGISTRY_STATUS_OK) {
        return REGISTRY_STATUS_OK;
    }
#endif
#ifdef MBED_CLIENT_ENABLE_DYNAMIC_STATIC_CREATION
    else if (registry_meta_get_dynamic_static_object_definition(object_id, object_def) == REGISTRY_STATUS_OK) {
        return REGISTRY_STATUS_OK;
    }
#endif
    else {
        return REGISTRY_STATUS_NOT_FOUND;
    }
}

registry_status_t registry_meta_get_resource_definition(uint16_t object_id, uint16_t resource_id, const lwm2m_resource_meta_definition_t** resource_def) {

    if (registry_static_internal_get_resource_definition(object_id, resource_id, resource_def) == REGISTRY_STATIC_INTERNAL_STATUS_OK) {
        return REGISTRY_STATUS_OK;
    }
#ifdef MBED_CLIENT_ENABLE_DYNAMIC_CREATION
    else if (registry_dynamic_get_resource_definition(object_id, resource_id, resource_def) == REGISTRY_STATUS_OK) {
        return REGISTRY_STATUS_OK;
    }
#endif
#ifdef MBED_CLIENT_ENABLE_DYNAMIC_STATIC_CREATION
    else if (registry_meta_get_dynamic_static_resource_definition(object_id, resource_id, resource_def) == REGISTRY_STATUS_OK) {
        return REGISTRY_STATUS_OK;
    }
#endif
    else {
        return REGISTRY_STATUS_NOT_FOUND;
    }
}

lwm2m_resource_observation_flags_t registry_meta_is_resource_observable(const lwm2m_resource_meta_definition_t* resource_def) {

    // if resource type or operations haven't been defined or reading is not allowed, resource cannot be observed
    if ((LWM2M_RESOURCE_TYPE_NONE == resource_def->type) ||
        (LWM2M_RESOURCE_OPERATIONS_NONE == resource_def->operations) || // poinless check as LWM2M_RESOURCE_OPERATIONS_R can be none
        !(LWM2M_RESOURCE_OPERATIONS_R & resource_def->operations)) {

        return LWM2M_RESOURCE_NOT_OBSERVABLE;

    }

    return LWM2M_RESOURCE_OBSERVABLE;
}

#ifdef MBED_CLIENT_ENABLE_DYNAMIC_CREATION
void registry_meta_dynamic_list_destroy()
{
    registry_dynamic_list_destroy();
}

registry_status_t registry_meta_set_operation_mode(registry_path_t path,
                                      const lwm2m_resource_meta_definition_operations_t mode)
{
    return registry_dynamic_resource_set_operation_mode(path, mode);
}
#endif



#ifdef MBED_CLIENT_ENABLE_DYNAMIC_STATIC_CREATION
registry_status_t registry_meta_add_object_definition(const lwm2m_object_meta_definition_t *object_def)
{
    tr_debug("registry_meta_add_object_definition()");
    if (!object_def) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    const lwm2m_object_meta_definition_t *tmpdef;
    if (registry_meta_get_dynamic_static_object_definition(object_def->id, &tmpdef) == REGISTRY_STATUS_OK) {
        return REGISTRY_STATUS_ALREADY_EXISTS;
    }

    registry_meta_dynamic_static_object_definition_list_t *item = lwm2m_alloc(sizeof(registry_meta_dynamic_static_object_definition_list_t));
    if (item == NULL) {
        return REGISTRY_STATUS_NO_MEMORY;
    }

    item->object = object_def;

    ns_list_add_to_end(&registry_meta_dynamic_static_definitions_list, item);
    return REGISTRY_STATUS_OK;

}

registry_status_t registry_meta_remove_object_definition(const lwm2m_object_meta_definition_t *object_def)
{
    tr_debug("registry_meta_remove_object_definition()");
    ns_list_foreach_safe(registry_meta_dynamic_static_object_definition_list_t, item, &registry_meta_dynamic_static_definitions_list) {
        if (item->object == object_def) {
            ns_list_remove(&registry_meta_dynamic_static_definitions_list, item);
            item->object = 0;
            lwm2m_free(item);
            return REGISTRY_STATUS_OK;
        }
    }
    return REGISTRY_STATUS_NOT_FOUND;
}

void registry_meta_clear_object_definitions(void)
{
    tr_debug("registry_meta_clear_object_definitions()");
    ns_list_foreach_safe(registry_meta_dynamic_static_object_definition_list_t, item, &registry_meta_dynamic_static_definitions_list) {
        ns_list_remove(&registry_meta_dynamic_static_definitions_list, item);
        item->object = 0;
        lwm2m_free(item);
    }
}

static registry_status_t registry_meta_get_dynamic_static_object_definition(uint16_t object_id, const lwm2m_object_meta_definition_t** object_def)
{
    tr_debug("registry_meta_get_dynamic_static_object_definition()");
    ns_list_foreach(registry_meta_dynamic_static_object_definition_list_t, item, &registry_meta_dynamic_static_definitions_list) {
        if (item->object && item->object->id == object_id) {
            *object_def = item->object;
            return REGISTRY_STATUS_OK;
        }
    }
    return REGISTRY_STATUS_NOT_FOUND;

}

static registry_status_t registry_meta_get_dynamic_static_resource_definition(uint16_t object_id, uint16_t resource_id, const lwm2m_resource_meta_definition_t **resource_def)
{
    tr_debug("registry_meta_get_dynamic_static_resource_definition()");
    const lwm2m_object_meta_definition_t *obj_def;
    if (registry_meta_get_dynamic_static_object_definition(object_id, &obj_def) != REGISTRY_STATUS_OK) {
        return REGISTRY_STATUS_NOT_FOUND;
    }

    for (int res_defs_cursor=0; res_defs_cursor < obj_def->resources_count; res_defs_cursor++) {

        const lwm2m_resource_meta_definition_t* res_def = &obj_def->resources.static_resources[res_defs_cursor];
        if (res_def->id == resource_id) {
            *resource_def = &obj_def->resources.static_resources[res_defs_cursor];
            return REGISTRY_STATUS_OK;
        }
    }

    return REGISTRY_STATUS_NOT_FOUND;
}
#endif // MBED_CLIENT_ENABLE_DYNAMIC_STATIC_CREATION
