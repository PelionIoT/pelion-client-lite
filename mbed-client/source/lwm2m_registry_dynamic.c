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

#include <stdint.h>
#include "lwm2m_registry.h"
#include "lwm2m_registry_dynamic.h"
#include "lwm2m_heap.h"

#ifdef MBED_CLIENT_ENABLE_DYNAMIC_CREATION

/**
 * \brief Dynamic LWM2M Object definitions are stored into a linked list.
 */
typedef struct lwm2m_dynamic_object_definition {
    lwm2m_object_meta_definition_t *object;
    ns_list_link_t link;
} lwm2m_dynamic_object_list_t;

typedef NS_LIST_HEAD(lwm2m_dynamic_object_list_t, link) dynamic_object_list_t;
extern dynamic_object_list_t dynamic_object_linked_list;

dynamic_object_list_t dynamic_object_linked_list;

void registry_dynamic_list_destroy(void)
{
    ns_list_foreach_safe(lwm2m_dynamic_object_list_t, item, &dynamic_object_linked_list) {
        for (int res_defs_cursor = 0; res_defs_cursor < item->object->resources_count; res_defs_cursor++) {
            ns_list_foreach_safe(lwm2m_dynamic_resource_list_t, res_item, item->object->resources.dynamic_resources) {
                ns_list_remove(item->object->resources.dynamic_resources, res_item);
                lwm2m_free(res_item->resource);
                lwm2m_free(res_item);
                item->object->resources_count--;
            }
        }
        ns_list_remove(&dynamic_object_linked_list, item);
        lwm2m_free(item->object->resources.dynamic_resources);
        lwm2m_free(item->object);
        item->object = 0;
        lwm2m_free(item);
    }
}

void registry_dynamic_list_init(void)
{
    ns_list_init(&dynamic_object_linked_list);
}

registry_status_t registry_add_dynamic_object(const uint16_t object_id)
{
    lwm2m_dynamic_object_list_t *item = lwm2m_alloc(sizeof(lwm2m_dynamic_object_list_t));
    if (item == NULL) {
        return REGISTRY_STATUS_NO_MEMORY;
    }

    item->object = lwm2m_alloc(sizeof(lwm2m_object_meta_definition_t));
    if (item->object == NULL) {
        lwm2m_free(item);
        return REGISTRY_STATUS_NO_MEMORY;
    }

    item->object->resources.dynamic_resources = (dynamic_resource_list_t*)lwm2m_alloc(sizeof(dynamic_resource_list_t));
    if (item->object->resources.dynamic_resources == NULL) {
        lwm2m_free(item->object);
        lwm2m_free(item);
        return REGISTRY_STATUS_NO_MEMORY;
    }

    item->object->id = object_id;
    item->object->mandatory = LWM2M_OBJECT_OPTIONAL;
    item->object->multiple = LWM2M_OBJECT_MULTIPLE_INSTANCES;
    item->object->resources_count = 0;
    ns_list_init(item->object->resources.dynamic_resources);
#if MBED_CONF_MBED_CLIENT_REGISTER_RESOURCE_NAME
    item->object->name = NULL;
#endif
    ns_list_add_to_end(&dynamic_object_linked_list, item);
    return REGISTRY_STATUS_OK;
}

registry_status_t registry_add_dynamic_resource(const uint16_t res_id,
                                   const lwm2m_resource_meta_definition_types_t type,
                                   const char *resource_name,
                                   const lwm2m_resource_meta_definition_multiple_t multiple,
                                   const lwm2m_object_meta_definition_t *object)
{
    lwm2m_object_meta_definition_t *temp_object = (lwm2m_object_meta_definition_t *)object;

    lwm2m_dynamic_resource_list_t *list_item = lwm2m_alloc(sizeof(lwm2m_dynamic_resource_list_t));
    if (list_item == NULL) {
        return REGISTRY_STATUS_NO_MEMORY;
    }

    list_item->resource = (lwm2m_resource_meta_definition_t *)lwm2m_alloc(sizeof(lwm2m_resource_meta_definition_t));
    if (list_item->resource == NULL) {
        lwm2m_free(list_item);
        return REGISTRY_STATUS_NO_MEMORY;
    }
#if MBED_CONF_MBED_CLIENT_REGISTER_RESOURCE_NAME
    list_item->resource->name = resource_name;
#endif
    list_item->resource->id = res_id;
    list_item->resource->type = type;
    list_item->resource->mandatory = LWM2M_RESOURCE_OPTIONAL;
    list_item->resource->multiple = multiple;
    list_item->resource->operations = LWM2M_RESOURCE_OPERATIONS_NONE;
    ns_list_add_to_end(temp_object->resources.dynamic_resources, list_item);
    temp_object->resources_count++;
    return REGISTRY_STATUS_OK;
}

registry_status_t registry_dynamic_get_object_definition(const uint16_t object_id,
                                                         const lwm2m_object_meta_definition_t** object_def)
{
    ns_list_foreach(lwm2m_dynamic_object_list_t, item, &dynamic_object_linked_list) {
        if (item->object && item->object->id == object_id) {
            *object_def = item->object;
            return REGISTRY_STATUS_OK;
        }
    }
    return REGISTRY_STATUS_NOT_FOUND;
}

registry_status_t registry_dynamic_get_resource_definition(uint16_t object_id,
                                                           uint16_t resource_id,
                                                           const lwm2m_resource_meta_definition_t** resource_def)
{
    const lwm2m_object_meta_definition_t *object;

    if (registry_dynamic_get_object_definition(object_id, &object) == REGISTRY_STATUS_OK) {
        for (int res_defs_cursor=0; res_defs_cursor < object->resources_count; res_defs_cursor++) {
            ns_list_foreach(lwm2m_dynamic_resource_list_t, item, object->resources.dynamic_resources) {
                if (item->resource->id == resource_id) {
                    *resource_def = item->resource;
                    return REGISTRY_STATUS_OK;
                }
            }
        }
    }
    return REGISTRY_STATUS_NOT_FOUND;
}

registry_status_t registry_dynamic_resource_set_operation_mode(registry_path_t path, const lwm2m_resource_meta_definition_operations_t mode)
{
    const lwm2m_resource_meta_definition_t *resource;
    if (registry_dynamic_get_resource_definition(path.object_id, path.resource_id, &resource) == REGISTRY_STATUS_OK) {
        lwm2m_resource_meta_definition_t *res = (lwm2m_resource_meta_definition_t *)resource;
        res->operations = mode;
        return REGISTRY_STATUS_OK;
    }
    return REGISTRY_STATUS_NOT_FOUND;
}

void registry_dynamic_list_remove_object(const uint16_t object_id)
{
    ns_list_foreach_safe(lwm2m_dynamic_object_list_t, item, &dynamic_object_linked_list) {
        if (item->object->id == object_id) {
            for (int res_defs_cursor = 0; res_defs_cursor < item->object->resources_count; res_defs_cursor++) {
                ns_list_foreach_safe(lwm2m_dynamic_resource_list_t, res_item, item->object->resources.dynamic_resources) {
                    ns_list_remove(item->object->resources.dynamic_resources, res_item);
                    lwm2m_free(res_item->resource);
                    lwm2m_free(res_item);
                    item->object->resources_count--;
                }
            }
            ns_list_remove(&dynamic_object_linked_list, item);
            lwm2m_free(item->object->resources.dynamic_resources);
            lwm2m_free(item->object);
            item->object = 0;
            lwm2m_free(item);
            return;
        }
    }
}

void registry_dynamic_list_remove_resource(const uint16_t object_id, const uint16_t resource_id)
{
    ns_list_foreach_safe(lwm2m_dynamic_object_list_t, item, &dynamic_object_linked_list) {
        if (item->object->id == object_id) {
            for (int res_defs_cursor = 0; res_defs_cursor < item->object->resources_count; res_defs_cursor++) {
                ns_list_foreach_safe(lwm2m_dynamic_resource_list_t, res_item, item->object->resources.dynamic_resources) {
                    if (res_item->resource->id == resource_id) {
                        ns_list_remove(item->object->resources.dynamic_resources, res_item);
                        lwm2m_free(res_item->resource);
                        lwm2m_free(res_item);
                        item->object->resources_count--;
                        return;
                    }
                }
            }
        }
    }
}
#endif
