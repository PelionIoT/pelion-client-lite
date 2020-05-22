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

#include <stddef.h>
#include <string.h>
#include <assert.h>
#include "mbed-client/lwm2m_registry.h"
#include "mbed-client/lwm2m_heap.h"
#include "mbed-client/lwm2m_notifier.h"
#include "mbed-client/lwm2m_registry_dynamic.h"
#include "eventOS_event.h"
#include "common_functions.h"
#include "randLIB.h"
#include "mbed-trace/mbed_trace.h"
#include "lwm2m_storage.h"
#include "CloudClientStorage.h"
#define TRACE_GROUP "OREG"

#define REGISTRY_PREALLOCATED_EVENT_READY 0
#define REGISTRY_PREALLOCATED_EVENT_SENT 1

// Structure used internally for holding observation data
typedef struct observation_data_s {

    registry_available_parameters_t available;
    unsigned token_size:4;
    bool dirty:1;
    bool sent:1;
    bool observed:1;
    uint8_t obs_data[];

} observation_data_t;

// Structure used internally for holding the dynamic data of a resource
typedef struct registry_object_s {

    void *next;
    observation_data_t *observation_data;
    registry_object_value_t value;
    registry_callback_t callback;
    uint32_t max_age;
    uint16_t id;
    unsigned registered:1;
    unsigned empty:1;
#if MBED_CLIENT_ENABLE_AUTO_OBSERVATION
    bool auto_observable:1;
#endif
    unsigned publish_value:1; /* If true then the resource value will be part of registration message */
#if MBED_CLIENT_REGISTRY_OBJECT_COUNT
    bool allocated:1;
#endif
} registry_object_t;

// Structure used internally for keeping track of event listeners
typedef struct registry_event_listener_s {

    void *next;
    arm_event_storage_t event;
    registry_event_listen_mode_t mode:2;

}registry_event_listener_t;

// Data types for internal usage
typedef enum registry_data_type_e {
    REGISTRY_DATA_LIST = 0,
    REGISTRY_DATA_INT,
#if MBED_CLIENT_ENABLE_FLOAT_VALUE
    REGISTRY_DATA_FLOAT,
#endif
    REGISTRY_DATA_STRING,
    REGISTRY_DATA_OPAQUE,
    REGISTRY_DATA_EMPTY
}registry_data_type_t;

static void send_events(registry_t *registry, const registry_path_t *path, registry_event_listen_mode_t mode);
static registry_data_type_t get_data_type(const registry_path_t *path);
static uint8_t multiple_object_instances(uint16_t object_id, registry_status_t *status);
static uint8_t multiple_resource_instances(uint16_t object_id, uint16_t resource_id, registry_status_t *status);
static void free_object_value(registry_data_type_t type, registry_object_value_t *value);
static void read_obs_data(registry_observation_parameters_t *parameters, const observation_data_t *data);
static void write_obs_data(observation_data_t *data, const registry_observation_parameters_t *parameters);
static uint8_t get_obs_data_size(const registry_observation_parameters_t *parameters);
static uint16_t get_id_from_path(const registry_path_t *path);
static void set_id_to_path(registry_path_t *path, uint16_t id);
static registry_object_t *get_object_from(const registry_path_t *path, sll_t *list);
static registry_status_t remove_objects_from(registry_t *registry, registry_path_t *path, sll_t *list, uint8_t first_round);
static registry_status_t remove_object_from(registry_t *registry, registry_path_t *path, sll_t *list);
static void registry_remove_all_objects(registry_t *registry);
static void clear_object(registry_object_t *object);
static uint8_t valid_object(const registry_path_t *path, uint8_t *multi_resource);
static registry_status_t registry_add_object(registry_t *registry, const registry_path_t *path, registry_object_t **object);
static registry_object_t *registry_get_object(const registry_t *registry, const registry_path_t *path);
static registry_status_t registry_get_object_data(const registry_t *registry, const registry_path_t *path, registry_object_value_t *value, registry_data_type_t data_type);
static registry_status_t registry_set_object_data(registry_t *registry, const registry_path_t *path, registry_object_value_t value, registry_data_type_t data_type);
static registry_status_t read_object_data(registry_listing_t *listing, registry_object_t *object, registry_object_value_t *value, registry_observation_parameters_t *parameters);
static void read_nested_list(registry_listing_t *listing, registry_object_t *object, uint8_t level);
static registry_object_t **listing_next(registry_listing_t *listing);
static registry_object_t **listing_next_reverse(registry_listing_t *listing);

#if MBED_CLIENT_ENABLE_AUTO_OBSERVATION
#define AUTO_OBS_TOKEN_MIN 1
#define AUTO_OBS_TOKEN_MAX 1023
#endif

#if MBED_CLIENT_REGISTRY_OBJECT_COUNT

static registry_object_t registy_objects[MBED_CLIENT_REGISTRY_OBJECT_COUNT];

static registry_object_t *allocate_registry_object(void)
{
    int i;

    for (i = 0; i < MBED_CLIENT_REGISTRY_OBJECT_COUNT; i++) {
        if (!registy_objects[i].allocated) {
            registy_objects[i].allocated = true;
            return &registy_objects[i];
        }
    }

    return NULL;
}

static void free_registry_object(registry_object_t *object)
{
    if (object) {
        object->allocated = false;
    }
}

#else

#define allocate_registry_object() lwm2m_alloc(sizeof(registry_object_t))

#define free_registry_object(object) lwm2m_free(object)

#endif

void registry_init(registry_t *registry, struct notifier_s *notifier)
{
    sll_init(registry->object_list);
    sll_init(registry->event_list);
    registry->notifier = notifier;
#if MBED_CLIENT_ENABLE_AUTO_OBSERVATION
    registry->auto_obs_token = randLIB_get_random_in_range(AUTO_OBS_TOKEN_MIN, AUTO_OBS_TOKEN_MAX);
#endif
#ifdef MBED_CLIENT_ENABLE_DYNAMIC_CREATION
    registry_dynamic_list_init();
#endif
}

// This is the real printer, which must be used via print_registry_path(), which lets compiler to remove
// the prefix and format strings on non-tracing builds. This saves ~200B of flash.
#if defined(MBED_CONF_MBED_TRACE_ENABLE) && (MBED_CONF_MBED_TRACE_ENABLE == 1)
void _print_registry_path(const char *prefix, const registry_path_t *path)
{
    switch (path->path_type) {
        case REGISTRY_PATH_OBJECT:
            tr_debug("%s%u", prefix, path->object_id);
            break;
        case REGISTRY_PATH_OBJECT_INSTANCE:
            tr_debug("%s%u/%u", prefix, path->object_id, path->object_instance_id);
            break;
        case REGISTRY_PATH_RESOURCE:
            tr_debug("%s%u/%u/%u", prefix, path->object_id, path->object_instance_id, path->resource_id);
            break;
        case REGISTRY_PATH_RESOURCE_INSTANCE:
            tr_debug("%s%u/%u/%u/%u", prefix, path->object_id, path->object_instance_id, path->resource_id, path->resource_instance_id);
            break;
    }
}
#endif

void registry_destroy(registry_t *registry)
{
    registry_remove_all_objects(registry);
}

static void send_allocated_event(arm_event_storage_t *event_storage)
{

    if (event_storage->data.event_data == REGISTRY_PREALLOCATED_EVENT_SENT) {
        tr_debug("send_allocated_event() skipping event.");
        return;
    }

    event_storage->data.event_data = REGISTRY_PREALLOCATED_EVENT_SENT;
    event_storage->data.event_type = REGISTRY_EVENT_CHANGED;
    eventOS_event_send_user_allocated(event_storage);

}

static void send_events(registry_t *registry, const registry_path_t *path, registry_event_listen_mode_t mode)
{

    registry_event_listener_t *listener;
    void *p;

    sll_foreach (registry->event_list, listener, p) {

        if (mode & listener->mode) {
            send_allocated_event(&listener->event);
        }

    }

    (void)p;//To keep compiler happy

}

static registry_data_type_t get_data_type(const registry_path_t *path)
{
    const lwm2m_resource_meta_definition_t *resource_data;
    registry_data_type_t data_type;

    if (path->path_type < REGISTRY_PATH_RESOURCE) {
        return REGISTRY_DATA_LIST;
    }

    registry_status_t status = registry_meta_get_resource_definition(path->object_id, path->resource_id, &resource_data);

    if (REGISTRY_STATUS_OK != status) {
        return REGISTRY_DATA_INT;
    }

    if (path->path_type == REGISTRY_PATH_RESOURCE && resource_data->multiple) {
        return REGISTRY_DATA_LIST;
    }

    switch (resource_data->type) {
        //TODO: Check that types are in right places
        {
            case LWM2M_RESOURCE_TYPE_NONE:
            case LWM2M_RESOURCE_TYPE_INTEGER:
            case LWM2M_RESOURCE_TYPE_BOOLEAN:
            case LWM2M_RESOURCE_TYPE_TIME:
                data_type = REGISTRY_DATA_INT;
                break;
        }
#if MBED_CLIENT_ENABLE_FLOAT_VALUE
        case LWM2M_RESOURCE_TYPE_FLOAT:
            data_type = REGISTRY_DATA_FLOAT;
            break;
#endif
        case LWM2M_RESOURCE_TYPE_STRING:
            data_type = REGISTRY_DATA_STRING;
            break;

        case LWM2M_RESOURCE_TYPE_OPAQUE:
        case LWM2M_RESOURCE_TYPE_OBJLNK:
            data_type = REGISTRY_DATA_OPAQUE;
    }

    return data_type;
}

static uint8_t multiple_object_instances(uint16_t object_id, registry_status_t *status)
{
    const lwm2m_object_meta_definition_t *object_data;
    uint8_t multiple;

    if (REGISTRY_STATUS_OK != registry_meta_get_object_definition(object_id, &object_data)) {
        *status = REGISTRY_STATUS_NOT_FOUND;
        //TODO! ...todo what?
        return 0;
    }

    multiple = (uint8_t)object_data->multiple;

    if (status) {
        *status = REGISTRY_STATUS_OK;
    }

    return multiple;
}

static uint8_t multiple_resource_instances(uint16_t object_id, uint16_t resource_id, registry_status_t *status)
{
    const lwm2m_resource_meta_definition_t *resource_data;
    uint8_t multiple;

    if (REGISTRY_STATUS_OK != registry_meta_get_resource_definition(object_id, resource_id, &resource_data)) {
        if (status) {
            *status = REGISTRY_STATUS_NOT_FOUND;
        }
        return 0;
    }

    multiple = (uint8_t)resource_data->multiple;

    if (status) {
        *status = REGISTRY_STATUS_OK;
    }

    return multiple;
}

static void free_object_value(registry_data_type_t type, registry_object_value_t *value)
{
    tr_debug("free_object_value() type: %d", type);
    if (REGISTRY_DATA_OPAQUE == type || REGISTRY_DATA_STRING == type) {
        tr_debug("free_object_value() string or opaque");
        if (value->generic_value.free_data) {
            tr_debug("free_object_value() freeing %p", value->generic_value.data.opaque_data);
            lwm2m_free(value->generic_value.data.opaque_data);
        }
    }
}

static void read_obs_data(registry_observation_parameters_t *parameters, const observation_data_t *data)
{

    const uint8_t *obs_data;

    parameters->available = data->available;
    parameters->dirty = data->dirty;
    parameters->sent = data->sent;
    parameters->observed = data->observed;
    parameters->token_size = data->token_size;

    obs_data = data->obs_data;

#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
    if (data->available.pmin) {
        memcpy(&parameters->pmin, obs_data, sizeof(uint32_t));
        obs_data += sizeof(uint32_t);
    }
    if (data->available.pmax) {
        memcpy(&parameters->pmax, obs_data, sizeof(uint32_t));
        obs_data += sizeof(uint32_t);
    }
    if (data->available.gt) {
        memcpy(&parameters->gt, obs_data, sizeof(float));
        obs_data += sizeof(float);
    }
    if (data->available.lt) {
        memcpy(&parameters->lt, obs_data, sizeof(float));
        obs_data += sizeof(float);
    }
    if (data->available.st) {
        memcpy(&parameters->st, obs_data, sizeof(float));
        obs_data += sizeof(float);
    }
    if (data->available.time) {
        memcpy(&parameters->time, obs_data, sizeof(uint32_t));
        obs_data += sizeof(uint32_t);
    }
    if (data->available.previous_value) {
        memcpy(&parameters->previous_value, obs_data, sizeof(registry_observation_value_t));
        obs_data += sizeof(registry_observation_value_t);
    }
#endif //MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
    if (data->available.content_type) {
        memcpy(&parameters->content_type, obs_data, sizeof(sn_coap_content_format_e));
        obs_data += sizeof(sn_coap_content_format_e);
    }
    if (data->token_size) {
        memcpy(parameters->token, obs_data, data->token_size);
    }

}

static void write_obs_data(observation_data_t *data, const registry_observation_parameters_t *parameters)
{

    uint8_t *obs_data;

    data->available = parameters->available;
    data->dirty = parameters->dirty;
    data->sent = parameters->sent;
    data->observed = parameters->observed;
    data->token_size = parameters->token_size;

    obs_data = data->obs_data;

#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
    if (parameters->available.pmin) {
        memcpy(obs_data, &parameters->pmin, sizeof(uint32_t));
        obs_data += sizeof(uint32_t);
    }
    if (parameters->available.pmax) {
        memcpy(obs_data, &parameters->pmax, sizeof(uint32_t));
        obs_data += sizeof(uint32_t);
    }
    if (parameters->available.gt) {
        memcpy(obs_data, &parameters->gt, sizeof(float));
        obs_data += sizeof(float);
    }
    if (parameters->available.lt) {
        memcpy(obs_data, &parameters->lt, sizeof(float));
        obs_data += sizeof(float);
    }
    if (parameters->available.st) {
        memcpy(obs_data, &parameters->st, sizeof(float));
        obs_data += sizeof(float);
    }
    if (parameters->available.time) {
        memcpy(obs_data, &parameters->time, sizeof(uint32_t));
        obs_data += sizeof(uint32_t);
    }
    if (parameters->available.previous_value) {
        memcpy(obs_data, &parameters->previous_value, sizeof(registry_observation_value_t));
        obs_data += sizeof(registry_observation_value_t);
    }
#endif //MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
    if (parameters->available.content_type) {
        memcpy(obs_data, &parameters->content_type, sizeof(sn_coap_content_format_e));
        obs_data += sizeof(sn_coap_content_format_e);
    }
    if (parameters->token_size) {
        memcpy(obs_data, parameters->token, parameters->token_size);
    }

}

static uint8_t get_obs_data_size(const registry_observation_parameters_t *parameters)
{

    uint8_t size = 0;

#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
    if (parameters->available.pmin) {
        size += sizeof(uint32_t);
    }
    if (parameters->available.pmax) {
        size += sizeof(uint32_t);
    }
    if (parameters->available.gt) {
        size += sizeof(float);
    }
    if (parameters->available.lt) {
        size += sizeof(float);
    }
    if (parameters->available.st) {
        size += sizeof(float);
    }
    if (parameters->available.time) {
        size += sizeof(uint32_t);
    }
    if (parameters->available.previous_value) {
        size += sizeof(registry_observation_value_t);
    }
#endif //MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
    if (parameters->available.content_type) {
        size += sizeof(sn_coap_content_format_e);
    }
    size += parameters->token_size;

    return size;

}

static uint16_t get_id_from_path(const registry_path_t *path)
{
    switch (path->path_type)
    {
        case REGISTRY_PATH_OBJECT:
            return path->object_id;
        case REGISTRY_PATH_OBJECT_INSTANCE:
            return path->object_instance_id;
        case REGISTRY_PATH_RESOURCE:
            return path->resource_id;
        case REGISTRY_PATH_RESOURCE_INSTANCE:
            break;
    }
    return path->resource_instance_id;
}

static void set_id_to_path(registry_path_t *path, uint16_t id)
{
    switch (path->path_type)
    {
        case REGISTRY_PATH_OBJECT:
            path->object_id = id;
            break;
        case REGISTRY_PATH_OBJECT_INSTANCE:
            path->object_instance_id = id;
            break;
        case REGISTRY_PATH_RESOURCE:
            path->resource_id = id;
            break;
        case REGISTRY_PATH_RESOURCE_INSTANCE:
            path->resource_instance_id = id;
            break;
    }
}

static registry_object_t *get_object_from(const registry_path_t *path, sll_t *list)
{

    registry_object_t *object;
    void *p;
    uint16_t id = get_id_from_path(path);

    sll_foreach(*list, object, p) {
        if(object->id == id) {
            return object;
        }
    }

    (void)p;//To keep compiler happy

    return NULL;

}

// XXX: uh, a recursive function combined with list iteration and modification. A refactor might be needed here.
static registry_status_t remove_objects_from(registry_t *registry, registry_path_t *path, sll_t *list, uint8_t first_round)
{
    registry_object_t *object;
    registry_object_t *object_to_free;
    void *p;
    uint16_t id = get_id_from_path(path);

    sll_foreach(*list, object, p) {

        if(!first_round || object->id == id) {

            set_id_to_path(path, object->id);

            if (path->path_type < REGISTRY_PATH_RESOURCE_INSTANCE) {
                if (path->path_type == REGISTRY_PATH_RESOURCE && !multiple_resource_instances(path->object_id, path->resource_id, NULL)) {
                    //No list available for this resource.
                } else if (object->value.list) {
                    path->path_type++;
                    remove_objects_from(registry, path, &object->value.list, 0);
                    path->path_type--;
                }
            }
            print_registry_path("remove_objects_from() removing: ", path);
            object_to_free = object;
            sll_remove_current(*list, object, p);
            free_object_value(get_data_type(path), &object_to_free->value);
            lwm2m_free(object_to_free->observation_data);
            free_registry_object(object_to_free);
            send_events(registry, path, REGISTRY_EVENT_LISTEN_CREATE_REMOVE);

            if (first_round) {
                return REGISTRY_STATUS_OK;
            }

        }

    }

    return REGISTRY_STATUS_NOT_FOUND;

}

static registry_status_t remove_object_from(registry_t *registry, registry_path_t *path, sll_t *list)
{
    return remove_objects_from(registry, path, list, 1);
}

static void clear_object(registry_object_t *object)
{
    object->observation_data = NULL;
    object->value.int_value = 0;
#if MBED_CLIENT_ENABLE_FLOAT_VALUE
    object->value.float_value = 0.0f;
#endif
    object->value.generic_value.free_data = 0;
    object->value.generic_value.data.opaque_data = NULL;
    object->value.generic_value.data.string = NULL;
    object->registered = 0;
    object->callback = NULL;
    object->empty = 1;
    object->max_age = LWM2M_VALUE_CACHE_MAX_AGE;
#if MBED_CLIENT_ENABLE_AUTO_OBSERVATION
    object->auto_observable = false;
#endif
    object->publish_value = false;
}

static uint8_t valid_object(const registry_path_t *path, uint8_t *multi_resource)
{
    uint8_t multiple;
    registry_status_t status;

    *multi_resource = 0;

    multiple = multiple_object_instances(path->object_id, &status);

    if (REGISTRY_STATUS_OK != status) {
        return 0;
    }

    if (path->path_type > REGISTRY_PATH_OBJECT) {
        if (path->object_instance_id > 0 && !multiple) {
            return 0;
        }
    }

    if(path->path_type < REGISTRY_PATH_RESOURCE) {
        return 1;
    }

    multiple = multiple_resource_instances(path->object_id, path->resource_id, &status);

    if (REGISTRY_STATUS_OK != status) {
        return 0;
    }

    if (path->path_type == REGISTRY_PATH_RESOURCE_INSTANCE && !multiple) {
        return 0;
    }

    *multi_resource = multiple;

    return 1;

}

static registry_status_t registry_add_object(registry_t *registry, const registry_path_t *path, registry_object_t **object)
{

    registry_path_t current_path;
    registry_object_t *current_object;
    uint8_t multi_resource;
    sll_t *list = &registry->object_list;

    if (!registry || !path) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    if (!valid_object(path, &multi_resource)) {
        return REGISTRY_STATUS_NOT_FOUND;
    }

    current_path = *path;
    current_path.path_type = REGISTRY_PATH_OBJECT;

    for(;;) {

        current_object = get_object_from(&current_path, list);

        if (!current_object) {
            current_object = allocate_registry_object();
            if(!current_object) {
                return REGISTRY_STATUS_NO_MEMORY;
            }

            clear_object(current_object);
            current_object->id = get_id_from_path(&current_path);

            if(current_path.path_type < REGISTRY_PATH_RESOURCE ||
              (current_path.path_type == REGISTRY_PATH_RESOURCE && multi_resource) ) {
                sll_init(current_object->value.list);
            }
            sll_add(*list, current_object);
            send_events(registry, path, REGISTRY_EVENT_LISTEN_CREATE_REMOVE);

#ifdef MBED_CONF_MBED_CLIENT_ENABLE_CPP_API
            // XXX: this notification via callback is only needed when the C++ API is in use
            registry_callback_t callback;
            registry_path_t parent_path = *path;

            if (path->path_type > REGISTRY_PATH_OBJECT) {

                parent_path.path_type--;

                if (registry_get_callback(registry, &parent_path, &callback) == REGISTRY_STATUS_OK) {
                    callback(REGISTRY_CALLBACK_ITEM_ADDED, path, NULL, NULL, NOTIFICATION_STATUS_IGNORE, registry);
                }
            }
#endif
        }

        if(current_path.path_type == path->path_type) {
#if defined(MBED_CLIENT_SET_LIFETIME_AS_DEFAULT_MAX_AGE) && MBED_CLIENT_SET_LIFETIME_AS_DEFAULT_MAX_AGE
            registry_set_max_age(registry, path, MBED_CLOUD_CLIENT_LIFETIME);
#endif
            break;
        }

        current_path.path_type++;
        list = &current_object->value.list;

    }

    *object = current_object;
    return REGISTRY_STATUS_OK;

}

static registry_object_t *registry_get_object(const registry_t *registry, const registry_path_t *path)
{

    registry_path_t current_path;
    registry_object_t *current_object;
    sll_t *list;
    uint8_t multi_resource;

    if (!valid_object(path, &multi_resource)) {
        return NULL;
    }

    // XXX: this list implementation sucks, as it can not handle a const list.
    // A proper type safe implementation needs to be done.
    list = (sll_t *)&registry->object_list;

    current_path = *path;
    current_path.path_type = REGISTRY_PATH_OBJECT;

    for (;;) {

        current_object = get_object_from(&current_path, list);

        if (!current_object) {
            return NULL;
        }

        if (current_path.path_type == path->path_type) {
            break;
        }

        if (!current_object->value.list) {
            return NULL;
        }

        current_path.path_type++;
        list = &current_object->value.list;

    }

    return current_object;

}

registry_status_t registry_remove_object(registry_t *registry, const registry_path_t *path, registry_removal_type_t removal_type)
{
    registry_path_t current_path;
    registry_object_t *current_object;
    sll_t *list;

    if (!registry || !path) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    print_registry_path("registry_remove_object() path: ", path);

    list = &registry->object_list;

    current_path = *path;
    current_path.path_type = REGISTRY_PATH_OBJECT;

    for (;;) {

        if (current_path.path_type == path->path_type) {
            registry_status_t status;
#ifdef MBED_CONF_MBED_CLIENT_ENABLE_CPP_API
            // XXX: this notification via callback is only needed when the C++ API is in use
            registry_callback_t callback = NULL;
            registry_path_t parent_path = *path;

            if (path->path_type > REGISTRY_PATH_OBJECT) {

                parent_path.path_type--;

                if (registry_get_callback(registry, &parent_path, &callback) != REGISTRY_STATUS_OK) {
                    tr_debug("registry_remove_object() could not find callback function");
                }
            }
#endif

            status = remove_object_from(registry, &current_path, list);

#ifdef MBED_CONF_MBED_CLIENT_ENABLE_CPP_API
            if ((removal_type != REGISTRY_REMOVE_SKIP_CALLBACK) && callback && status == REGISTRY_STATUS_OK) {
                callback(removal_type == REGISTRY_REMOVE_FOR_REPLACEMENT ? REGISTRY_CALLBACK_ITEM_REPLACED : REGISTRY_CALLBACK_ITEM_REMOVED,
                         &parent_path,
                         NULL,
                         NULL,
                         NOTIFICATION_STATUS_IGNORE,
                         registry);
            }
#endif
            return status;
        }

        current_object = get_object_from(&current_path, list);

        if (!current_object || !current_object->value.list) {
            break; //Not found.
        }

        current_path.path_type++;
        list = &current_object->value.list;

    }

    return REGISTRY_STATUS_NOT_FOUND;

}

static void registry_remove_all_objects(registry_t *registry)
{
    registry_path_t path;

    if (!registry) {
        return;
    }

    registry_set_path(&path, 0, 0, 0, 0, REGISTRY_PATH_OBJECT);

    remove_objects_from(registry, &path, &registry->object_list, 0);

}

static registry_status_t registry_get_object_data(const registry_t *registry, const registry_path_t *path, registry_object_value_t *value, registry_data_type_t data_type)
{

    registry_object_t *object;

    if (!registry || !path) {
        tr_debug("registry_get_object_data() null arguments");
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    if (path->path_type < REGISTRY_PATH_RESOURCE) {
        return REGISTRY_STATUS_NO_DATA;
    }

    if (path->path_type == REGISTRY_PATH_RESOURCE && multiple_resource_instances(path->object_id, path->resource_id, NULL)) {
        return REGISTRY_STATUS_NO_DATA;
    }

    if ((data_type != REGISTRY_DATA_EMPTY) && (data_type != get_data_type(path)))
    {
        tr_debug("registry_get_object_data() wrong data type requested");
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    object = registry_get_object(registry, path);

    if (!object) {
        return REGISTRY_STATUS_NOT_FOUND;
    }

    *value = object->value;

    if (object->empty) {
        return REGISTRY_STATUS_NO_DATA;
    } else {
        return REGISTRY_STATUS_OK;
    }

}

registry_status_t registry_get_value_int(const registry_t *registry, const registry_path_t *path, int64_t *value)
{
    registry_object_value_t int_value;
    registry_status_t status;

    if (!value) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    status = registry_get_object_data(registry, path, &int_value, REGISTRY_DATA_INT);

    *value = int_value.int_value;

    return status;
}
#if MBED_CLIENT_ENABLE_FLOAT_VALUE
registry_status_t registry_get_value_float(const registry_t *registry, const registry_path_t *path, float *value)
{
    registry_object_value_t float_value;
    registry_status_t status;

    if (!value) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    status = registry_get_object_data(registry, path, &float_value, REGISTRY_DATA_FLOAT);

    *value = float_value.float_value;

    return status;
}
#endif

registry_status_t registry_get_value_boolean(const registry_t *registry, const registry_path_t *path, bool *value)
{
    registry_object_value_t int_value;
    registry_status_t status;

    if (!value) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    status = registry_get_object_data(registry, path, &int_value, REGISTRY_DATA_INT);

    *value = int_value.int_value;

    return status;
}

registry_status_t registry_get_value_time(const registry_t *registry, const registry_path_t *path, int64_t *value)
{
    return registry_get_value_int(registry, path, value);
}

registry_status_t registry_get_value_string(const registry_t *registry, const registry_path_t *path, const char **value)
{
    registry_object_value_t string_value;
    registry_status_t status;

    if (!value) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    status = registry_get_object_data(registry, path, &string_value, REGISTRY_DATA_STRING);

    *value = string_value.generic_value.data.string;

    return status;
}

registry_status_t registry_get_value_opaque(const registry_t *registry, const registry_path_t *path, registry_data_opaque_t **value)
{
    registry_object_value_t opaque_value;
    registry_status_t status;

    if (!value) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    status = registry_get_object_data(registry, path, &opaque_value, REGISTRY_DATA_OPAQUE);

    *value = opaque_value.generic_value.data.opaque_data;

    return status;
}

registry_status_t registry_get_value_empty(const registry_t *registry, const registry_path_t *path, bool *empty)
{
    registry_object_value_t value;
    registry_status_t status;

    if (!empty) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    status = registry_get_object_data(registry, path, &value, REGISTRY_DATA_EMPTY);

    *empty = value.empty_value;

    return status;
}

registry_status_t registry_is_value_empty(const registry_t *registry, const registry_path_t *path, bool *empty)
{
    registry_object_t *object;

    if (!empty || !registry || !path) {
        tr_error("registry_get_object_data() null arguments");
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    if (path->path_type < REGISTRY_PATH_RESOURCE) {
        return REGISTRY_STATUS_NO_DATA;
    }

    if (path->path_type == REGISTRY_PATH_RESOURCE && multiple_resource_instances(path->object_id, path->resource_id, NULL)) {
        return REGISTRY_STATUS_NO_DATA;
    }

    object = registry_get_object(registry, path);

    if (!object) {
        return REGISTRY_STATUS_NO_DATA;
    }

    *empty = object->empty;

    return REGISTRY_STATUS_OK;
}

static registry_status_t registry_set_object_data(registry_t *registry, const registry_path_t *path, registry_object_value_t value, registry_data_type_t data_type)
{

    print_registry_path("registry_set_object_data() path: ", path);

    registry_object_t *object;

    if (!registry || !path) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    if (path->path_type < REGISTRY_PATH_RESOURCE) {
        return REGISTRY_STATUS_NO_DATA;
    }

    if (path->path_type == REGISTRY_PATH_RESOURCE && multiple_resource_instances(path->object_id, path->resource_id, NULL)) {
        return REGISTRY_STATUS_NO_DATA;
    }

    // special handling for empty value
    if ((data_type != REGISTRY_DATA_EMPTY) && (data_type != get_data_type(path)))
    {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    object = registry_get_object(registry, path);

    if (!object) {
        registry_status_t status;
        status = registry_add_object(registry, path, &object);
        if (status != REGISTRY_STATUS_OK) {
            return status;
        }
    }

    free_object_value(data_type, &object->value);

    // special handling for empty value
    if (data_type == REGISTRY_DATA_EMPTY) {
        object->empty = 1;
    } else {
        object->empty = 0;
        object->value = value;

        notifier_set_dirty(registry, path);
    }

    send_events(registry, path, REGISTRY_EVENT_LISTEN_VALUE_CHANGES);

    return REGISTRY_STATUS_OK;
}


registry_status_t registry_set_value_int(registry_t *registry, const registry_path_t *path, int64_t value)
{
    registry_object_value_t int_value;
    int_value.int_value = value;
    return registry_set_object_data(registry, path, int_value, REGISTRY_DATA_INT);
}

#if MBED_CLIENT_ENABLE_FLOAT_VALUE
registry_status_t registry_set_value_float(registry_t *registry, const registry_path_t *path, float value)
{
    registry_object_value_t float_value;
    float_value.float_value = value;
    return registry_set_object_data(registry, path, float_value, REGISTRY_DATA_FLOAT);
}
#endif

registry_status_t registry_set_value_boolean(registry_t *registry, const registry_path_t *path, bool value)
{
    return registry_set_value_int(registry, path, (int64_t) value);
}

registry_status_t registry_set_value_time(registry_t *registry, const registry_path_t *path, int64_t value)
{
    return registry_set_value_int(registry, path, value);
}

registry_status_t registry_set_value_string(registry_t *registry, const registry_path_t *path, const char *value, bool free_on_remove)
{

    print_registry_path("registry_set_value_string() path: ", path);
    tr_debug("value: %s", value);

    registry_object_value_t string_value;
    string_value.generic_value.free_data = free_on_remove;
    string_value.generic_value.data.string = value;
    return registry_set_object_data(registry, path, string_value, REGISTRY_DATA_STRING);
}

registry_status_t registry_set_value_string_copy(registry_t *registry, const registry_path_t *path, const uint8_t *value, size_t length)
{
    registry_status_t status = REGISTRY_STATUS_NO_MEMORY;

    // create a zero terminated string copy of the data
    char *value_copy = lwm2m_alloc_string_copy(value, length);

    if (value_copy) {

        status = registry_set_value_string(registry, path, value_copy, true);
        if (status != REGISTRY_STATUS_OK) {
            lwm2m_free(value_copy);
        }
    }
    return status;
}

registry_status_t registry_set_value_opaque(registry_t *registry, const registry_path_t *path, registry_data_opaque_t *value, bool free_on_remove)
{
    registry_object_value_t opaque_value;
    opaque_value.generic_value.free_data = free_on_remove;
    opaque_value.generic_value.data.opaque_data = value;
    return registry_set_object_data(registry, path, opaque_value, REGISTRY_DATA_OPAQUE);
}

registry_status_t registry_set_value_opaque_copy(registry_t *registry, const registry_path_t *path, const uint8_t *value, size_t length)
{
    registry_data_opaque_t *value_copy;
    registry_status_t status = REGISTRY_STATUS_NO_MEMORY;

// Store value directly into kvstore
#ifdef PROTOMAN_OFFLOAD_TLS
    if (path->object_id == 0 && path->object_instance_id == 0) {
        if (path->resource_id == 3) {
            if (!storage_set_parameter(LWM2M_DEVICE_CERTIFICATE, value, length)) {
                tr_error("set_connector_credentials() LWM2M_DEVICE_CERTIFICATE failed");
                return false;
            }
        } else if (path->resource_id == 4) {
            if (!storage_set_parameter(LWM2M_SERVER_ROOT_CA_CERTIFICATE, value, length)) {
                tr_error("set_connector_credentials() LWM2M_SERVER_ROOT_CA_CERTIFICATE failed");
                return false;
            }

        } else if (path->resource_id == 5) {
            if (!storage_set_parameter(LWM2M_DEVICE_PRIVATE_KEY, value, length)) {
                tr_error("set_connector_credentials() LWM2M_DEVICE_PRIVATE_KEY failed");
                return false;
            }

        }

        return REGISTRY_STATUS_OK;
    }
#endif //PROTOMAN_OFFLOAD_TLS

    // create a zero terminated string copy of the data
    value_copy = lwm2m_alloc(sizeof(registry_data_opaque_t) + length);

    if (value_copy) {
        value_copy->size = length;
        memcpy(value_copy->data, value, length);
        status = registry_set_value_opaque(registry, path, value_copy, true);
        if (status != REGISTRY_STATUS_OK) {
            lwm2m_free(value_copy);
        }
    }
    return status;
}

registry_status_t registry_set_value_empty(registry_t *registry, const registry_path_t *path, bool empty)
{
    registry_object_value_t value;
    value.empty_value = empty;
    return registry_set_object_data(registry, path, value, REGISTRY_DATA_EMPTY);
}

registry_status_t registry_set_max_age(registry_t *registry, const registry_path_t *path, uint32_t max_age) {

    registry_object_t *object;

    if (!registry || !path) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    object = registry_get_object(registry, path);

    if (!object) {
        registry_status_t status;
        status = registry_add_object(registry, path, &object);
        if (status != REGISTRY_STATUS_OK) {
            return status;
        }
    }

    object->max_age = max_age;

    return REGISTRY_STATUS_OK;
}

registry_status_t registry_get_max_age(registry_t *registry, const registry_path_t *path, uint32_t *max_age) {

    registry_object_t *object;

    if (!registry || !path || !max_age) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    object = registry_get_object(registry, path);

    if (!object) {
        return REGISTRY_STATUS_NOT_FOUND;
    }

    *max_age = object->max_age;

    return REGISTRY_STATUS_OK;
}

registry_status_t registry_set_callback(registry_t *registry, const registry_path_t *path, registry_callback_t callback)
{
    registry_object_t *object;

    if (!registry || !path) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    if (path->path_type == REGISTRY_PATH_RESOURCE && multiple_resource_instances(path->object_id, path->resource_id, NULL)) {
        return REGISTRY_STATUS_NO_DATA;
    }

    object = registry_get_object(registry, path);

    if (!object) {
        registry_status_t status;
        status = registry_add_object(registry, path, &object);
        if (status != REGISTRY_STATUS_OK) {
            return status;
        }
    }

    object->callback = callback;

    return REGISTRY_STATUS_OK;
}

registry_status_t registry_get_callback(const registry_t *registry, const registry_path_t *path, registry_callback_t* callback)
{
    registry_object_t *object;

    if (!registry || !path) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }


    if (path->path_type == REGISTRY_PATH_RESOURCE && multiple_resource_instances(path->object_id, path->resource_id, NULL)) {
        return REGISTRY_STATUS_NO_DATA;
    }

    object = registry_get_object(registry, path);

    if (!object || !object->callback) {
        return REGISTRY_STATUS_NOT_FOUND;
    }

    *callback = object->callback;

    return REGISTRY_STATUS_OK;

}

registry_status_t registry_get_observation_parameters(const registry_t *registry, const registry_path_t *path, registry_observation_parameters_t *parameters)
{
    registry_object_t *object;

    if (!registry || !path || !parameters) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    object = registry_get_object(registry, path);

    if (!object) {
        return REGISTRY_STATUS_NOT_FOUND;
    }

    if (!object->observation_data) {
        return REGISTRY_STATUS_NO_DATA;
    }

    read_obs_data(parameters, object->observation_data);

    return REGISTRY_STATUS_OK;

}

registry_status_t registry_set_observation_parameters(registry_t *registry, const registry_path_t *path, const registry_observation_parameters_t *parameters)
{
    registry_object_t *object;
    observation_data_t *observation_data;
    uint8_t obs_data_size;

    if (!registry || !path || !parameters) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    object = registry_get_object(registry, path);

    if (!object) {
        return REGISTRY_STATUS_NOT_FOUND;
    }

    obs_data_size = get_obs_data_size(parameters);

    observation_data = lwm2m_alloc(sizeof(observation_data_t) + obs_data_size);

    if (!observation_data) {
        return REGISTRY_STATUS_NO_MEMORY;
    }

    write_obs_data(observation_data, parameters);
    lwm2m_free(object->observation_data);
    object->observation_data = observation_data;

    return REGISTRY_STATUS_OK;
}

static registry_status_t read_object_data(registry_listing_t *listing, registry_object_t *object,
                                          registry_object_value_t *value, registry_observation_parameters_t *parameters)
{

    if (object) {

        if (( value && listing->path.path_type == REGISTRY_PATH_RESOURCE_INSTANCE ) ||
            ( value && listing->path.path_type == REGISTRY_PATH_RESOURCE &&
              !multiple_resource_instances(listing->path.object_id, listing->path.resource_id, NULL) ) ) {

            *value = object->value;
            listing->value_set = 1;

        } else {

            listing->value_set = 0;

        }

        if (parameters && object->observation_data) {

            read_obs_data(parameters, object->observation_data);
            listing->parameters_set = 1;

        } else {

            listing->parameters_set = 0;

        }

        listing->registered = object->registered;
        if (listing->set_registered) {
            object->registered = 1;
        }

        return REGISTRY_STATUS_OK;

    }

    return REGISTRY_STATUS_NO_DATA;

}

static void read_nested_list(registry_listing_t *listing, registry_object_t *object, uint8_t level)
{

    if (object && level < REGISTRY_PATH_RESOURCE_INSTANCE) {

        switch (level) {

            case REGISTRY_PATH_OBJECT:
                listing->object_instance = (void*)&object->value.list;
                break;
            case REGISTRY_PATH_OBJECT_INSTANCE:
                listing->resource = (void*)&object->value.list;
                break;
            case REGISTRY_PATH_RESOURCE:
                if (multiple_resource_instances(listing->path.object_id, listing->path.resource_id, NULL)) {
                    listing->resource_instance = (void*)&object->value.list;
                }
                break;

        }

    }

}

static registry_object_t **listing_next(registry_listing_t *listing)
{

    if (listing->resource_instance) {
        listing->path.path_type = REGISTRY_PATH_RESOURCE_INSTANCE;
        return &listing->resource_instance;
    }

    if (listing->resource) {
        listing->path.path_type = REGISTRY_PATH_RESOURCE;
        return &listing->resource;
    }

    if (listing->object_instance) {
        listing->path.path_type = REGISTRY_PATH_OBJECT_INSTANCE;
        return &listing->object_instance;
    }

    if (listing->object) {
        listing->path.path_type = REGISTRY_PATH_OBJECT;
        return &listing->object;
    }

    return NULL;

}

static registry_object_t **listing_next_reverse(registry_listing_t *listing)
{
    if (listing->object) {
        listing->path.path_type = REGISTRY_PATH_OBJECT;
        return &listing->object;
    }

    if (listing->object_instance) {
        listing->path.path_type = REGISTRY_PATH_OBJECT_INSTANCE;
        return &listing->object_instance;
    }

    if (listing->resource) {
        listing->path.path_type = REGISTRY_PATH_RESOURCE;
        return &listing->resource;
    }

    if (listing->resource_instance) {
        listing->path.path_type = REGISTRY_PATH_RESOURCE_INSTANCE;
        return &listing->resource_instance;
    }

    return NULL;

}


registry_status_t registry_get_objects(const registry_t *registry, registry_listing_t *listing, registry_object_value_t *value, registry_observation_parameters_t *parameters)
{

    void *p;
    registry_object_t **object;

    if (!registry || !listing) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    /* First call requires special treatment: are we trying to read all registry contents or just parts of it? */
    if ((listing->listing_type != REGISTRY_LISTING_IN_PROGRESS) &&
        (listing->listing_type != REGISTRY_LISTING_DIRECTORY_IN_PROGRESS)) {

        registry_object_t *object;

        listing->object = NULL;
        listing->object_instance = NULL;
        listing->resource = NULL;
        listing->resource_instance = NULL;

        if (listing->listing_type == REGISTRY_LISTING_ALL) {

            //Get first object

            listing->object = (void*)&registry->object_list;
            sll_get_next(listing->object, p);

            if (!listing->object) {
                return REGISTRY_STATUS_NO_DATA;
            }

            listing->path.object_id = listing->object->id;
            listing->path.path_type = REGISTRY_PATH_OBJECT;

            listing->listing_type = REGISTRY_LISTING_IN_PROGRESS;

            read_nested_list(listing, listing->object, REGISTRY_PATH_OBJECT);

            return read_object_data(listing, listing->object, value, parameters);

        } else if (listing->listing_type == REGISTRY_LISTING_DIRECTORY) {

            object = registry_get_object(registry, &listing->path);

            if (!object) {
                return REGISTRY_STATUS_NOT_FOUND;
            }

            listing->listing_type = REGISTRY_LISTING_DIRECTORY_IN_PROGRESS;

            read_nested_list(listing, object, listing->path.path_type);

            return read_object_data(listing, object, value, parameters);

        }

        //Find first resource

        object = registry_get_object(registry, &listing->path);

        if (!object) {
            return REGISTRY_STATUS_NOT_FOUND;
        }

        read_nested_list(listing, object, listing->path.path_type);

        listing->listing_type = REGISTRY_LISTING_IN_PROGRESS;

        return read_object_data(listing, object, value, parameters);

    }

    if (listing->listing_type == REGISTRY_LISTING_IN_PROGRESS) {
        //Go to next resource.
        while (NULL != (object = listing_next(listing))) {

            sll_get_next(*object, p);

            if (*object) {
                set_id_to_path(&listing->path, (*object)->id);

                read_nested_list(listing, *object, listing->path.path_type);

                return read_object_data(listing, *object, value, parameters);

            }

        }
    } else if (listing->listing_type == REGISTRY_LISTING_DIRECTORY_IN_PROGRESS) {

        /* pick the next sibling */

        while (NULL != (object = listing_next_reverse(listing))) {
            sll_get_next(*object, p);

            if (*object) {
                set_id_to_path(&listing->path, (*object)->id);

                return read_object_data(listing, *object, value, parameters);

            }
        }
    }

    (void)p;//To keep compiler happy

    return REGISTRY_STATUS_NO_DATA;

}

uint32_t registry_object_count_resources(const registry_t *registry, const registry_path_t *path) {
    registry_listing_t listing;
    listing.set_registered = 0;
    listing.path = *path;
    listing.listing_type = REGISTRY_LISTING_RECURSIVE;
    uint32_t count = 0;
    while (REGISTRY_STATUS_OK == registry_get_objects(registry, &listing, 0, 0)) {
        if (listing.path.path_type == REGISTRY_PATH_RESOURCE) {
            count++;
        }
    }
    return count;
}
registry_status_t registry_object_has_sibling(const registry_t *registry, const registry_path_t *path, bool *result) {

    registry_status_t status = REGISTRY_STATUS_OK;
    registry_listing_t listing;
    registry_object_value_t value;
    registry_observation_parameters_t parameters;

    print_registry_path("registry_object_has_sibling() path: ", path);

    if (!result) {
        tr_debug("registry_object_has_sibling() invalid argument");
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    listing.path = *path;
    listing.listing_type = REGISTRY_LISTING_DIRECTORY;
    listing.set_registered = 0;
    /* take one step back to see if there are any siblings under the parent object */
    listing.path.path_type--;

    while (REGISTRY_STATUS_OK == (status = registry_get_objects(registry, &listing, &value, &parameters))) {

        if ((path->path_type == REGISTRY_PATH_OBJECT_INSTANCE) &&
            (listing.path.path_type == REGISTRY_PATH_OBJECT_INSTANCE)) {

            if (path->object_instance_id != listing.path.object_instance_id) {

                *result = true;
                return REGISTRY_STATUS_OK;
            }

        } else if ((path->path_type == REGISTRY_PATH_RESOURCE_INSTANCE) &&
                   (listing.path.path_type == REGISTRY_PATH_RESOURCE_INSTANCE)) {

            if (path->resource_instance_id != listing.path.resource_instance_id) {

                *result = true;
                return REGISTRY_STATUS_OK;
            }
        }
    }

    /* let the caller know if we did not find a sibling for a non-error reason */
    if (status == REGISTRY_STATUS_NO_DATA) {
        *result = false;
        status = REGISTRY_STATUS_OK;
    }
    return status;
}

#ifdef MBED_CLIENT_ENABLE_DYNAMIC_CREATION
registry_status_t registry_add_instance(registry_t *registry, registry_path_t *path) {

    registry_object_t* new_obj;
#ifdef MBED_CONF_MBED_CLIENT_ENABLE_CPP_API
    registry_path_t parent_path = *path;
#endif

    // If the path points to a specific object instance or resource instance,
    // we honor that request: it will be created if necessary.
    // Existing instances will NOT be overwritten.

    if (path->path_type == REGISTRY_PATH_OBJECT || path->path_type == REGISTRY_PATH_RESOURCE) {

        // start looking for free instance id's from the beginning
        if (path->path_type == REGISTRY_PATH_OBJECT) {
            path->object_instance_id = 0;
        } else {
            path->resource_instance_id = 0;
        }

        path->path_type++;

        // this may be a bit time-consuming, but at least it ensures that the new instance path has a unique id
        while (REGISTRY_STATUS_OK == registry_path_exists(registry, path)) {
            if (path->path_type == REGISTRY_PATH_OBJECT_INSTANCE) {
                if (path->object_instance_id++ >= UINT16_MAX) {
                    return REGISTRY_STATUS_NOT_FOUND;
                }
            } else {
                if (path->resource_instance_id++ >= UINT16_MAX) {
                    return REGISTRY_STATUS_NOT_FOUND;
                }
            }
        }
    }

    print_registry_path("registry_add_instance() creating new instance path: ", path);

    registry_status_t status = registry_add_object(registry, path, &new_obj);

#ifdef MBED_CONF_MBED_CLIENT_ENABLE_CPP_API
    if (REGISTRY_STATUS_OK == status) {

        // XXX: this notification via callback is only needed when the C++ API is in use
        if (path->path_type >= parent_path.path_type) {

            registry_callback_t callback;
            print_registry_path("registry_add_instance() telling cpp wrapper about addition: ", path);

            if (registry_get_callback(registry, &parent_path, &callback) == REGISTRY_STATUS_OK) {
                tr_debug("registry_add_instance() calling item added callback");
                callback(REGISTRY_CALLBACK_ITEM_ADDED, path, NULL, NULL, NOTIFICATION_STATUS_INIT, registry);
            }
        }
    }
#endif
    return status;
}
#endif //MBED_CLIENT_ENABLE_DYNAMIC_CREATION

registry_status_t registry_listen_events(registry_t *registry, void *data_ptr, registry_event_listen_mode_t mode, int8_t handler_id)
{

    registry_event_listener_t *entry;

    if (!registry) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    entry = lwm2m_alloc(sizeof(registry_event_listener_t));

    if (!entry) {
        return REGISTRY_STATUS_NO_MEMORY;
    }

    entry->mode = mode;
    entry->event.data.receiver = handler_id;
    entry->event.data.sender = 0;
    entry->event.data.data_ptr = data_ptr;
    entry->event.data.event_data = REGISTRY_PREALLOCATED_EVENT_READY;
    entry->event.data.event_id = REGISTRY_EVENT_ID;
    entry->event.data.priority = ARM_LIB_LOW_PRIORITY_EVENT;

    sll_add(registry->event_list, entry);

    return REGISTRY_STATUS_OK;

}

registry_status_t registry_event_processed(registry_t *registry, arm_event_s *event)
{
    if (!registry || ! event) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    event->event_data = REGISTRY_PREALLOCATED_EVENT_READY;

    return REGISTRY_STATUS_OK;

}


registry_status_t registry_listen_events_stop(registry_t *registry, void *data_ptr, registry_event_listen_mode_t mode, int8_t handler_id)
{

    registry_event_listener_t *entry;
    registry_event_listener_t *entry_to_remove;
    void *p;

    if (!registry) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    sll_foreach(registry->event_list, entry, p) {

        if (entry->event.data.receiver == handler_id && mode == entry->mode && data_ptr == entry->event.data.data_ptr) {

            eventOS_cancel(&entry->event);
            entry_to_remove = entry;
            sll_remove_current(registry->event_list, entry, p);
            lwm2m_free(entry_to_remove);
            return REGISTRY_STATUS_OK;

        }

    }

    return REGISTRY_STATUS_NOT_FOUND;

}

void registry_set_path(registry_path_t *path, const uint16_t object, const uint16_t object_instance, const uint16_t resource, const uint16_t resource_instance, const uint8_t type)
{
    path->object_id = object;
    path->object_instance_id = object_instance;
    path->resource_id = resource;
    path->resource_instance_id = resource_instance;
    path->path_type = type;
}

bool registry_compare_path(const registry_path_t *path, const registry_path_t *path2)
{

    // Only check the parts of the path that are required to match.

    if (path->path_type != path2->path_type) {
        return false;
    }

    if (path->object_id != path2->object_id) {
        return false;
    }

    if (path->path_type == REGISTRY_PATH_OBJECT) {
        return true;
    }

    if (path->object_instance_id != path2->object_instance_id) {
        return false;
    }

    if (path->path_type == REGISTRY_PATH_OBJECT_INSTANCE) {
        return true;
    }

    if (path->resource_id != path2->resource_id) {
        return false;
    }

    if (path->path_type == REGISTRY_PATH_RESOURCE) {
        return true;
    }

    if (path->resource_instance_id != path2->resource_instance_id) {
        return false;
    }

    return true;

}

registry_status_t registry_set_auto_observable_parameter(registry_t *registry, const registry_path_t *path, bool auto_observable)
{
#if MBED_CLIENT_ENABLE_AUTO_OBSERVATION
    registry_object_t *object;

    if (!registry || !path) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    object = registry_get_object(registry, path);

    if (!object) {
        registry_status_t status;
        status = registry_add_object(registry, path, &object);
        if (status != REGISTRY_STATUS_OK) {
            return status;
        }
    }

    object->auto_observable = auto_observable;

    if (!auto_observable) {
        return REGISTRY_STATUS_OK;
    }

    // auto obs token range is between 1 -1023
    registry->auto_obs_token++;
    if (registry->auto_obs_token > AUTO_OBS_TOKEN_MAX) {
        registry->auto_obs_token = 1;
    }

    uint8_t token[sizeof(uint16_t)];
    common_write_16_bit(registry->auto_obs_token, token);

    notifier_start_observation(registry->notifier, path, token, sizeof(uint16_t), COAP_CT_NONE);

    return REGISTRY_STATUS_OK;
#else
    (void) registry;
    (void) path;
    (void) auto_observable;

    tr_warn("registry_set_auto_observable_parameter() - feature disabled");

    return REGISTRY_STATUS_OK;
#endif // MBED_CLIENT_ENABLE_AUTO_OBSERVATION
}

bool registry_is_auto_observable(registry_t *registry, const registry_path_t *path)
{
#if MBED_CLIENT_ENABLE_AUTO_OBSERVATION
    registry_object_t *object;
    if (!registry || !path) {
        return false;
    }

    object = registry_get_object(registry, path);

    if (!object) {
        return false;
    }
    return object->auto_observable;
#else
    (void) registry;
    (void) path;

    tr_warn("registry_is_auto_observable() - feature disabled");

    return false;
#endif // MBED_CLIENT_ENABLE_AUTO_OBSERVATION
}

registry_status_t registry_path_exists(registry_t *registry, registry_path_t *path)
{
    registry_object_t *object;
    if (!registry || !path) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    object = registry_get_object(registry, path);
    if (!object) {
        print_registry_path("registry_path_exists() does not exist: ", path);
        return REGISTRY_STATUS_NOT_FOUND;
    }

    print_registry_path("registry_path_exists() exists: ", path);
    return REGISTRY_STATUS_OK;
}

registry_status_t registry_set_resource_value_to_reg_msg(registry_t *registry, const registry_path_t *path, bool publish)
{
#if MBED_CLIENT_ENABLE_PUBLISH_RESOURCE_VALUE_IN_REG_MSG

    registry_object_t *object;

    if (!registry || !path) {
        return REGISTRY_STATUS_INVALID_INPUT;
    }

    // Only resource values are allowed in registration message
    const lwm2m_resource_meta_definition_t *static_data;
    if (path->path_type == REGISTRY_PATH_RESOURCE &&
        REGISTRY_STATUS_OK == registry_meta_get_resource_definition(path->object_id,
                                                                    path->resource_id,
                                                                    &static_data)) {

        // seems pretty wrong as also time type should be able register
        // and asserting for these seems like unnecessary as other interfaces just fail for invalid input
        /*
        assert (static_data->type == LWM2M_RESOURCE_TYPE_STRING ||
            static_data->type == LWM2M_RESOURCE_TYPE_INTEGER ||
#if MBED_CLIENT_ENABLE_FLOAT_VALUE
            static_data->type == LWM2M_RESOURCE_TYPE_FLOAT ||
#endif
            static_data->type == LWM2M_RESOURCE_TYPE_BOOLEAN ||
            static_data->type == LWM2M_RESOURCE_TYPE_OPAQUE ||
            static_data->type == LWM2M_RESOURCE_TYPE_TIME);
            */


        object = registry_get_object(registry, path);
        if (!object) {
            return REGISTRY_STATUS_NOT_FOUND;
        }
        object->publish_value = publish;
        return REGISTRY_STATUS_OK;
    }

    return REGISTRY_STATUS_INVALID_INPUT;

#else

    (void) registry;
    (void) path;
    (void) publish;

    tr_warn("registry_set_resource_value_to_reg_msg() - feature disabled");

    return REGISTRY_STATUS_OK;

#endif // MBED_CLIENT_ENABLE_PUBLISH_RESOURCE_VALUE_IN_REG_MSG
}

bool registry_publish_resource_value_in_reg_msg(registry_t *registry, const registry_path_t *path)
{
#if MBED_CLIENT_ENABLE_PUBLISH_RESOURCE_VALUE_IN_REG_MSG

    registry_object_t *object;
    if (!registry || !path) {
        return false;
    }

    object = registry_get_object(registry, path);

    if (!object) {
        return false;
    }
    return object->publish_value;

#else

    (void) registry;
    (void) path;

    tr_warn("registry_publish_resource_value_in_reg_msg() - feature disabled");

    return false;

#endif // MBED_CLIENT_ENABLE_PUBLISH_RESOURCE_VALUE_IN_REG_MSG
}
