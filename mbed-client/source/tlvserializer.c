/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
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

#include "tlvserializer.h"
#include "lwm2m_heap.h"
#include "lwm2m_registry.h"
#include "lwm2m_registry_meta.h"
#include "lwm2m_constants.h"
#include "common_functions.h"
#include "mbed-trace/mbed_trace.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>


#define MAX_TLV_LENGTH_SIZE 3
#define MAX_TLV_ID_SIZE 2
#define TLV_TYPE_SIZE 1

// -9223372036854775808 - +9223372036854775807
// max length of int64_t string is 20 bytes + nil
#define REGISTRY_INT64_STRING_MAX_LEN 21
#define REGISTRY_INT8_STRING_MAX_LEN 4

#if MBED_CLIENT_ENABLE_FLOAT_VALUE
// (space needed for -3.402823 × 10^38) + (magic decimal 6 digits added as no precision is added to "%f") + trailing zero
#define REGISTRY_FLOAT_STRING_MAX_LEN 48
#endif

// (space needed for -1.79769313486231571e+308 or 2.22507385850720138e-308 ) + (magic decimal 6 digits added as no precision is added to %e) + (trailing zero)
#define REGISTRY_DOUBLE_SCIENTIFIC_STRING_MAX_LEN 34

#define TRACE_GROUP "tlvs"


static registry_tlv_serialize_status_t registry_serialize_append_to_buffer(const uint8_t *value, int value_len, uint8_t **data, uint32_t *size);
static bool is_dirty_object_instance(const registry_t* registry, const registry_listing_t* listing, const registry_observation_parameters_t *parameters);

/*
 * \brief Serializes resources under the given path
 *
 * \param registry Registry instance
 * \param listing Registry iterator struct
 * \param data Pointer to allocated data will be stored through this pointer
 * \param size Size of allocated data will be stored through this pointer
 * \param format Which format to use (text/plain or TLV)
 *
 * \return REGISTRY_TLV_SERIALIZE_STATUS_OK if everything went okay
 *
 */
static registry_tlv_serialize_status_t registry_serialize_resources(const registry_t* registry,
                                                             registry_listing_t* listing,
                                                             registry_status_t *listing_status,
                                                             bool every_resource,
                                                             uint8_t** data, uint32_t *size,
                                                             registry_serialization_format_t format,
                                                             const bool dirty_only,
                                                             registry_object_value_t *value,
                                                             registry_observation_parameters_t *parameters);

/*
 * \brief Serializes registry data (object) under the given path
 *
 * \param registry Registry instance
 * \param listing Registry iterator struct
 * \param data Pointer to allocated data will be stored through this pointer
 * \param size Size of allocated data will be stored through this pointer
 * \param format Which format to use (text/plain or TLV)
 * \param single_instance Serialize only one object instance, which requires special handling
 *
 * \return REGISTRY_TLV_SERIALIZE_STATUS_OK if everything went okay
 *
 */
static registry_tlv_serialize_status_t registry_serialize_object(const registry_t* registry,
                                                          registry_listing_t* listing,
                                                          registry_status_t *listing_status,
                                                          uint8_t **data,
                                                          uint32_t *size,
                                                          registry_serialization_format_t format,
                                                          const bool dirty_only,
                                                          bool single_instance,
                                                          bool is_object_path);

/*
 * \brief Serializes a resource under the given path
 *
 * \param registry Registry instance
 * \param listing Registry iterator struct
 * \param data Pointer to allocated data will be stored through this pointer
 * \param size Size of allocated data will be stored through this pointer
 * \param format Serialization format
 *
 * \return REGISTRY_TLV_SERIALIZE_STATUS_OK if everything went okay
 *
 */
static registry_tlv_serialize_status_t registry_serialize_resource(const registry_t* registry,
                                                            registry_listing_t* listing,
                                                            uint8_t **data, uint32_t *size,
                                                            registry_serialization_format_t format,
                                                            const bool dirty_only,
                                                            const registry_object_value_t *registry_value,
                                                            const registry_observation_parameters_t *parameters);

/*
 * \brief Serializes resource instances under the given path (resource)
 *
 * \param registry Registry instance
 * \param listing Registry iterator struct
 * \param data Pointer to allocated data will be stored through this pointer
 * \param size Size of allocated data will be stored through this pointer
 *
 * \return REGISTRY_TLV_SERIALIZE_STATUS_OK if everything went okay
 *
 */
static registry_tlv_serialize_status_t registry_serialize_multiple_resource(const registry_t* registry, registry_listing_t* listing, registry_status_t *listing_status, const bool dirty_only, registry_object_value_t *value, registry_observation_parameters_t *parameters, uint8_t **data, uint32_t *size);


/*
 * \brief Serializes an integer-type value under the given path
 *
 * \param registry Registry instance
 * \param path Registry path struct
 * \param type TLV type information
 * \param id TLV field id
 * \param data Pointer to allocated data will be stored through this pointer
 * \param size Size of allocated data will be stored through this pointer
 *
 * \return REGISTRY_TLV_SERIALIZE_STATUS_OK if everything went okay
 *
 */
static registry_tlv_serialize_status_t registry_serialize_TLV_binary_int(const registry_t* registry,
                                                                    registry_path_t* path,
                                                                    uint8_t type,
                                                                    uint16_t id,
                                                                    uint8_t **data,
                                                                    uint32_t *size,
                                                                    const registry_object_value_t *value);

#if MBED_CLIENT_ENABLE_FLOAT_VALUE
static registry_tlv_serialize_status_t registry_serialize_TLV_binary_float(const registry_t* registry,
                                                                    uint8_t type,
                                                                    uint16_t id,
                                                                    uint8_t **data,
                                                                    uint32_t *size,
                                                                    const registry_object_value_t *value);
#endif


#if MBED_CLIENT_ENABLE_SERIALIZE_PLAINTEXT

/**
 * \brief Serializes a resource value (int, boolean, float, string) in text format as defined
 *        in the OMA LWM2M specification.
 *
 * \param registry Registry instance
 * \param path Registry path struct
 * \param data Pointer to allocated string will be stored through this pointer
 * \param size Size of allocated data will be stored through this pointer
 *
 * \return REGISTRY_TLV_SERIALIZE_STATUS_OK if everything went okay
 */
static registry_tlv_serialize_status_t registry_serialize_text_int(const registry_t* registry,
                                                            uint8_t **data,
                                                            uint32_t *size,
                                                            const registry_object_value_t *value);

static registry_tlv_serialize_status_t registry_serialize_text_bool(const registry_t* registry,
                                                            uint8_t **data,
                                                            uint32_t *size,
                                                            const registry_object_value_t *value);

#if MBED_CLIENT_ENABLE_FLOAT_VALUE
static registry_tlv_serialize_status_t registry_serialize_text_float(const registry_t* registry,
                                                              uint8_t **data,
                                                              uint32_t *size,
                                                              const registry_object_value_t *value);
#endif

static registry_tlv_serialize_status_t registry_serialize_text_string(const registry_t* registry,
                                                               uint8_t **data,
                                                               uint32_t *size,
                                                               const registry_object_value_t *value);

#endif // MBED_CLIENT_ENABLE_SERIALIZE_PLAINTEXT

/*
 * \brief Serializes a generic data blob of given size as OMA-TLV
 *
 * \param type TLV type information
 * \param id TLV id field
 * \param value Pointer to the data which needs to be serialized
 * \param value_length Length of data
 * \param data Pointer to allocated data will be stored through this pointer
 * \param size Size of allocated data will be stored through this pointer
 *
 * \return REGISTRY_TLV_SERIALIZE_STATUS_OK if everything went okay
 */
static registry_tlv_serialize_status_t registry_serialize_TILV(uint8_t type, uint16_t id, const uint8_t *value, uint32_t value_length, uint8_t **data, uint32_t *size);

/*
 * \brief Serializes a 16bit value (TLV ID field) to the given buffer
 *
 * \param id TLV id field value
 * \param size Size of written data will be stored through this pointer
 * \param id_ptr Pointer to data buffer where the value will be serialized to.
 */
static void registry_serialize_id(uint16_t id, uint32_t *size, uint8_t *id_ptr);

/*
 * \brief Serializes a 32bit value (TLV length field) to the given buffer
 *
 * \param id TLV length field value
 * \param size Size of written data will be stored through this pointer
 * \param length_ptr Pointer to data buffer where the value will be serialized to.
 */
static void registry_serialize_length(uint32_t length, uint32_t *size, uint8_t *length_ptr);


static registry_tlv_serialize_status_t registry_deserialize_resources(registry_t* registry,
                                                               const registry_path_t* path,
                                                               const uint8_t* tlv,
                                                               uint32_t tlv_size,
                                                               registry_tlv_serialize_operation_t operation);

static registry_tlv_serialize_status_t registry_deserialize_resource(registry_t* registry,
                                                              const registry_path_t* path,
                                                              const uint8_t* tlv,
                                                              uint32_t tlv_size,
                                                              registry_tlv_serialize_operation_t operation);

static registry_tlv_serialize_status_t registry_deserialize_resource_tlv(registry_t* registry,
                                                              const registry_path_t* path,
                                                              registry_tlv_t* til,
                                                              registry_tlv_serialize_operation_t operation);

static registry_tlv_serialize_status_t registry_deserialize_resource_instances(registry_t* registry,
                                                                        const registry_path_t* path,
                                                                        const uint8_t* tlv,
                                                                        uint32_t tlv_size,
                                                                        registry_tlv_serialize_operation_t operation);


uint8_t* registry_serialize(const registry_t* registry,
                            const registry_path_t* path,
                            uint32_t *size,
                            registry_serialization_format_t format,
                            bool dirty_only,
                            registry_tlv_serialize_status_t *status)
{

    registry_listing_t listing;
    registry_object_value_t value;
    registry_observation_parameters_t parameters;
    bool is_object_path = false;

    const lwm2m_resource_meta_definition_t* meta_data;

    uint8_t* tlv_data = NULL;
    uint32_t tlv_data_size = 0;

    *status = REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND;

#if MBED_CLIENT_ENABLE_SERIALIZE_PLAINTEXT
    if (format == REGISTRY_SERIALIZE_PLAINTEXT || format == REGISTRY_SERIALIZE_OPAQUE) {
#else
    if (format == REGISTRY_SERIALIZE_OPAQUE) {
#endif
        // Check not to use plain text or opaque on multiple resources.
        // This check could be removed, but it would make it harder to notice incorrect usage.
        switch (path->path_type) {
            {
            case REGISTRY_PATH_RESOURCE:
                if(REGISTRY_STATUS_OK == registry_meta_get_resource_definition(path->object_id, path->resource_id, &meta_data)) {
                    if (meta_data->multiple == LWM2M_RESOURCE_SINGLE_INSTANCE) {
                        break;
                    }
                }
            case REGISTRY_PATH_OBJECT:
            case REGISTRY_PATH_OBJECT_INSTANCE:
                *status = REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
                *size = 0;
                return NULL;

            }
            case REGISTRY_PATH_RESOURCE_INSTANCE:
                break;
        }
    }

    listing.path = *path;
    listing.listing_type = REGISTRY_LISTING_RECURSIVE;
    listing.set_registered = 0;

    registry_status_t iter_status = registry_get_objects(registry, &listing, &value, &parameters);
    if (iter_status == REGISTRY_STATUS_NOT_FOUND) {
        *size = 0;
        return NULL;
    }

    //Always send every value in object_instance level notification
    if (listing.path.path_type == REGISTRY_PATH_OBJECT_INSTANCE) {
        dirty_only = false;
    }

    if (listing.path.path_type == REGISTRY_PATH_OBJECT) {
        is_object_path = true;
    }

    while (REGISTRY_STATUS_OK == iter_status && (*status == REGISTRY_TLV_SERIALIZE_STATUS_OK || *status == REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND)) {

        if (listing.path.path_type == REGISTRY_PATH_OBJECT_INSTANCE) {

            print_registry_path("registry_serialize() listing.path: ", &listing.path);
            /* either caller asked for a specific object instance, or this instance is one
             * of the asked instances under an object that was requested.
             */

            bool single_object_instance = REGISTRY_PATH_OBJECT_INSTANCE == path->path_type;

            *status = registry_serialize_object(registry, &listing, &iter_status, &tlv_data, &tlv_data_size, format, dirty_only, single_object_instance, is_object_path);


        } else if (listing.path.path_type == REGISTRY_PATH_RESOURCE) {

            print_registry_path("registry_serialize() listing.path: ", &listing.path);

            *status = registry_serialize_resources(registry, &listing, &iter_status, false, &tlv_data, &tlv_data_size, format, false, &value, &parameters);

        } else if (listing.path.path_type == REGISTRY_PATH_RESOURCE_INSTANCE) {

            print_registry_path("registry_serialize() listing.path: ", &listing.path);

            if (listing.value_set) {

#if MBED_CLIENT_ENABLE_SERIALIZE_PLAINTEXT
                *status = registry_serialize_resource(registry, &listing, &tlv_data, &tlv_data_size, REGISTRY_SERIALIZE_PLAINTEXT, false, &value, &parameters);
#else
                *status = registry_serialize_resource(registry, &listing, &tlv_data, &tlv_data_size, REGISTRY_SERIALIZE_TLV, false, &value, &parameters);
#endif
            }
            iter_status = registry_get_objects(registry, &listing, &value, &parameters);

        } else if (listing.path.path_type == REGISTRY_PATH_OBJECT) {
            /* try the next registry item, hopefully it's an object instance */

            print_registry_path("registry_serialize() listing.path: ", &listing.path);

            iter_status = registry_get_objects(registry, &listing, &value, &parameters);

        }
    }

    if (*status == REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND) {
        //Not found from some resource does not matter as long as we got data from some of the resource(s).
        *status = REGISTRY_TLV_SERIALIZE_STATUS_OK;
    }

    *size = tlv_data_size;
    return tlv_data;
}



static registry_tlv_serialize_status_t registry_serialize_resources(const registry_t* registry,
                                      registry_listing_t* listing,
                                      registry_status_t *listing_status,
                                      bool every_resource,
                                      uint8_t** data,
                                      uint32_t *size,
                                      registry_serialization_format_t format,
                                      const bool dirty_only,
                                      registry_object_value_t *value,
                                      registry_observation_parameters_t *parameters)
{
    registry_tlv_serialize_status_t status;

    do {
        if (listing->value_set) {
            status = registry_serialize_resource(registry, listing, data, size, format, dirty_only, value, parameters);
            *listing_status = registry_get_objects(registry, listing, value, parameters);
        } else {
            status = registry_serialize_multiple_resource(registry, listing, listing_status, dirty_only, value, parameters, data, size);
        }

    } while (every_resource && listing->path.path_type >= REGISTRY_PATH_RESOURCE &&
             *listing_status == REGISTRY_STATUS_OK &&
             (status == REGISTRY_TLV_SERIALIZE_STATUS_OK || status == REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND));

    return status;

}


static bool is_dirty_object_instance(const registry_t* registry,
                                     const registry_listing_t* listing,
                                     const registry_observation_parameters_t *parameters)
{
    //Create copies to prevent changing listing during object instance check
    registry_listing_t listing_cpy;
    registry_observation_parameters_t parameters_cpy;
    listing_cpy = *listing;
    parameters_cpy = *parameters;

    registry_status_t listing_status = REGISTRY_STATUS_OK;
    registry_tlv_serialize_status_t status = REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND;
    registry_object_value_t value;

    do {
        if (!(listing_cpy.parameters_set) || parameters_cpy.dirty) {
            return true;
        }
        listing_status = registry_get_objects(registry, &listing_cpy, &value, &parameters_cpy);
    } while (listing_cpy.path.path_type >= REGISTRY_PATH_RESOURCE &&
             listing_status == REGISTRY_STATUS_OK &&
             (status == REGISTRY_TLV_SERIALIZE_STATUS_OK || status == REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND));

    return false;
}


static registry_tlv_serialize_status_t registry_serialize_object(const registry_t* registry,
                                                          registry_listing_t* listing,
                                                          registry_status_t *listing_status,
                                                          uint8_t **data,
                                                          uint32_t *size,
                                                          registry_serialization_format_t format,
                                                          bool dirty_only,
                                                          bool single_instance,
                                                          bool is_object_path)
{

    uint8_t *resource_data = NULL;
    uint32_t resource_size = 0;
    registry_tlv_serialize_status_t status = REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND;
    registry_object_value_t value;
    registry_observation_parameters_t parameters;
    uint16_t object_instance = listing->path.object_instance_id;

    /* we rely on being passed an object instance in the listing struct */

    if (REGISTRY_STATUS_OK != (*listing_status = registry_get_objects(registry, listing, &value, &parameters)) ||
        listing->path.path_type < REGISTRY_PATH_RESOURCE) {
        return status;
    }

    //In the case object path, whole instance should be sent even if only one resource is dirty
    if (is_object_path) {
        if (dirty_only && is_dirty_object_instance(registry, listing, &parameters)) {
            dirty_only = false;
        }
    }

    status = registry_serialize_resources(registry, listing, listing_status, true, &resource_data, &resource_size, format, dirty_only, &value, &parameters);

    if(status == REGISTRY_TLV_SERIALIZE_STATUS_OK ||
       (status == REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND && resource_size)) {

        /* if the caller only wanted this object instance serialized, we don't need to wrap the resource
         * data into object instance tlv value
         */
        if (single_instance) {

            status = registry_serialize_append_to_buffer(resource_data, resource_size, data, size);
        } else {

            status = registry_serialize_TILV(TYPE_OBJECT_INSTANCE,
                                             object_instance,
                                             resource_data,
                                             resource_size,
                                             data,
                                             size);
        }
        lwm2m_free(resource_data);
    }

    return status;
}


registry_tlv_serialize_status_t registry_serialize_resource(const registry_t* registry,
                                                            registry_listing_t* listing,
                                                            uint8_t **data,
                                                            uint32_t *size,
                                                            registry_serialization_format_t format,
                                                            const bool dirty_only,
                                                            const registry_object_value_t *registry_value,
                                                            const registry_observation_parameters_t *parameters)
{

    registry_tlv_serialize_status_t status = REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND;
    const lwm2m_resource_meta_definition_t* resdef;

    /* by default, we are handling a resource and resource id will be serialized */
    uint8_t resource_type;
    uint16_t resource_id;
    bool empty = false;

    print_registry_path("registry_serialize_resource() listing->path: ", &listing->path);

    if (dirty_only && listing->parameters_set && !parameters->dirty) {
        tr_debug("registry_serialize_resource() !dirty, skip.");
        return REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND;
    }

    if (registry_meta_get_resource_definition(listing->path.object_id, listing->path.resource_id, &resdef) != REGISTRY_STATUS_OK) {
        return REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND;
    }

    if (LWM2M_RESOURCE_OBSERVABLE != registry_meta_is_resource_observable(resdef)) {
        // Skip resources that cannot be read.
        return REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND; //TODO: Check this code.
    }

    registry_status_t temp_status = registry_is_value_empty(registry, &listing->path, &empty);

    if ((REGISTRY_STATUS_OK == temp_status && empty) ||
         REGISTRY_STATUS_NO_DATA == temp_status) {
        // no data in resource
        return REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND;
    }

    /* resource instances need to have the correct type and resource instance id instead of resource id */
    if (listing->path.path_type > REGISTRY_PATH_RESOURCE) {
        resource_type = TYPE_RESOURCE_INSTANCE;
        resource_id = listing->path.resource_instance_id;
    } else {
        resource_type = TYPE_RESOURCE;
        resource_id = listing->path.resource_id;
    }

    if (format == REGISTRY_SERIALIZE_OPAQUE && resdef->type == LWM2M_RESOURCE_TYPE_OPAQUE) {

        status = registry_serialize_append_to_buffer(registry_value->generic_value.data.opaque_data->data,
                                                        registry_value->generic_value.data.opaque_data->size,
                                                        data, size);
    }
    else if (format == REGISTRY_SERIALIZE_TLV) {

        switch (resdef->type) {

            case LWM2M_RESOURCE_TYPE_INTEGER:
            case LWM2M_RESOURCE_TYPE_TIME:
                status = registry_serialize_TLV_binary_int(registry, &listing->path, resource_type, resource_id, data, size, registry_value);
                break;

            case LWM2M_RESOURCE_TYPE_BOOLEAN:
                status = registry_serialize_TILV(resource_type, resource_id, (uint8_t*)&registry_value->int_value, 1, data, size);
                break;

            case LWM2M_RESOURCE_TYPE_STRING:
                status = registry_serialize_TILV(resource_type, resource_id,
                                                (uint8_t*)registry_value->generic_value.data.string, strlen(registry_value->generic_value.data.string),
                                                data, size);
                break;

            case LWM2M_RESOURCE_TYPE_OPAQUE:
                status = registry_serialize_TILV(resource_type, resource_id,
                                                registry_value->generic_value.data.opaque_data->data,
                                                registry_value->generic_value.data.opaque_data->size,
                                                data, size);
                break;

#if MBED_CLIENT_ENABLE_FLOAT_VALUE
            case LWM2M_RESOURCE_TYPE_FLOAT:
                status = registry_serialize_TLV_binary_float(registry, resource_type, resource_id, data, size, registry_value);
                break;
#endif

            default:
                //TODO: Objlnk
                assert(0);

        }

    }
#if MBED_CLIENT_ENABLE_SERIALIZE_PLAINTEXT
    /* caller may want to get TLV back even for single resource */
    else if (format == REGISTRY_SERIALIZE_PLAINTEXT) {

        bool empty = false;

        if (REGISTRY_STATUS_OK == registry_is_value_empty(registry, &listing->path, &empty) && !empty) {

            switch (resdef->type) {

                case LWM2M_RESOURCE_TYPE_INTEGER:
                case LWM2M_RESOURCE_TYPE_TIME:
                    status = registry_serialize_text_int(registry, data, size, registry_value);
                    break;

                case LWM2M_RESOURCE_TYPE_BOOLEAN:
                    status = registry_serialize_text_bool(registry, data, size, registry_value);
                    break;

                case LWM2M_RESOURCE_TYPE_STRING:
                    status = registry_serialize_text_string(registry, data, size, registry_value);
                    break;

                case LWM2M_RESOURCE_TYPE_OPAQUE:
                    status = registry_serialize_append_to_buffer(registry_value->generic_value.data.opaque_data->data,
                                                                    registry_value->generic_value.data.opaque_data->size,
                                                                    data, size);
                    break;

#if MBED_CLIENT_ENABLE_FLOAT_VALUE
                case LWM2M_RESOURCE_TYPE_FLOAT:
                    status = registry_serialize_text_float(registry, data, size, registry_value);
                    break;
#endif

                default:
                    //TODO: Objlnk
                    assert(0);

            }
        } else {
            status = REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND;
        }

    }
#endif // MBED_CLIENT_ENABLE_SERIALIZE_PLAINTEXT
    else {
        // Invalid format
        assert(false);
    }

    return status;
}

static registry_tlv_serialize_status_t registry_serialize_multiple_resource(const registry_t* registry,
                                                                     registry_listing_t* listing,
                                                                     registry_status_t *listing_status,
                                                                     const bool dirty_only,
                                                                     registry_object_value_t *value,
                                                                     registry_observation_parameters_t *parameters,
                                                                     uint8_t **data,
                                                                     uint32_t *size)
{

    registry_tlv_serialize_status_t status = REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND;
    uint8_t* nested_data = NULL;
    uint32_t nested_data_size = 0;
    uint16_t resource_id = listing->path.resource_id;
    bool empty;

    while (REGISTRY_STATUS_OK == (*listing_status = registry_get_objects(registry, listing, value, parameters))) {

        print_registry_path("registry_serialize_multiple_resource() listing->path: ", &listing->path);

        if (listing->path.path_type != REGISTRY_PATH_RESOURCE_INSTANCE) {
            break;
        }

        registry_status_t temp_status = registry_is_value_empty(registry, &listing->path, &empty);

        if ((REGISTRY_STATUS_OK == temp_status && empty) ||
             REGISTRY_STATUS_NO_DATA == temp_status) {
            continue;
        }


        if (!listing->value_set) {
            continue;
        }

        status = registry_serialize_resource(registry, listing, &nested_data, (uint32_t *) &nested_data_size, REGISTRY_SERIALIZE_TLV, dirty_only, value, parameters);


        if (REGISTRY_TLV_SERIALIZE_STATUS_OK != status && REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND != status) {
            break;
        }

    }

    if (nested_data) {
        status = registry_serialize_TILV(TYPE_MULTIPLE_RESOURCE, resource_id, nested_data, nested_data_size, data, size);
    }

    lwm2m_free(nested_data);
    return status;
}

uint8_t *registry_write_int64(int64_t value, uint8_t *ptr, uint32_t *value_size)
{
    // Turn variable len off for now as testing does not support it yet.
#if 0
    if (value < 0) {

        if (value >= INT8_MIN) {
            *value_size = 1;
            *ptr++ = (uint8_t) value;
        } else if (value >= INT16_MIN) {
            *value_size = 2;
            ptr = common_write_16_bit((uint16_t) value, ptr);
        } else if (value >= INT32_MIN) {
            *value_size = 4;
            ptr = common_write_32_bit((uint32_t) value, ptr);
        } else {
            *value_size = 8;
            ptr = common_write_64_bit((uint64_t) value, ptr);
        }

    } else {

        if (value <= INT8_MAX) {
            *value_size = 1;
            *ptr++ = (uint8_t) value;
        } else if (value <= INT16_MAX) {
            *value_size = 2;
            ptr = common_write_16_bit((uint16_t) value, ptr);
        } else if (value <= INT32_MAX) {
            *value_size = 4;
            ptr = common_write_32_bit((uint32_t) value, ptr);
        } else  {
#endif
            *value_size = 8;
            ptr = common_write_64_bit(value, ptr);
#if 0
        }

    }
#endif
    return ptr;
}

/* See, OMA-TS-LightweightM2M-V1_0-20170208-A, Appendix C,
 * Data Types, Integer, Boolean and TY
 * Yime, TLV Format */
static registry_tlv_serialize_status_t registry_serialize_TLV_binary_int(const registry_t* registry,
                                                                  registry_path_t* path,
                                                                  uint8_t type,
                                                                  uint16_t id,
                                                                  uint8_t **data,
                                                                  uint32_t *size,
                                                                  const registry_object_value_t *value)
{
    /* max len 8 bytes */
    uint8_t buffer[8];
    uint32_t size_written;

    registry_write_int64(value->int_value, buffer, &size_written);

    return registry_serialize_TILV(type, id, buffer, size_written, data, size);
}

static registry_tlv_serialize_status_t registry_serialize_append_to_buffer(const uint8_t *value, int value_len, uint8_t **data, uint32_t *size)
{
    tr_debug("registry_serialize_apppend_to_buffer() value_len: %d", value_len);
    if (!value || value_len < 0) {

        return REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT; //TODO: Check if this is an error?
    }

    if (value_len > 0) {

        void *new_data = lwm2m_realloc(*data, *size + value_len);

        if (!new_data) {
            lwm2m_free(*data);
            *data = NULL; //TODO: Check if there is a need for this?
            return REGISTRY_TLV_SERIALIZE_STATUS_NO_MEMORY;
        }

        *data = new_data;

        /* append the new data */
        memcpy((*data) + (*size), value, value_len);
        *size += value_len;
    }

    return REGISTRY_TLV_SERIALIZE_STATUS_OK;

}

#if MBED_CLIENT_ENABLE_SERIALIZE_PLAINTEXT
static registry_tlv_serialize_status_t registry_serialize_text_int(const registry_t* registry,
                                                            uint8_t **data,
                                                            uint32_t *size,
                                                            const registry_object_value_t *value)
{
    char int64_string[REGISTRY_INT64_STRING_MAX_LEN];

    tr_debug("registry_serialize_text_int() value: %" PRId64, value->int_value);

    /* write the integer value to a decimal number string and copy it into a buffer allocated for caller */
    int value_len = snprintf(int64_string, REGISTRY_INT64_STRING_MAX_LEN, "%" PRId64, value->int_value);

    return registry_serialize_append_to_buffer((uint8_t*)int64_string, value_len, data, size);
}

static registry_tlv_serialize_status_t registry_serialize_text_bool(const registry_t* registry,
                                                            uint8_t **data,
                                                            uint32_t *size,
                                                            const registry_object_value_t *value)
{
    tr_debug("registry_serialize_text_bool() value: %" PRId64, value->int_value);

    char bool_string;

    if (value->int_value == 0) {
        bool_string = '0';
    } else {
        bool_string = '1';
    }

    return registry_serialize_append_to_buffer((uint8_t*)&bool_string, sizeof(bool_string), data, size);
}

#if MBED_CLIENT_ENABLE_FLOAT_VALUE
static registry_tlv_serialize_status_t registry_serialize_text_float(const registry_t* registry,
                                                              uint8_t **data,
                                                              uint32_t *size,
                                                              const registry_object_value_t *value)
{
    // max length of double string in here is 33 bytes + zero terminator
    // Note: the "%e" really is formatting a double, not float, so we need space for it.
    char float_string[REGISTRY_DOUBLE_SCIENTIFIC_STRING_MAX_LEN];

    tr_debug("registry_serialize_text_float() value: %e", value->float_value);

    int value_len = snprintf(float_string, REGISTRY_DOUBLE_SCIENTIFIC_STRING_MAX_LEN, "%e", value->float_value);

    if (value_len >= REGISTRY_DOUBLE_SCIENTIFIC_STRING_MAX_LEN) {
        // oops, the float conversion works unexpectedly and produces more digits than we had space for
        tr_error("unable to serialize float value %e", value->float_value);
        return REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
    }

    return registry_serialize_append_to_buffer((uint8_t*)float_string, value_len, data, size);
}
#endif

static registry_tlv_serialize_status_t registry_serialize_text_string(const registry_t* registry,
                                                               uint8_t **data,
                                                               uint32_t *size,
                                                               const registry_object_value_t *value)
{

    return registry_serialize_append_to_buffer((uint8_t*)value->generic_value.data.string, strlen(value->generic_value.data.string), data, size);
}

#endif // MBED_CLIENT_ENABLE_SERIALIZE_PLAINTEXT

#if MBED_CLIENT_ENABLE_FLOAT_VALUE
static registry_tlv_serialize_status_t registry_serialize_TLV_binary_float(const registry_t* registry,
                                                                    uint8_t type,
                                                                    uint16_t id,
                                                                    uint8_t **data,
                                                                    uint32_t *size,
                                                                    const registry_object_value_t *value)
{
    uint8_t buffer[4];
    // XXX: ugh. need fix this type coercion properly.
    common_write_32_bit(*(uint32_t*)&value->float_value, buffer);
    return registry_serialize_TILV(type, id, buffer, sizeof(buffer), data, size);
}
#endif



static registry_tlv_serialize_status_t registry_serialize_TILV(uint8_t type,
                                                        uint16_t id,
                                                        const uint8_t *value,
                                                        uint32_t value_length,
                                                        uint8_t **data,
                                                        uint32_t *size)
{

    uint8_t *tlv;
    const uint32_t type_length = TLV_TYPE_SIZE;
    type += id < 256 ? 0 : ID16;
    type += value_length < 8 ? value_length :
            value_length < 256 ? LENGTH8 :
            value_length < 65536 ? LENGTH16 : LENGTH24;

    const uint8_t tlv_type = type & 0xFF;

    uint32_t id_size;
    uint8_t id_array[MAX_TLV_ID_SIZE];
    registry_serialize_id(id, &id_size, id_array);

    uint32_t length_size;
    uint8_t length_array[MAX_TLV_LENGTH_SIZE];
    registry_serialize_length(value_length, &length_size, length_array);

    // Humm.. this does allocate the exact amount of memory needed for the end result. But
    // the code could be saved a bit by actually allocating for the worst case scenario, which
    // is at most just 3 bytes off the optimal. This function is ~250B long, partially
    // due to this "optimization".
    const uint32_t new_data_size = *size + type_length + id_size + length_size + value_length;

    // Try to avoid fragmentation by reallocating existing block, if there is any.
    if (*data) {
        tlv = (uint8_t*)lwm2m_realloc(*data, new_data_size);
    } else {
        tlv = (uint8_t*)lwm2m_alloc(new_data_size);
    }
    if (!tlv) {
        /* memory allocation has failed */
        /* return failure immediately */
        lwm2m_free(*data);
        *data = NULL;
        *size = 0;
        return REGISTRY_TLV_SERIALIZE_STATUS_NO_MEMORY;
        /* eventually NULL will be returned to serializer public method caller */
    }

    // dest is buffer past the existing data, where the new TLV will be copied
    uint8_t* dest = tlv + *size;

    *data = tlv;
    *size = new_data_size;

    memcpy(dest, &tlv_type, type_length);
    dest += type_length;

    memcpy(dest, id_array, id_size);
    dest += id_size;

    memcpy(dest, length_array, length_size);
    dest += length_size;

    memcpy(dest, value, value_length);

    return REGISTRY_TLV_SERIALIZE_STATUS_OK;
}

static void registry_serialize_id(uint16_t id, uint32_t *size, uint8_t *id_ptr)
{

    if(id > 255) {
        *size=2;
        id_ptr[0] = (id & 0xFF00) >> 8;
        id_ptr[1] = id & 0xFF;
    } else {
        *size=1;
        id_ptr[0] = id & 0xFF;
    }
}

static void registry_serialize_length(uint32_t length, uint32_t *size, uint8_t *length_ptr)
{

    if (length > 65535) {
        *size = 3;
        length_ptr[0] = (length & 0xFF0000) >> 16;
        length_ptr[1] = (length & 0xFF00) >> 8;
        length_ptr[2] = length & 0xFF;
    } else if (length > 255) {
        *size = 2;
        length_ptr[0] = (length & 0xFF00) >> 8;
        length_ptr[1] = length & 0xFF;
    } else if (length > 7) {
        *size = 1;
        length_ptr[0] = length & 0xFF;
    } else {
        *size=0;
    }
}

static bool registry_tlv_available(registry_tlv_t* stlv)
{
    return ((stlv->offset + stlv->length) < stlv->tlv_size);
}

static void registry_tlv_init(registry_tlv_t* stlv, const uint8_t *tlv, uint32_t tlv_size)
{
    stlv->tlv = tlv;
    stlv->tlv_size = tlv_size;
    stlv->offset = 0;
    stlv->length = 0;
}


static registry_tlv_serialize_status_t registry_tlv_deserialize_id(registry_tlv_t* stlv, uint32_t idLength)
{

    if ((stlv->offset) >= stlv->tlv_size) {
        return REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT;
    }

    stlv->id = stlv->tlv[stlv->offset++];
    if (ID16 == idLength) {

        if (stlv->offset >= stlv->tlv_size) {
            return REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT;
        }
        stlv->id = (stlv->id << 8) + stlv->tlv[stlv->offset++];
    }

    return REGISTRY_TLV_SERIALIZE_STATUS_OK;
}

static registry_tlv_serialize_status_t registry_tlv_deserialize_length(registry_tlv_t* stlv, uint32_t lengthType)
{

    if (lengthType > 0) {
        if (stlv->offset >= stlv->tlv_size) {
            return REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT;
        }
        stlv->length = stlv->tlv[stlv->offset++];
    }

    if (lengthType > LENGTH8) {
        if (stlv->offset >= stlv->tlv_size) {
            return REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT;
        }
        stlv->length = (stlv->length << 8) + stlv->tlv[stlv->offset++];
    }

    if (lengthType > LENGTH16) {
        if (stlv->offset >= stlv->tlv_size) {
            return REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT;
        }
        stlv->length = (stlv->length << 8) + stlv->tlv[stlv->offset++];
    }

    return REGISTRY_TLV_SERIALIZE_STATUS_OK;
}

static registry_tlv_serialize_status_t registry_tlv_deserialize(registry_tlv_t* stlv)
{

    if (stlv->offset + stlv->length >= stlv->tlv_size) {
        return REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT;
    }
    stlv->offset = stlv->offset + stlv->length;
    stlv->type = stlv->tlv[stlv->offset] & 0xC0;

    uint32_t idLength = stlv->tlv[stlv->offset] & ID16;
    uint32_t lengthType = stlv->tlv[stlv->offset] & LENGTH24;
    if (0 == lengthType) {
        stlv->length = stlv->tlv[stlv->offset] & 0x07;
    }

    stlv->offset++;

    if (registry_tlv_deserialize_id(stlv, idLength) == REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT) {
        return REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT;
    }

    if (registry_tlv_deserialize_length(stlv, lengthType) == REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT) {
        return REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT;
    }

    if (stlv->offset + stlv->length > stlv->tlv_size) {
        return REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT;
    }

    return REGISTRY_TLV_SERIALIZE_STATUS_OK;
}

/*
 * Read 1-8 bytes from given data and interpret them as network-byte-order integer.
 */
static uint64_t registry_tlv_read_uint64(const uint8_t* data, uint8_t size)
{
    uint64_t value = 0;

    for (int i = size-1; i >= 0; i--) {
        value |= (uint64_t) data[size - 1 - i] << (8 * i);
    }

    return value;
 }

// used by unit tests
int64_t registry_tlv_read_int64(const uint8_t *data, uint8_t size)
{

    int64_t value;

    value = registry_tlv_read_uint64(data, size);

    /* Cast to according the size read if needed */
    switch (size) {
        case 1: return (int64_t)(int8_t)value;
        case 2: return (int64_t)(int16_t)value;
        case 4: return (int64_t)(int32_t)value;
    }

    return value;

}

/*
 * Wrap generic integer reading with values from given tlv struct.
 */
static int64_t registry_tlv_get_value_integer(const registry_tlv_t* tlvs)
{
    return registry_tlv_read_int64(tlvs->tlv + tlvs->offset, tlvs->length);
}

#if MBED_CLIENT_ENABLE_FLOAT_VALUE
static float registry_tlv_get_value_float(const registry_tlv_t* tlvs)
{
    uint32_t value;
    value = registry_tlv_read_uint64(tlvs->tlv + tlvs->offset, tlvs->length);
    return *(float*)&value;
}
#endif

#if 0
/*
 * Read uint16 from given data (network byte order)
 */
static uint16_t registry_tlv_read_uint16(const uint8_t* data)
{
    uint8_t msb = data[0];
    uint8_t lsb = data[1];
    return (msb << 8) + lsb;
}
#endif

static const uint8_t* registry_tlv_get_value_string(const registry_tlv_t* tlvs, uint32_t* length)
{
    const uint8_t* tlv_value = tlvs->tlv + tlvs->offset;
    *length = tlvs->length;
    return tlv_value;
}


#if 0
static uint8_t registry_tlv_is_object_instance(const uint8_t *tlv, uint32_t offset)
{
    uint8_t ret = 0;
    if (tlv) {
        uint8_t value = tlv[offset];
        ret = (TYPE_OBJECT_INSTANCE == (value & TYPE_RESOURCE));
    }
    return ret;
}
#endif

registry_tlv_serialize_status_t registry_deserialize(registry_t* registry,
                                                     const registry_path_t* path,
                                                     const uint8_t* tlv,
                                                     uint32_t tlv_size,
                                                     registry_tlv_serialize_operation_t operation)
{

    registry_tlv_serialize_status_t status = REGISTRY_TLV_SERIALIZE_STATUS_OK;

    /* start by reading the first TLV header to see if the path agrees with it */
    registry_tlv_t til;
    registry_tlv_init(&til, tlv, tlv_size);
    print_registry_path("registry_deserialize() path: ", path);

    if (path->path_type == REGISTRY_PATH_OBJECT && operation == REGISTRY_OPERATION_REPLACE) {
        tr_debug("registry_deserialize() removing whole object for replacement");
        /* remove the whole object. this is a special case during bootstrap sequence. */
        registry_status_t status = registry_remove_object(registry, path, REGISTRY_REMOVE_FOR_REPLACEMENT);

        if (status != REGISTRY_STATUS_OK && status != REGISTRY_STATUS_NOT_FOUND) {
            return REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
        }
    }

    while (registry_tlv_available(&til) && status == REGISTRY_TLV_SERIALIZE_STATUS_OK) {

        /* attempt to read the next TLV header */

        if (registry_tlv_deserialize(&til) != REGISTRY_TLV_SERIALIZE_STATUS_OK) {
            return REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT;
        }

        // Duplicate path, which is used by all the branches (and the non-existing else does not
        // mind if this not copied). This saves a few dozen of bytes of code.
        registry_path_t curr_path = *path;

        if (til.type == TYPE_OBJECT_INSTANCE) {
            /* now we need to look for resources under this object instance and move their contents into registry.
             * 'operation' will dictate if we rewrite the whole tree (PUT) or just update individual values (POST)
             */
            curr_path.object_instance_id = til.id;
            curr_path.path_type = REGISTRY_PATH_OBJECT_INSTANCE;
            if (operation == REGISTRY_OPERATION_REPLACE) {
                /* remove everything under this object instance */
                registry_status_t status = registry_remove_object(registry, &curr_path, REGISTRY_REMOVE_FOR_REPLACEMENT);

                if (status != REGISTRY_STATUS_OK && status != REGISTRY_STATUS_NOT_FOUND) {
                    return REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
                }
            }
            status = registry_deserialize_resources(registry, &curr_path, tlv + til.offset, til.length, operation);

        } else if (til.type == TYPE_RESOURCE) {
            curr_path.resource_id = til.id;
            curr_path.path_type = REGISTRY_PATH_RESOURCE;
            if (operation == REGISTRY_OPERATION_REPLACE) {
                /* remove everything under this object instance */
                registry_status_t status = registry_remove_object(registry, &curr_path, REGISTRY_REMOVE_FOR_REPLACEMENT);

                if (status != REGISTRY_STATUS_OK && status != REGISTRY_STATUS_NOT_FOUND) {
                    return REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
                }
            }
            status = registry_deserialize_resource_tlv(registry, &curr_path, &til, operation);

        } else if (til.type == TYPE_RESOURCE_INSTANCE) {
            curr_path.resource_instance_id = til.id;
            curr_path.path_type = REGISTRY_PATH_RESOURCE_INSTANCE;
            status = registry_deserialize_resource_tlv(registry, &curr_path, &til, operation);
        } else if (til.type == TYPE_MULTIPLE_RESOURCE) {
            curr_path.path_type = REGISTRY_PATH_RESOURCE;
            curr_path.resource_id = til.id;
            status = registry_deserialize_resource_instances(registry, &curr_path, tlv + til.offset, til.length, operation);
        }

    }

    return status;
}

static registry_tlv_serialize_status_t registry_deserialize_resources(registry_t* registry,
                                                               const registry_path_t* path,
                                                               const uint8_t* tlv,
                                                               uint32_t tlv_size,
                                                               registry_tlv_serialize_operation_t operation)
{

    registry_tlv_serialize_status_t status = REGISTRY_TLV_SERIALIZE_STATUS_OK;
    registry_tlv_t til;

    registry_tlv_init(&til, tlv, tlv_size);

    while (registry_tlv_available(&til) && status == REGISTRY_TLV_SERIALIZE_STATUS_OK) {

        registry_path_t curr_path = *path;

        /* attempt to read the next TLV header */

        if (registry_tlv_deserialize(&til) != REGISTRY_TLV_SERIALIZE_STATUS_OK) {
            return REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT;
        }

        curr_path.path_type = REGISTRY_PATH_RESOURCE;
        curr_path.resource_id = til.id;

        if (til.type == TYPE_RESOURCE && path->path_type == REGISTRY_PATH_OBJECT_INSTANCE) {
            /* this appears to be a serialized resource -> attempt to deserialize it */
            status = registry_deserialize_resource_tlv(registry, &curr_path, &til, operation);

        } else if (til.type == TYPE_MULTIPLE_RESOURCE && path->path_type == REGISTRY_PATH_OBJECT_INSTANCE) {
            /* and this looks like a resource with multiple instances, which needs a different kind of handler */
            status = registry_deserialize_resource_instances(registry, &curr_path, tlv + til.offset, til.length, operation);
        }

    }

    return status;
}

static registry_tlv_serialize_status_t registry_deserialize_resource(registry_t* registry,
                                                              const registry_path_t* path,
                                                              const uint8_t* tlv,
                                                              uint32_t tlv_size,
                                                              registry_tlv_serialize_operation_t operation)
{

    /* by default, we are handling a resource and resource id will be deserialized */
    registry_tlv_t til;

    registry_tlv_init(&til, tlv, tlv_size);

    if (registry_tlv_deserialize(&til) != REGISTRY_TLV_SERIALIZE_STATUS_OK) {
        return REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT;
    }

    return registry_deserialize_resource_tlv(registry, path, &til, operation);
}

static registry_tlv_serialize_status_t registry_deserialize_resource_tlv(registry_t* registry,
                                                              const registry_path_t* path,
                                                              registry_tlv_t* til,
                                                              registry_tlv_serialize_operation_t operation)
{

    registry_tlv_serialize_status_t status = REGISTRY_TLV_SERIALIZE_STATUS_OK;
    const lwm2m_resource_meta_definition_t* resdef;

    /* by default, we are handling a resource and resource id will be deserialized */
    registry_path_t curr_path = *path;

    if (registry_meta_get_resource_definition(path->object_id, path->resource_id, &resdef) != REGISTRY_STATUS_OK) {
        return REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND;
    }
    /* resource instances need to have the correct type and resource instance id instead of resource id */
    if (curr_path.path_type > REGISTRY_PATH_RESOURCE) {
        curr_path.resource_instance_id = til->id;
    }

    if (resdef->type == LWM2M_RESOURCE_TYPE_INTEGER) {

        int64_t value;

        if (til->length == 1 || til->length == 2 || til->length == 4 || til->length == 8) {

            value = registry_tlv_get_value_integer(til);
            if (registry_set_value_int(registry, &curr_path, value) != REGISTRY_STATUS_OK) {
                status = REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
            }

        } else {
            tr_error("registry_deserialize_resource_tlv unexpected integer size");
            return REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
        }



    } else if (resdef->type == LWM2M_RESOURCE_TYPE_BOOLEAN) {

        bool value;

        if (til->length != 1) {
            tr_error("registry_deserialize_resource_tlv unexpected boolean size");
            return REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
        }

        value = (0 != registry_tlv_get_value_integer(til));
        if (registry_set_value_boolean(registry, &curr_path, value) != REGISTRY_STATUS_OK) {
            status = REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
        }

    } else if (resdef->type == LWM2M_RESOURCE_TYPE_TIME) {

        int64_t value;

        if (til->length > sizeof(value)) {
            tr_error("registry_deserialize_resource_tlv unexpected time size");
            return REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
        }

        value = registry_tlv_get_value_integer(til);
        if (registry_set_value_time(registry, &curr_path, value) != REGISTRY_STATUS_OK) {
            status = REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
        }

    } else if (resdef->type == LWM2M_RESOURCE_TYPE_STRING) {

        uint32_t value_size = 0;
        const uint8_t* value = registry_tlv_get_value_string(til, &value_size);
        if (value) {

            if (registry_set_value_string_copy(registry, &curr_path, value, value_size) != REGISTRY_STATUS_OK) {
                status = REGISTRY_TLV_SERIALIZE_STATUS_NO_MEMORY;
            }

        }
    } else if (resdef->type == LWM2M_RESOURCE_TYPE_OPAQUE) {

        const uint8_t* value;
        uint32_t value_size;
        // opaque data is encoded pretty much like string in TLV format
        value = registry_tlv_get_value_string(til, &value_size);
        if (value) {

            if (registry_set_value_opaque_copy(registry, &curr_path, value, value_size) != REGISTRY_STATUS_OK) {
                status = REGISTRY_TLV_SERIALIZE_STATUS_NO_MEMORY;
            }
        }
    }
#if MBED_CLIENT_ENABLE_FLOAT_VALUE
    else if (resdef->type == LWM2M_RESOURCE_TYPE_FLOAT) {
        /* TODO: add support for double. changes needed in registry API as well. */
        float value;

        if (til->length != sizeof(float)) {
            tr_error("registry_deserialize_resource_tlv unexpected float size");
            return REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
        }

        value = registry_tlv_get_value_float(til);
        if (registry_set_value_float(registry, &curr_path, value) != REGISTRY_STATUS_OK) {
            status = REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
        }
    }
#endif
    else {
        // TODO: Read Objlnk. Type none should not have any data, but does it need some handling?
        tr_error("registry_deserialize_resource_tlv unknown type: %d", resdef->type);
        status = REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
    }

    return status;
}

static registry_tlv_serialize_status_t registry_deserialize_resource_instances(registry_t* registry,
                                                                        const registry_path_t* path,
                                                                        const uint8_t* tlv,
                                                                        uint32_t tlv_size,
                                                                        registry_tlv_serialize_operation_t operation)
{

    registry_tlv_serialize_status_t status = REGISTRY_TLV_SERIALIZE_STATUS_OK;

    registry_tlv_t til;
    registry_tlv_init(&til, tlv, tlv_size);

    while (registry_tlv_available(&til) && status == REGISTRY_TLV_SERIALIZE_STATUS_OK) {

        // attempt to read the next TLV header
        if (registry_tlv_deserialize(&til) != REGISTRY_TLV_SERIALIZE_STATUS_OK) {
            return REGISTRY_TLV_SERIALIZE_STATUS_INVALID_INPUT;
        }

        registry_path_t curr_path = *path;
        curr_path.path_type = REGISTRY_PATH_RESOURCE_INSTANCE;
        curr_path.resource_instance_id = til.id;
        if (til.type == TYPE_RESOURCE_INSTANCE) {
            status = registry_deserialize_resource_tlv(registry, &curr_path, &til, operation);
        } else {
            status = registry_deserialize_resource(registry, &curr_path, tlv + til.offset, til.length, operation);
        }

    }
    return status;
}

#if MBED_CLIENT_ENABLE_DESERIALIZE_PLAINTEXT

registry_tlv_serialize_status_t registry_deserialize_text_resource_instance(registry_t* registry,
                                                                            const registry_path_t* path,
                                                                            const char* data,
                                                                            const uint32_t data_size,
                                                                            const registry_tlv_serialize_operation_t operation)
{
    registry_tlv_serialize_status_t status = REGISTRY_TLV_SERIALIZE_STATUS_OK;
    const lwm2m_resource_meta_definition_t* resdef;
#if MBED_CLIENT_ENABLE_FLOAT_VALUE
    char string_value[REGISTRY_FLOAT_STRING_MAX_LEN];
#else
    char string_value[REGISTRY_INT64_STRING_MAX_LEN];
#endif
    char *string_end;

    if (path->path_type < REGISTRY_PATH_RESOURCE || registry_meta_get_resource_definition(path->object_id, path->resource_id, &resdef) != REGISTRY_STATUS_OK) {
        return REGISTRY_TLV_SERIALIZE_STATUS_NOT_FOUND;
    }

    //TODO: Translate errors returned by registry_set_value functions properly.

    if (resdef->type == LWM2M_RESOURCE_TYPE_INTEGER || resdef->type == LWM2M_RESOURCE_TYPE_TIME) {

        int64_t value;

        //NOTE: Time does have its own setter, but it would just call registry_set_value_int

        if (data_size < REGISTRY_INT64_STRING_MAX_LEN) {

            memcpy(string_value, data, data_size);
            string_value[data_size] = '\0';
            value = strtoll(string_value, &string_end, 10);
            if (string_end != (string_value + data_size)) {
                status = REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
            } else if (registry_set_value_int(registry, path, value) != REGISTRY_STATUS_OK) {
                status = REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
            }

        } else {
            tr_error("registry_deserialize_text_resource_instance unexpected integer size");
            return REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
        }

    } else if (resdef->type == LWM2M_RESOURCE_TYPE_BOOLEAN) {

        bool value;

        if (data_size != 1) {
            tr_error("registry_deserialize_text_resource_instance unexpected boolean size");
            return REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
        }

        if ('1' == *data) {
            value = 1;
        } else if ('0' == *data) {
            value = 0;
        } else {
            return REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
        }

        if (registry_set_value_boolean(registry, path, value) != REGISTRY_STATUS_OK) {
            status = REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
        }

    } else if (resdef->type == LWM2M_RESOURCE_TYPE_STRING) {

        if (registry_set_value_string_copy(registry, path, (uint8_t*)data, data_size) != REGISTRY_STATUS_OK) {
            status = REGISTRY_TLV_SERIALIZE_STATUS_NO_MEMORY;
        }

    }
#if MBED_CLIENT_ENABLE_FLOAT_VALUE
    else if (resdef->type == LWM2M_RESOURCE_TYPE_FLOAT) {
        /* TODO: add support for double. changes needed in registry API as well. */
        float value;

        if (data_size < REGISTRY_FLOAT_STRING_MAX_LEN) {
            memcpy(string_value, data, data_size);
            string_value[data_size] = '\0';
            value = strtof(string_value, &string_end);
            if (string_end != (string_value + data_size)) {
                status = REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
            } else if (registry_set_value_float(registry, path, value) != REGISTRY_STATUS_OK) {
                status = REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
            }

        } else {
            tr_error("registry_deserialize_text_resource_instance unexpected float size");
            return REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
        }

    }
#endif
    else if (resdef->type == LWM2M_RESOURCE_TYPE_OPAQUE) {

        if (REGISTRY_STATUS_OK != registry_set_value_opaque_copy(registry, path, (uint8_t*)data, data_size)) {
            status = REGISTRY_TLV_SERIALIZE_STATUS_NO_MEMORY;
        }

    } else {
        // TODO:  Objlnk. Type none should not have any data, but does it need some handling?
        tr_error("registry_deserialize_text_resource_instance unsupported type: %d", resdef->type);
        status = REGISTRY_TLV_SERIALIZE_STATUS_GENERIC_ERROR;
    }

    return status;
}

#endif // MBED_CLIENT_ENABLE_DESERIALIZE_PLAINTEXT
