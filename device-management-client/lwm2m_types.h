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

#ifndef LWM2M_TYPES_H
#define LWM2M_TYPES_H

#include "mbed-client/lwm2m_config.h"
#include <inttypes.h>

/** \file lwm2m_types.h
 *  \brief Enums and types for LwM2M interface
 */

#ifdef __cplusplus
extern "C" {
#endif


/**
 * \brief Type of the resource callback call.
 */
typedef enum registry_callback_type_e {
    REGISTRY_CALLBACK_NONE = 0, ///< Callback type not set.
    REGISTRY_CALLBACK_VALUE_UPDATED = 1, ///< Value change.
    REGISTRY_CALLBACK_EXECUTE, ///< Execute received for the Resource.
    REGISTRY_CALLBACK_BLOCKMESSAGE_INCOMING, ///< Message block received for the Resource.
    REGISTRY_CALLBACK_BLOCKMESSAGE_OUTGOING, ///< Message block is being sent.
    REGISTRY_CALLBACK_NOTIFICATION_STATUS, ///< Notification status has changed.
    REGISTRY_CALLBACK_ITEM_REMOVED, ///< Registry Object, Resource or Instance was removed.
    REGISTRY_CALLBACK_ITEM_REPLACED, ///< Registry Object, Resource or Instance was removed, but will be added again.
    REGISTRY_CALLBACK_ITEM_ADDED ///< Registry Object, Resource or Instance was added.
} registry_callback_type_t;


/**
 * \brief Resource remove mode.
 */
typedef enum registry_removal_type_e {
    REGISTRY_REMOVE, ///< Normal remove operation.
    REGISTRY_REMOVE_FOR_REPLACEMENT, ///< Resource is replaced with a new one.
    REGISTRY_REMOVE_SKIP_CALLBACK ///< Do not call removal callback function.
} registry_removal_type_t;

/**
 * \brief Notification status codes.
 */
typedef enum registry_notification_status_e {
    NOTIFICATION_STATUS_IGNORE = -1,        ///< Ignored status.
    NOTIFICATION_STATUS_INIT = 0,           ///< Initial state.
    NOTIFICATION_STATUS_BUILD_ERROR,        ///< CoAP message building fails.
    NOTIFICATION_STATUS_RESEND_QUEUE_FULL,  ///< CoAP resend queue full.
    NOTIFICATION_STATUS_SENT,               ///< Notification sent to the server but ACK not yet received.
    NOTIFICATION_STATUS_DELIVERED,          ///< Received ACK from server.
    NOTIFICATION_STATUS_SEND_FAILED,        ///< Message sending failed (retransmission completed).
    NOTIFICATION_STATUS_SUBSCRIBED,         ///< Server has started the observation.
    NOTIFICATION_STATUS_UNSUBSCRIBED        ///< Server has stopped the observation (RESET message or GET with observe 1).
} registry_notification_status_t;

/**
 *  \brief Client Lite internal callbacks always associate with a token to enable multiple ongoing callbacks.
 */
typedef struct registry_callback_token_s {
    uint8_t token[8]; ///< Token data.
    unsigned token_size:4; ///< Length of the token data.
} registry_callback_token_t;

/**
 *  \brief Structure for marking the observation parameters available inside the associated structure.
 */
typedef struct registry_available_parameters_s {
#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
    uint8_t pmin:1; ///< Flag for minimum period.
    uint8_t pmax:1; ///< Flag for maximum period.
    uint8_t gt:1; ///< Flag for greater than.
    uint8_t lt:1; ///< Flag for less than.
    uint8_t st:1; ///< Flag for step.
    uint8_t time:1; ///< Flag for time.
    uint8_t previous_value:1; ///< Flag for previous value.
#endif
    uint8_t content_type:1; ///< Flag for requested content type.

} registry_available_parameters_t;

#if MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS
/**
 *  \brief Union for carrying previous integer or floating point value of the observed Resource.
 */
typedef union registry_observation_value_u {
#if MBED_CLIENT_ENABLE_FLOAT_VALUE
    float float_value; ///< Float value of the resource.
#endif
    int64_t int_value; ///< Integer value of the resource.
} registry_observation_value_t;

#else
typedef void registry_observation_value_t;
#endif //MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS


/**
 *  \brief Structure for keeping opaque data in a registry item.
 */
typedef struct registry_data_opaque_s {
    uint32_t size; ///< Size of the data in bytes.
    uint8_t data[]; ///< Field used for accessing the data.
} registry_data_opaque_t;

/**
 *  \brief Common name for storing either opaque or string data of Resources.
 */
typedef union registry_data_generic_u {
    registry_data_opaque_t *opaque_data; ///< Stores opaque data.
    const char *string; ///< Stores string data as a null-terminated string.
} registry_data_generic_t;

/**
 *  \brief All non-primitive data in registry item values is stored through this structure.
 */
typedef struct registry_generic_value_s {
    uint8_t free_data;              ///< If > 0, data will be freed automatically once removed.
    registry_data_generic_t data; ///< Union for storing the pointer to the actual data.
} registry_generic_value_t;

/**
 *  \brief All resource values are stored through this common name.
 */
typedef union registry_object_value_u {

    int64_t int_value; ///< Used for accessing integer values.
#if MBED_CLIENT_ENABLE_FLOAT_VALUE
    float float_value; ///< Used for accessing float value.
#endif
    registry_generic_value_t generic_value; ///< Used for accessing string and opaque values.
    void *list; ///< For internal use only, MUST NOT be accessed from application.
    uint8_t empty_value; ///< If true, the object value has not been set. This is just for keeping the `registry_get`or `registry_set` API consistent. */

} registry_object_value_t;

/**
 * \brief Describes the path of an item in the LwM2M Object registry.
 *
 * \note Field `path_type` must be read before reading other fields, except `object_id`, to check if they are available.
 */
typedef struct registry_path_s {

    uint16_t object_id; ///< Object ID, for example value 1 translates to /1.
    uint16_t object_instance_id; ///< Object Instance ID, for example value 1 in all applicable IDs translates to /1/1.
    uint16_t resource_id; ///< Resource ID, for example value 1 in all applicable IDs translates to /1/1/1.
    uint16_t resource_instance_id;///< Resource Instance ID, for example value 1 in all applicable IDs translates to /1/1/1/1.

    // this needs only 2 bits, but a bitfield wastes 300 bytes of ROM while saving nothing in RAM
    uint8_t  path_type; ///< This field describes which other fields are valid inside this structure.

} registry_path_t;

/**
 * \brief Possible status codes for registry functions.
 */
typedef enum registry_status_e {

    REGISTRY_STATUS_NO_DATA = 1, ///< There is no data to be read.
    REGISTRY_STATUS_OK = 0, ///< No errors.
    REGISTRY_STATUS_NOT_FOUND = (-1), ///< Resource not found.
    REGISTRY_STATUS_NO_MEMORY = (-2), ///< Out of memory.
    REGISTRY_STATUS_INVALID_INPUT = (-3), ///< Invalid input parameter or data.
    REGISTRY_STATUS_ALREADY_EXISTS = (-4) ///< Resource already created.

} registry_status_t;

/**
 * \brief These values are used for indicating what kind of events are listened from the registry.
 *
 * \note `registry_event_listen_mode_t` uses bitmask values, `REGISTRY_EVENT_LISTEN_EVERY_EVENT` sets all the bits.
 */
typedef enum registry_event_listen_mode_e {

    REGISTRY_EVENT_LISTEN_VALUE_CHANGES = 1, ///< Request events from value changes.
    REGISTRY_EVENT_LISTEN_CREATE_REMOVE = 2, ///< Request events from Object creation removal.
    REGISTRY_EVENT_LISTEN_EVERY_EVENT = 3 ///< Request all available events.

} registry_event_listen_mode_t;

/**
 * \brief Used for selecting the listing type before calling the listing function,
 *        and for internal state information internally.
 */
typedef enum listing_type_e {

    REGISTRY_LISTING_IN_PROGRESS = 0, ///< Internal state, Must not be set by user.
    REGISTRY_LISTING_ALL = 1, ///< List everything stored to registry.
    REGISTRY_LISTING_DIRECTORY = 2, ///< List one directory.
    REGISTRY_LISTING_RECURSIVE = 3, ///< List everything located under the given path.
    REGISTRY_LISTING_DIRECTORY_IN_PROGRESS = 4 ///< Internal state. Must not be set by user.

} listing_type_t;

/**
 * \brief This data structure is used when searching or otherwise iterating the LwM2M Object hierarchy
 *        in the registry.
 *
 * \note Required fields MUST be set before the first function call to the applicable function is made.
 * \note After the a call, the fields MUST NOT changed unless a completely new listing is being started.
 */
typedef struct registry_listing_s {

    /**
     *  Before the first function call, this path MUST be set if `listing_type` is
     *  set as `REGISTRY_LISTING_DIRECTORY` or `REGISTRY_LISTING_RECURSIVE`.
     *
     *  After a successful function call, the path is the path of the current Object.
     */
    registry_path_t path;
    /**
     * This field MUST be set as `REGISTRY_LISTING_ALL`, `REGISTRY_LISTING_DIRECTORY` or `REGISTRY_LISTING_RECURSIVE`.
     */
    uint8_t listing_type;
    uint8_t value_set; ///< This bit is set as 1 if a value is available for the current Resource.
    uint8_t parameters_set; ///< This bit is set as 1 if observation parameters are available for the current Resource.
    uint8_t registered; ///< This bit is set if the Resource has been registered.
    uint8_t set_registered; ///< This bit MUST be set as 0, unless the user wants to set the registered bit as 1.

    struct registry_object_s *object;            ///< For internal use only, MUST NOT be accessed from application.
    struct registry_object_s *object_instance;   ///< For internal use only, MUST NOT be accessed from application.
    struct registry_object_s *resource;          ///< For internal use only, MUST NOT be accessed from application.
    struct registry_object_s *resource_instance; ///< For internal use only, MUST NOT be accessed from application.

} registry_listing_t;

#ifdef __cplusplus
}
#endif

#endif //LWM2M_TYPES_H
