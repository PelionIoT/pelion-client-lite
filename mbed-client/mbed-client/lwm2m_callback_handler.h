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

#ifndef LWM2M_CALLBACK_HANDLER_H
#define LWM2M_CALLBACK_HANDLER_H

/*! \file lwm2m_callback_handler.h
 *  \brief Client Lite internal LwM2M Object registry callback handler API.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "lwm2m_registry.h"

#define CALLBACK_HANDLER_EVENT_INIT 0 ///< Callback handler init event
#define CALLBACK_HANDLER_EVENT_ID 40 ///< Callback handler event ID

/**
 * \brief Client Lite internal registry callbacks pass data using this struct.
 */
typedef struct callback_data_s {
    registry_callback_token_t cb_token;     //!< Token for distinguishing callbacks from each other.
    registry_object_value_t cb_value;       //!< Registry item value.
    // XXX: meld this into the this same struct, no need to allocate it always separately.
    registry_data_opaque_t* cb_opaque_data; //!< A callback can also contain opaque data, not originating from registry.
    registry_path_t path;                   //!< Path (LwM2M Resource ID) to the registry item .
} callback_data_t;

/**
 * \brief Initialize the callback handler.
 *
 * \param registry The registry that is associated with this callback handler.
 */
void callback_handler_init(registry_t *registry);

/**
 * \brief Send callback handler event.
 *
 * \param data Value of this pointer is set to field `data_ptr` of the event.
 * \param type Event type.
 */
void callback_handler_send_event(void *data, uint8_t type);

#ifdef __cplusplus
}
#endif

#endif //LWM2M_CALLBACK_HANDLER_H
