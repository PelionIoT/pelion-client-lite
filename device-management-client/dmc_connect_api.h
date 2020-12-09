// ----------------------------------------------------------------------------
// Copyright 2019-2020 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#ifndef __DMC_CONNECT_API_H__
#define __DMC_CONNECT_API_H__

/*! \file dmc_connect_api.h
* \brief API for connecting Device Management Client to the backend service
*/

#include "lwm2m_interface.h"
#include "lwm2m_registry.h"

#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
#include "dmc_update_api.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Interface event codes reported to the observer through the `event_id`
 * field of the event.
 */
typedef enum {
    M2M_CLIENT_EVENT_SETUP_COMPLETED = 100,     ///< Internal client setup completed.
    M2M_CLIENT_EVENT_NETWORK_SETUP_COMPLETED    ///< Network setup completed.
} m2m_client_event_t;

/**
 * Structure holding endpoint information.
 */
typedef struct pdmc_endpoint_info_ {
    char endpoint_name[MAX_ALLOWED_STRING_LENGTH];
    char device_id[MAX_ALLOWED_STRING_LENGTH];
} pdmc_endpoint_info_s;

/***
 * The normal sequence of use:
 * -# pdmc_connect_init
 * -# lwm2m_interface_t* if = pdmc_connect_get_interface
 * -# registry_t* reg = &if.endpoint.registry
 * -# pdmc_connect_add_cloud_resource(reg, ...)
 * -# pdmc_connect_register
 * See also `lwm2m_registry.h` for relevant value modification functions.
**/

/**
* \brief Device Management Client connection initialization. This must be called before using other operations.
* \param event_handler_id An ID for the event handler receiving event notifications from client status changes.
*/
void pdmc_connect_init(uint8_t event_handler_id);

/**
* \brief Deinitialize Device Management Client.
*/
void pdmc_connect_deinit(void);

/**
* \brief Device Management Client registration. If necessary, initiates the internal update component and performs the bootstrap procedure automatically.
* \param iface Pointer to the network interface.
*/
void pdmc_connect_register(void* iface);

/**
* \brief Device Management Client updates register information to Device Management.
*/
void pdmc_connect_register_update(void);

/**
* \brief Deregister from Device Management.
*/
void pdmc_connect_close(void);

/**
* \brief Get `lwm2m_interface`. This interface has an endpoint containing a registry that is a necessary parameter for most
* `lwm2m_*` calls.
* \return pointer `lwm2m_interface_t`
*/
lwm2m_interface_t *pdmc_connect_get_interface(void);

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
/**
* \brief A helper function for adding Resources to Device Management (the Resources should be defined in `oma_lwm2m_object_defs.c`)
* \param registry A pointer to the registry (use `pdmc_connect_get_interface` after `pdmc_connect_init` to
* get the registry from the interface's endpoint.
* \param path The path to the Resource. This will be populated with parameters `object`, `object_instance` and `resource` given to this function call.
* \param object Refers to the Object level in an OMA Object like "object/x/x", for example `300/0/0`.
* \param object_instance Refers to the Object Instance level in an OMA Object like "x/object_instance/x", for example `300/1/0`.
* \param resource Refers to the Resource level in OMA Object like "x/x/resource", for example `300/1/3`.
* \param auto_observable Auto observable Resources are updated to the service side automatically.
* \param callback A `registry_callback_t` type of a callback that will be notified on changes in a Resource.
* \return `1` in success.
*/
int pdmc_connect_add_cloud_resource(registry_t *registry, registry_path_t *path,
                                        const uint16_t object, const uint16_t object_instance, const uint16_t resource,
                                        bool auto_observable, registry_callback_t callback);

/**
* \brief A helper function for adding Resource instances to Device Management (the Resources should be defined in `oma_lwm2m_object_defs.c`)
* \param registry A pointer to the registry (use `pdmc_connect_get_interface` after `pdmc_connect_init` to
* get the registry from the interface's endpoint.
* \param path The path to the Resource. This will be populated with parameters `object`, `object_instance` and `resource` given to this function call.
* \param object Refers to the Object level in an OMA Object like "object/x/x", for example `300/0/0`.
* \param object_instance Refers to the Object Instance level in an OMA Object like "x/object_instance/x", for example `300/1/0`.
* \param resource Refers to the Resource level in OMA Object like "x/x/resource", for example `300/1/3`.
* \param resource_instance Refers to the Resource instance level in OMA Object like "x/x/x/resource_instance", for example `300/1/3/4`.
* \param auto_observable Auto observable Resources are updated to the service side automatically.
* \param callback A `registry_callback_t` type of a callback that will be notified on changes in a Resource instances.
* \return `1` in success.
*/
int pdmc_connect_add_cloud_resource_instance(registry_t *registry, registry_path_t *path,
                                    const uint16_t object, const uint16_t object_instance, const uint16_t resource,
                                    const uint16_t resource_instance,
                                    bool auto_observable, registry_callback_t callback);
#endif // !MBED_CLOUD_CLIENT_DISABLE_REGISTRY

/**
* \brief Get information on a connected endpoint.
* \param endpoint_info After a successfull call, points to `pdmc_endpoint_info_s`.
* \return True in success, false in failure.
*/
bool pdmc_connect_endpoint_info(pdmc_endpoint_info_s *endpoint_info);

/**
* \brief Get endpoint name.
* Can be called before connecting, but must only be called after `pdmc_connect_init()`.
* \param endpoint_name Output buffer that on a succesful call will contain the endpoint name as a C string.
* \param size The size of the `endpoint_name` buffer. Any data that doesn't fit will be discarded.
* \return True in success, false in failure.
*/
bool pdmc_connect_get_endpoint_name(char *endpoint_name, size_t size);

/**
* \brief Get device id of a connected device.
* \param device_id Output buffer that on a succesful call will contain the device id as a C string.
* \param size The size of the `device_id` buffer. Any data that doesn't fit will be discarded.
* \return True in success, false in failure.
*/
bool pdmc_connect_get_device_id(char *device_id, size_t size);

/**
* \brief Pause Device Management Client's timed functionality and close network connection
* to Device Management. After a successful call, you can continue the operation
* by calling `resume()`.
*
* \note This operation does not deregister Device Management Client from Device Management.
* It closes the socket and removes the interface from the interface list.
*/
void pdmc_connect_pause(void);

/**
 * \brief Resume Device Management Client's timed functionality and network connection
 * to Device Management. Updates registration. Can be only called after
 * a successful call to `pause()`.
 *
 * \param iface A handler to the network interface.
 */
void pdmc_connect_resume(void *iface);

#ifdef __cplusplus
}
#endif

#endif // __DMC_CONNECT_API_H__

