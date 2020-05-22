// ----------------------------------------------------------------------------
// Copyright 2019 ARM Ltd.
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


#ifdef MBED_CLIENT_USER_CONFIG_FILE
#include MBED_CLIENT_USER_CONFIG_FILE
#endif

#ifdef MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#include MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#endif

#ifndef MBED_CONF_MBED_CLIENT_ENABLE_CPP_API

#define PDMC_CONNECT_STARTUP_EVENT_TYPE 6

#include "mbed-trace/mbed_trace.h"
#include "mbed-client/lwm2m_interface.h"
#include "mbed-client/lwm2m_storage.h"
#include "device-management-client/lwm2m_registry_handler.h"
#include "device-management-client/dmc_connect_api.h"
#include "device-management-client/dmc_update_api.h"
#include "eventOS_event.h"
#include "platform/reboot.h"

#include <stdio.h>
#include <assert.h>

#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
#include "update-client-hub/update_client_hub.h"
#include "update-client-lwm2m/lwm2m-source.h"
#include "update-client-lwm2m/update_lwm2m_monitor.h"
#include "UpdateClientResources.h"

/* To be removed once update storage is defined in user config file.
   Default to filesystem in the meantime.
*/
#ifndef MBED_CLOUD_CLIENT_UPDATE_STORAGE
#define MBED_CLOUD_CLIENT_UPDATE_STORAGE ARM_UCP_FLASHIAP
#endif

#ifdef MBED_CLOUD_CLIENT_UPDATE_STORAGE
extern ARM_UC_PAAL_UPDATE MBED_CLOUD_CLIENT_UPDATE_STORAGE;
#else
#error Update client storage must be defined in user configuration file
#endif

static void update_client_initialization();
static bool schedule_update_event(arm_event_storage_t *ev, void *cb, uintptr_t param);
static bool update_client_initialized = false;
#endif // MBED_CLOUD_CLIENT_SUPPORT_UPDATE

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE
#include "fota/fota.h"

static void fota_update_init(void);
#endif

#define TRACE_GROUP "pdmc"

typedef enum {  // note these are encapsulated to u8 type, so remember limit 255 if more events are created
    APPLICATION_EVENT_HANDLER_UPDATE_INIT = 200,
    APPLICATION_EVENT_START_BOOTSTRAP,
    APPLICATION_EVENT_REGISTER,
    APPLICATION_EVENT_UNREGISTER,
    APPLICATION_EVENT_REGISTRATION_UPDATE,
    APPLICATION_EVENT_PAUSE,
    APPLICATION_EVENT_RESUME,
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
    APPLICATION_EVENT_UPDATE_CLIENT_PROCESS_QUEUE
#endif
} application_event_t;

extern const char           MBED_CLOUD_DEV_MANUFACTURER[];
extern const char           MBED_CLOUD_DEV_MODEL_NUMBER[];
extern const char           MBED_CLOUD_DEV_SERIAL_NUMBER[];

static int8_t               internal_event_handler_id;
static int8_t               app_event_handler_id;
static lwm2m_interface_t    interface;
static arm_event_storage_t  user_allocated_event;
static bool                 event_in_flight;

static void pdmc_connect_event_handler(arm_event_s *event);
static void print_registry_status_code(registry_status_t status);
static void send_event(uint8_t event_type);
static void forward_event_to_external_interface(arm_event_t *orig_event);
static oma_lwm2m_binding_and_mode_t get_binding_mode(void);
static registry_status_t reboot_callback(registry_callback_type_t type,
                                         const registry_path_t *path,
                                         const registry_callback_token_t *token,
                                         const registry_object_value_t *value,
                                         const registry_notification_status_t notification_status,
                                         registry_t *registry);

/**
* \brief initialises update
*/
void pdmc_connect_init_update(void);

/**
* \brief setups default device objects
*/
void simple_m2m_create_device_object(void);

static void pdmc_connect_event_handler(arm_event_t *event)
{
    event_in_flight = false;

    if (event->event_type == PDMC_CONNECT_STARTUP_EVENT_TYPE && event->event_id == 0) {
        return;
    }

    if (event->event_id > LWM2M_INTERFACE_FIRST_EVENT_ID &&
            event->event_id < LWM2M_INTERFACE_LAST_EVENT_ID) {
        if (event->event_id == LWM2M_INTERFACE_OBSERVER_EVENT_BOOTSTRAP_DONE) {
            tr_debug("pdmc_connect_event_handler - LWM2M_INTERFACE_OBSERVER_EVENT_BOOTSTRAP_DONE");
            pdmc_connect_init_update();  // moves to the registration
        }

        forward_event_to_external_interface(event);  // just inform also application of these events
        return;  // rest are c_api_simple_m2m events
    }

    switch (event->event_id) {
        case APPLICATION_EVENT_HANDLER_UPDATE_INIT:
#if MBED_CLOUD_CLIENT_FOTA_ENABLE
            fota_update_init();
#endif
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
            if (!update_client_initialized) {
                update_client_initialization();
                break;
            }
#endif // MBED_CLOUD_CLIENT_SUPPORT_UPDATE
            // we should make state machine progress even if update is not enabled
            send_event(APPLICATION_EVENT_REGISTER);
            break;

        case APPLICATION_EVENT_START_BOOTSTRAP:
             tr_debug("application_event_handler() APPLICATION_EVENT_START_BOOTSTRAP");
            lwm2m_interface_bootstrap(&interface);
            break;
        case APPLICATION_EVENT_UNREGISTER:
            lwm2m_interface_unregister_object(&interface);
            break;
        case APPLICATION_EVENT_REGISTRATION_UPDATE:
            endpoint_update_registration(&interface.endpoint);
            break;
        case APPLICATION_EVENT_REGISTER:
            lwm2m_interface_register_object(&interface, 0);
            break;
        case APPLICATION_EVENT_PAUSE:
#ifdef MBED_CONF_CLOUD_CLIENT_USE_SOFT_PAUSE_RESUME
            // The "soft pause" will not cause teardown of mbedtls layer, which allows one
            // to just perform a socket re-establishment and continue using the DTLS session
            // as-is, without the heavy handshake process.
            lwm2m_interface_pause(&interface);
#else
            lwm2m_interface_stop(&interface);
#endif
            break;
        case APPLICATION_EVENT_RESUME:
            lwm2m_interface_resume(&interface);
            break;

#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
        case APPLICATION_EVENT_UPDATE_CLIENT_PROCESS_QUEUE:
            ARM_UC_ProcessElement(event);
            break;
#endif
        default:
            tr_error("pdmc_connect_event_handler - unhandled event: %" PRId8 " sender %x", event->event_id, event->sender);
            break;
    }
}

static void print_registry_status_code(registry_status_t status)
{
#if MBED_CONF_MBED_TRACE_ENABLE
    const char *status_str = "Unknown status";
    if (status != REGISTRY_STATUS_OK) {
        switch (status) {
            case REGISTRY_STATUS_NO_DATA:
                status_str = "There is no date to be read";
                break;
            case REGISTRY_STATUS_OK:
                status_str = "No errors";
                break;
            case REGISTRY_STATUS_NOT_FOUND:
                status_str = "Resource not found";
                break;
            case REGISTRY_STATUS_NO_MEMORY:
                status_str = "Out of memory";
                break;
            case REGISTRY_STATUS_INVALID_INPUT:
                status_str = "Invalid input parameter or data";
                break;
            case REGISTRY_STATUS_ALREADY_EXISTS:
                status_str = "Resource already created";
                break;
            default:
                break;
        }
        tr_error("status: (%d) %s", status, status_str);
    }
#else
#endif
}

static registry_status_t reboot_callback(registry_callback_type_t type,
                                        const registry_path_t *path,
                                        const registry_callback_token_t *token,
                                        const registry_object_value_t *value,
                                        const registry_notification_status_t notification_status,
                                        registry_t *registry);

void simple_m2m_create_optional_default_objects(void)
{
    registry_status_t ret;
    registry_path_t path;
    registry_t *registry = &interface.endpoint.registry;

    // Manufacturer  // problematic if these are set here as easy setting set by app get overwritten
    pdmc_connect_add_cloud_resource(registry, &path, 3, 0, 0, true, NULL);
    ret = registry_set_value_string(registry, &path, (char *)MBED_CLOUD_DEV_MANUFACTURER, false);
    print_registry_status_code(ret);
    ret = registry_set_resource_value_to_reg_msg(registry, &path, true);
    print_registry_status_code(ret);

    // Model Number
    pdmc_connect_add_cloud_resource(registry, &path, 3, 0, 1, true, NULL);
    ret = registry_set_value_string(registry, &path, (char *)MBED_CLOUD_DEV_MODEL_NUMBER, false);
    print_registry_status_code(ret);
    ret = registry_set_resource_value_to_reg_msg(registry, &path, true);
    print_registry_status_code(ret);

    // Serial Number
    pdmc_connect_add_cloud_resource(registry, &path, 3, 0, 2, true, NULL);
    ret = registry_set_value_string(registry, &path, (char*)MBED_CLOUD_DEV_SERIAL_NUMBER, false);
    print_registry_status_code(ret);
    ret = registry_set_resource_value_to_reg_msg(registry, &path, true);
    print_registry_status_code(ret);
}

void simple_m2m_create_device_object(void)
{
    registry_status_t ret;
    registry_path_t path;
    registry_t *registry = &interface.endpoint.registry;

    // Reboot
    pdmc_connect_add_cloud_resource(registry, &path, 3, 0, 4, true, reboot_callback);  // created by default by default by cpp device class

    // none type can't be set to reg msg, fixed by removing assert still not worky, additionally test cases assume that delete to these fails with 400 or 405 not 404 as now happens
    ret = registry_set_resource_value_to_reg_msg(registry, &path, true);

    // Error Code
    registry_set_path(&path, 3, 0, 11, 0, REGISTRY_PATH_RESOURCE_INSTANCE);   // created by default by default by cpp device class
    print_registry_status_code(ret);
    ret = registry_set_value_int(registry, &path, 0);
    print_registry_status_code(ret);
    ret = registry_set_auto_observable_parameter(registry, &path, true);
    print_registry_status_code(ret);

    // Supported Binding and Modes
    pdmc_connect_add_cloud_resource(registry, &path, 3, 0, 16, true, NULL);    // created by default by default by cpp device class
    ret = registry_set_value_string(registry, &path, (char *)BINDING_MODE_UDP, false);
    print_registry_status_code(ret);
}

// todo this should likely be in application side.
static registry_status_t reboot_callback(registry_callback_type_t type,
                                         const registry_path_t *path,
                                         const registry_callback_token_t *token,
                                         const registry_object_value_t *value,
                                         const registry_notification_status_t notification_status,
                                         registry_t *registry)
{
    if (notification_status == NOTIFICATION_STATUS_IGNORE) {
        // This status means we've just received the POST request.
        // We need to send response here and wait for it to be delivered before actually rebooting, to avoid
        // leaving server 'hanging', waiting for the response.
        send_final_response(path, &(pdmc_connect_get_interface()->endpoint), token->token, token->token_size, COAP_MSG_CODE_RESPONSE_CHANGED, true);
    } else if (notification_status == NOTIFICATION_STATUS_DELIVERED || notification_status == NOTIFICATION_STATUS_SEND_FAILED) {
        // Execute response has gone through and has been acknowledged, or sending the response has failed.
        // Either way, the correct result is to reboot the device.
        mbed_client_default_reboot();
    }
    return REGISTRY_STATUS_OK;
}

static oma_lwm2m_binding_and_mode_t get_binding_mode(void)
{
#ifdef MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP
    return BINDING_MODE_U;
#endif
#ifdef MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP_QUEUE
    return BINDING_MODE_Q;
#endif
#if defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP) || defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE)
    #ifdef MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP
        return BINDING_MODE_T;
    #endif
    #ifdef MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE
        return BINDING_MODE_T_Q;
    #endif
#endif
}

static void send_event(uint8_t event_type)
{
    if (event_in_flight) {
        tr_info("send_event - event already in queue");
        return;
    }

    user_allocated_event.data.data_ptr = NULL;
    user_allocated_event.data.event_data = 0;
    user_allocated_event.data.sender = 0;
    user_allocated_event.data.event_type = 0;
    user_allocated_event.data.receiver = internal_event_handler_id;
    user_allocated_event.data.event_id = event_type;
    user_allocated_event.data.priority = ARM_LIB_LOW_PRIORITY_EVENT;

    eventOS_event_send_user_allocated(&user_allocated_event);
    event_in_flight = true;
}

static void forward_event_to_external_interface(arm_event_t *orig_event)
{
    orig_event->receiver = app_event_handler_id;
    eventOS_event_send(orig_event);
}

lwm2m_interface_t *pdmc_connect_get_interface(void)
{
    return &interface;
}

void pdmc_connect_init(uint8_t event_handler_id)
{
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
    update_client_initialized = false;
#endif

    event_in_flight = false;

    internal_event_handler_id = eventOS_event_handler_create(pdmc_connect_event_handler,
                                                             PDMC_CONNECT_STARTUP_EVENT_TYPE);
    if (internal_event_handler_id < 0) {
        tr_error("pdmc_connect_init - failed to create event handler\n");
        return;
    }

    app_event_handler_id = event_handler_id;

    lwm2m_interface_init(&interface, 0, get_binding_mode(), LWM2M_INTERFACE_NETWORK_STACK_UNINITIALIZED /*this parameter is not used*/);

    bool result = lwm2m_interface_setup(&interface, internal_event_handler_id, &interface,
                                        MBED_CLOUD_CLIENT_ENDPOINT_TYPE, MBED_CLOUD_CLIENT_LIFETIME, NULL);
    assert(result);
    (void) result;

    arm_event_t evt = {0};
    evt.receiver = app_event_handler_id;
    evt.event_id = M2M_CLIENT_EVENT_SETUP_COMPLETED;
    evt.priority = ARM_LIB_LOW_PRIORITY_EVENT;

    if (eventOS_event_send(&evt) < 0) {
        tr_error("pdmc_connect_init - failed to send event");
        assert(false);
    }

    simple_m2m_create_device_object();  // moved to end of setup so that these can be changed by app
    simple_m2m_create_optional_default_objects();  // init manufactor modelnumber and serial
}

void pdmc_connect_deinit(void)
{
    eventOS_cancel(&user_allocated_event);
    lwm2m_interface_clean(&interface);
}

void pdmc_connect_register(void *iface)
{
    lwm2m_interface_set_platform_network_handler(&interface, iface);

    if (storage_registration_credentials_available()) {
        pdmc_connect_init_update();
    } else {
        send_event(APPLICATION_EVENT_START_BOOTSTRAP);
    }
}

void pdmc_connect_init_update(void)
{
    send_event(APPLICATION_EVENT_HANDLER_UPDATE_INIT);
}

void pdmc_connect_close(void)
{
    send_event(APPLICATION_EVENT_UNREGISTER);
}

void pdmc_connect_register_update(void)
{
    send_event(APPLICATION_EVENT_REGISTRATION_UPDATE);
}

void pdmc_connect_pause(void)
{
    send_event(APPLICATION_EVENT_PAUSE);
}

void pdmc_connect_resume(void *iface)
{
    lwm2m_interface_set_platform_network_handler(&interface, iface);
    send_event(APPLICATION_EVENT_RESUME);
}

int pdmc_connect_add_cloud_resource(registry_t *registry, registry_path_t *path,
                                    const uint16_t object, const uint16_t object_instance, const uint16_t resource,
                                    bool auto_observable, registry_callback_t callback)
{
    registry_status_t ret;

    registry_set_path(path, object, object_instance, resource, 0, REGISTRY_PATH_RESOURCE);

    ret = registry_set_auto_observable_parameter(registry, path, auto_observable);

    if (callback && ret == REGISTRY_STATUS_OK) {
        ret = registry_set_callback(registry, path, callback);
        print_registry_status_code(ret);
    }

    return (ret == REGISTRY_STATUS_OK);
}

bool pdmc_connect_endpoint_info(pdmc_endpoint_info_s *endpoint_info)
{
    int32_t size = (sizeof(endpoint_info->endpoint_name)-1);
    char *name_end;

    name_end = (char*)storage_read_endpoint_name(endpoint_info->endpoint_name, &size, true);
    if (!name_end || name_end == endpoint_info->endpoint_name) {
        return false;
    }

    *name_end = '\0';

    size = (sizeof(endpoint_info->device_id)-1);
    name_end = (char*)storage_read_internal_endpoint_name(endpoint_info->device_id, &size, false);
    if (!name_end || name_end == endpoint_info->device_id) {
        return false;
    }

    *name_end = '\0';

    return true;
}

#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
void pdmc_connect_update_set_authorize_handler(void (*authorize_handler)(int32_t request, uint64_t priority))
{
    ARM_UC_SetAuthorizePriorityHandler(authorize_handler);
}

void pdmc_connect_update_set_error_handler(void (*error_handler)(int32_t error))
{
    ARM_UC_HUB_AddErrorCallback(error_handler);
}

void pdmc_connect_update_set_progress_handler(void (*progress_handler)(uint32_t progress, uint32_t total))
{
    ARM_UC_SetProgressHandler(progress_handler);
}

static void update_client_initialization(void)
{
    tr_info("update_client_initialization");

    // Init FOTA if it's enabled

    ARM_UCS_LWM2M_SOURCE_endpoint_set(&interface.endpoint);

    /* Register sources */
    static const ARM_UPDATE_SOURCE* sources[1];
    sources[0] = ARM_UCS_LWM2M_SOURCE_source_get();

    ARM_UC_HUB_SetSources(sources, sizeof(sources)/sizeof(ARM_UPDATE_SOURCE*));

    /* Register sink for telemetry */
    ARM_UC_HUB_AddMonitor(get_update_lwm2m_monitor());

    /* Link internal queue with external scheduler.
       The callback handler is called whenever a task is posted to
       an empty queue. This will trigger the queue to be processed.
    */
    ARM_UC_HUB_AddNotificationHandler(schedule_update_event);

#ifdef MBED_CLOUD_CLIENT_UPDATE_STORAGE
    /* Set implementation for storing firmware */
    ARM_UC_HUB_SetStorage(&MBED_CLOUD_CLIENT_UPDATE_STORAGE);
#endif

#ifdef MBED_CLOUD_DEV_UPDATE_PSK
    /* Add pre shared key */
    ARM_UC_AddPreSharedKey(arm_uc_default_psk, arm_uc_default_psk_bits);
#endif

    ARM_UC_HUB_Initialize();

    update_client_initialized = true;

    send_event(APPLICATION_EVENT_REGISTER);
}

static void init_update_event(arm_event_s *ev, void *cb, uintptr_t param)
{
    ev->receiver = internal_event_handler_id;
    ev->sender = 0;
    ev->event_type = 0;
    ev->event_id = APPLICATION_EVENT_UPDATE_CLIENT_PROCESS_QUEUE;
    ev->data_ptr = cb;
    ev->priority = ARM_LIB_LOW_PRIORITY_EVENT;
    ev->event_data = param;
}

static bool schedule_update_event(arm_event_storage_t *ev, void *cb, uintptr_t param)
{
    if (ev == NULL) {
        tr_info("schedule_update_event - event is null!");
        return false;
    }

    init_update_event(&ev->data, cb, param);
    eventOS_event_send_user_allocated(ev);
    return true;
}

#endif // MBED_CLOUD_CLIENT_SUPPORT_UPDATE

#if MBED_CLOUD_CLIENT_FOTA_ENABLE
static void fota_update_init(void)
{
    // Init FOTA if it's enabled
    int fota_status = fota_init(&interface.endpoint);
    assert(!fota_status);
    (void) fota_status;
}
#endif

#endif // MBED_CONF_MBED_CLIENT_ENABLE_CPP_API
