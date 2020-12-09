/*
 * Copyright (c) 2018 ARM Limited. All rights reserved.
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
#ifndef LWM2M_INTERFACE_H
#define LWM2M_INTERFACE_H

#include "lwm2m_connection.h"
#include "lwm2m_constants.h"
#include "lwm2m_endpoint.h"
#include "lwm2m_registry.h"

/** \file lwm2m_interface.h
 *  \brief Client Lite internal LwM2M and Device Management state machine API.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define REREGISTRATION_INTERVAL 70 ///< Percents of end point lifetime, re-registration interval = endpoint lifetime * (REREGISTRATION_INTERVAL/100) s.
#define REREGISTRATION_UDP_QUEUE_LOW_INTERVAL 50 ///< Percents of endpoint lifetime when using UDP or QUEUE for lifetime value up to 300 seconds, re-registration interval = end point lifetime * (REREGISTRATION_UDP_QUEUE_INTERVAL/100) s.
#define REREGISTRATION_UDP_QUEUE_INTERMEDIATE_INTERVAL 60 ///< Percents of endpoint lifetime when using UDP or QUEUE for lifetime value up to 600 seconds, re-registration interval = end point lifetime * (REREGISTRATION_UDP_QUEUE_INTERVAL/100) s.
#define MAXIMUM_RECONNECTION_TIME_INTERVAL   10 ///< The maximum initial reconnection time interval in seconds.

#define MAX_RECONNECT_ATTEMPT   2 ///< Number of reconnection attempts before giving an error to upper layers.

#ifdef MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP_QUEUE
/**
 * \brief Callback function definition.
 *
 * \param Pointer to the observer.
 */
typedef void (*interface_callback_handler)(void *);
#endif // MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP_QUEUE

// TODO: map these back to M2MInterface::Error in wrapper

/**
 * Interface error codes that are reported to the observer in the `event_type` field of
 * the event if the `event_id` is `LWM2M_INTERFACE_OBSERVER_EVENT_ERROR`.
 */
typedef enum {
        LWM2M_INTERFACE_ERROR_NONE = 0,         ///< ErrorNone = 0
        LWM2M_INTERFACE_ERROR_ALREADY_EXISTS,   ///< AlreadyExists
        LWM2M_INTERFACE_ERROR_BOOTSTRAP_FAILED, ///< BootstrapFailed
        LWM2M_INTERFACE_ERROR_INVALID_PARAMETERS,   ///< InvalidParameters
        LWM2M_INTERFACE_ERROR_NOT_REGISTERED,       ///< NotRegistered
        LWM2M_INTERFACE_ERROR_TIMEOUT,              ///< Timeout
        LWM2M_INTERFACE_ERROR_NETWORK_ERROR,        ///< NetworkError
        LWM2M_INTERFACE_ERROR_RESPONSE_PARSE_FAILED,    ///< ResponseParseFailed
        LWM2M_INTERFACE_ERROR_UNKNOWN_ERROR,        ///< UnknownError
        LWM2M_INTERFACE_ERROR_MEMORY_FAIL,          ///< MemoryFail
        LWM2M_INTERFACE_ERROR_NOT_ALLOWED,          ///< NotAllowed
        LWM2M_INTERFACE_ERROR_SECURE_CONNECTION_FAILED, ///< SecureConnectionFailed
        LWM2M_INTERFACE_ERROR_CERTIFICATE_FAILED,   ///< CertificateFailed,
        LWM2M_INTERFACE_ERROR_PLATFORM_FAULT,       ///< PlatformFault,
        LWM2M_INTERFACE_ERROR_INTERNAL_FAILURE,     ///< InternalFailure,
        LWM2M_INTERFACE_ERROR_DNS_RESOLVING_FAILED, ///< DnsResolvingFailed

        LWM2M_INTERFACE_ERROR_UNREGISTRATION_FAILED ///< UnregistrationFailed
} lwm2m_interface_error_t;

/**
 * Interface event codes that are reported to the observer in the `event_id`
 * field of the event.
 */
typedef enum {
    LWM2M_INTERFACE_FIRST_EVENT_ID = 0,
    LWM2M_INTERFACE_OBSERVER_EVENT_ERROR = 1, ///< Error occurred, check the error code from `lwm2m_interface_error_t` for more details.
    LWM2M_INTERFACE_OBSERVER_EVENT_OBJECT_REGISTERED, ///< Client registration done.
    LWM2M_INTERFACE_OBSERVER_EVENT_OBJECT_UNREGISTERED, ///< Client unregistered.
    LWM2M_INTERFACE_OBSERVER_EVENT_REGISTRATION_UPDATED, ///< Client registration updated.
    LWM2M_INTERFACE_OBSERVER_EVENT_BOOTSTRAP_DONE, ///< Client bootstrap done.
    LWM2M_INTERFACE_OBSERVER_EVENT_VALUE_UPDATED, ///< Not used. TODO: Check if there is use for this code?
    LWM2M_INTERFACE_LAST_EVENT_ID
} lwm2m_interface_observer_event_t;
/**
 * Stack type used with client.
 * \note The client really only cares about IP version.
 */
typedef enum {
    LWM2M_INTERFACE_NETWORK_STACK_UNINITIALIZED = 0, ///< Not set.
    LWM2M_INTERFACE_NETWORK_STACK_LWIP_IPV4, ///< IPv4
    LWM2M_INTERFACE_NETWORK_STACK_LWIP_IPV6, ///< IPv6
    LWM2M_INTERFACE_NETWORK_STACK_RESERVED, ///< Reserved
    LWM2M_INTERFACE_NETWORK_STACK_NANOSTACK_IPV6, ///< IPv6
    LWM2M_INTERFACE_NETWORK_STACK_ATWINC_IPV4, ///< IPv4
    LWM2M_INTERFACE_NETWORK_STACK_UNKNOWN ///< ???
} lwm2m_interface_network_stack_t;


/**
 * \brief A unified container for holding socket address data across different platforms.
 */
typedef struct lwm2m_interface_socketaddress_s {
    lwm2m_interface_network_stack_t stack; ///< Stack type.
    void                        *address; ///< Pointer to the address.
    uint8_t                     length; ///< Length of the address. MUST be 4 or 16.
    uint16_t                    port; ///< TCP or UDP port number.
} lwm2m_interface_socketaddress_t;

/**
 * \brief Container for resolved address information.
 */
typedef struct lwm2m_interface_resolved_address_data_s {
    const lwm2m_interface_socketaddress_t    *address; ///< Resolved address.
} lwm2m_interface_resolved_address_data_t;

/**
 * \brief Container for received data.
 */
typedef struct lwm2m_interface_received_data_s {
    uint8_t                               *data; ///< Pointer to data received.
    uint16_t                               size; ///< Size of the data.
    const lwm2m_interface_socketaddress_t *address; ///< Source address information.
} lwm2m_interface_received_data_t;

/**
 * \brief Container for LwM2M registration security and lifetime information.
 */
typedef struct lwm2m_interface_update_register_data_s {
    uint16_t        security_instance; ///< Instance ID for security.
    uint32_t        lifetime; ///< Registration lifetime.
} lwm2m_interface_update_register_data_t;

/**
 * \brief Container for holding the LwM2M Security Object Instance ID.
 */
typedef struct lwm2m_interface_security_data_s {
    uint16_t        security_instance; ///< Instance ID for security.
} lwm2m_interface_security_data_t;

/**
 * \brief Common container type for data passed with internal events.
 */
typedef union _lwm2m_interface_event_data_u {
    lwm2m_interface_resolved_address_data_t resolved_address; ///< Resolved address.
    lwm2m_interface_received_data_t         received_data; ///< Received data address.
    lwm2m_interface_update_register_data_t  update_register_data; ///< Update register data.
    lwm2m_interface_security_data_t         security_data; ///< Security data.
} lwm2m_interface_event_data_u;

/**
 * \brief LwM2M server type.
 */
typedef enum {
    LWM2M_SERVER_TYPE_SERVER = 0, ///< Bootstrap server.
    LWM2M_SERVER_TYPE_BOOTSTRAP = 1 ///< LwM2M server.
} lwm2wm_interface_server_type_t;

/**
 * \brief Reconnection state.
 */
typedef enum {
    LWM2M_INTERFACE_RECONNECTION_STATE_NONE, ///< Not reconnecting
    LWM2M_INTERFACE_RECONNECTION_STATE_WITH_UPDATE, ///< Reconnecting using update register.
    LWM2M_INTERFACE_RECONNECTION_STATE_FULL_REGISTRATION, ///< Reconnecting with full register.
    LWM2M_INTERFACE_RECONNECTION_STATE_UNREGISTRATION ///< Try to reconnect to unregister.
} lwm2m_interface_reconnection_state_t;

/**
 ** \brief enum Defines the types of timer
 * that can be created for mbed Client.
 */
typedef enum {
    LWM2M_INTERFACE_TIMER_REGISTRATION          = 41, ///< Registration timer. TODO: Check if this is actually needed
    LWM2M_INTERFACE_TIMER_QUEUE_SLEEP           = 42, ///< Queue sleep timer.
    LWM2M_INTERFACE_TIMER_RETRY                 = 43, ///< Operation retry timer.
    LWM2M_INTERFACE_TIMER_BOOTSTRAP_FLOW        = 44, ///< Bootstrap timer.
    LWM2M_INTERFACE_TIMER_REGISTRATION_FLOW     = 45, ///< Registration timer.
    LWM2M_INTERFACE_TIMER_REREGISTRATION        = 46  ///< Update registration timer.
} lwm2m_interface_timer_id_t;


/**
 * \brief An enum defining the type of the security attribute
 * used by the Security Object.
 */
typedef enum {
    LWM2M_INTERFACE_SECURITY_MODE_PSK = 0, ///< Security mode PSK.
    LWM2M_INTERFACE_SECURITY_MODE_CERTIFICATE = 2, ///< Security mode certificate.
    LWM2M_INTERFACE_SECURITY_MODE_NO_SECURITY = 3 ///< Non-secure mode.
} lwm2m_interface_security_mode_t;


/**
 *  \brief Main data structure for Client Lite LwM2M Connectivity and Device Management state machine.
 */
typedef struct lwm2m_interface_s {

    int8_t                          event_handler_id; ///< ID for the interface event handler.

    // An observer needs to give us a tasklet ID and a pointer to their context.
    int8_t                          observer_id; ///< Event handler ID of the observer.

    uint16_t                        server_port; ///< LwM2M server port.
    // TODO: pass this to connection?
    uint16_t                        listen_port; ///< Local port.
    uint8_t                         current_state; ///< Interface state.

    // Note: next bool and enum variables were earlier packed to bitfields,
    // which saved ~8 bytes of RAM. But it also made binary ~174 bytes bigger on Cortex M0.
    // So this version is now a trade-off between ROM and RAM.

    uint8_t                         reconnect_attempt; ///< Number of reconnection attempts.
    uint8_t                         initial_reconnection_time; ///< Initial delay for reconnection in seconds.
    oma_lwm2m_binding_and_mode_t    binding_mode; ///< Connection mode.
    lwm2m_interface_reconnection_state_t reconnection_state; ///< Reconnection state.
    bool                            event_ignored; ///< Current event ignored if true.
    bool                            event_generated; ///< Event has been generated if true.
    bool                            is_registered; ///< True if registred
    bool                            reconnecting; ///< Reconnecting if true.
    bool                            retry_timer_expired; ///< Reconnection timer expired if true.
    bool                            bootstrapped; ///< Bootstrap done if true.
#ifdef MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP_QUEUE
    bool                            queue_mode_timer_ongoing; ///< Queue mode timer running if true.
#endif //#ifdef MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP_QUEUE
    bool                            unregister_ongoing; ///< Unregistration in progress if true.

    // These variables are here in purpose despite wasting a bit of RAM for alignment,
    // as on the Cortex M0 this produces much smaller code.

#ifdef MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP_QUEUE
    interface_callback_handler      callback_handler; ///< Pointer to a callback handler.
#endif //MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP_QUEUE

#ifndef DISABLE_ERROR_DESCRIPTION
    // The DISABLE_ERROR_DESCRIPTION macro will reduce the flash usage by ~1800 bytes.
    const char                      *error_description; ///< Pointer to textual error description in null-terminated string format.
#endif
    void                            *observer; ///< Set to `data_ptr` field of event sent to observer.

    void                            *network_interface; ///< Pointer to network interface.

    lwm2m_interface_event_data_u    *event_data; ///< Pointer to event data.

    uint32_t                        reconnection_time; ///< Delay for reconnecting in seconds.

    // Preallocated event for observer communication.
    arm_event_storage_t             observer_event; ///< Preallocated event that can be sent to observer.

    // Even though we provide a function API, we break the direct chain through event loop.
    arm_event_storage_t             external_event; ///< Preallocated incoming event.

    endpoint_t                      endpoint; ///< Endpoint data.

    connection_t                    connection; ///< Connection data.

    lwm2m_interface_event_data_u    external_event_data; ///< Data for the incoming event.

#ifdef PROTOMAN_SECURITY_ENABLE_PSK
    uint8_t                         psk[MAX_ALLOWED_PSK_SIZE];
    uint8_t                         psk_size;
    uint8_t                         psk_id[MAX_ALLOWED_PSK_ID_SIZE];
    uint8_t                         psk_id_size;
#endif //PROTOMAN_SECURITY_ENABLE_PSK

    char                            server_ip_address[MAX_ALLOWED_IP_STRING_LENGTH]; ///< Server address in null terminated string format.

} lwm2m_interface_t;


/**
 * \brief Constructor that intializes the context.
 * \param interface Context structure to intialize.
 * \param listen_port Listening port for the endpoint, default is 8000.
 * \param mode Binding mode of the client, default is UDP
 * \param stack Network stack to be used for connection, default is LwIP_IPv4.
 */
void lwm2m_interface_init(lwm2m_interface_t *interface,
                          const uint16_t listen_port,
                          oma_lwm2m_binding_and_mode_t mode,
                          lwm2m_interface_network_stack_t stack);

/**
 * \brief Setup for handling all memory allocation.
 * \param interface Context structure.
 * \param observer_id Tasklet receiving the observation events.
 * \param observer Observer to pass the event callbacks for various
 * interface operations.
 * \param endpoint_name Endpoint name of the client.
 * \param endpoint_type Endpoint type of the client.
 * \param life_time Lifetime of the client in seconds.
 * \param domain Domain of the client.
 * \param context_address Context address, default is empty.
 * \return True if setup is successful, else false.
 */
bool lwm2m_interface_setup(lwm2m_interface_t *interface,
                            int8_t observer_id,
                            void *observer,
                            const char *endpoint_type,
                            const int32_t life_time,
                            const char *context_address);

/**
 * \brief Destroy and clean up interface struct.
 *
 * \param interface Context structure.
 */
void lwm2m_interface_clean(lwm2m_interface_t *interface);

/**
 * \brief Close network connection and stop interface timers.
 * \note The interface can be started again using `lwm2m_interface_continue()`
 *       or it can be destroyed using `lwm2m_interface_clean()`.
 *
 * \param interface Context structure.
 */
void lwm2m_interface_stop(lwm2m_interface_t *interface);

void lwm2m_interface_pause(lwm2m_interface_t *interface);

/**
 * \brief Resume operation after `lwm2m_interface_stop()`.
 *
 * \param interface Context structure.
 *
 * \return True on success, false on failure.
 */
bool lwm2m_interface_resume(lwm2m_interface_t *interface);

/**
 * \brief Initiate bootstrapping of the client with the provided bootstrap
 * server information.
 * \param interface Context structure.
 */
void lwm2m_interface_bootstrap(lwm2m_interface_t *interface);

/**
 * \brief Cancel ongoing bootstrapping operation of the client. If the client has
 * already bootstrapped successfully, this function deletes the existing
 * bootstrap information from the client.
 * \param interface Context structure.
 */
void lwm2m_interface_cancel_bootstrap(lwm2m_interface_t *interface);

/**
 * \brief Initiate registration of the provided security Object to the
 * corresponding LwM2M server.
 * \param interface Context structure.
 * \param security_instance Security object containing the information
 * required for registering to the LwM2M server.
 * \note If the client wants to register to multiple LwM2M servers, it must call
 * this function once for each LwM2M server Object separately.
 */
void lwm2m_interface_register_object(lwm2m_interface_t *interface, uint16_t security_instance);

/**
 * \brief Update or refresh the client's registration on the LwM2M
 * server.
 * \param interface Context structure.
 * \param security_instance Security Object from which the device Object
 * needs to update registration. If there is only one LwM2M server registered,
 * this parameter can be NULL.
 * \param lifetime Lifetime for the endpoint client in seconds.
 */
void lwm2m_interface_update_registration(lwm2m_interface_t *interface, uint16_t security_instance, const uint32_t lifetime);

/**
 * \brief Unregister the registered object from the LwM2M server.
 * \param interface Context structure.
 */
void lwm2m_interface_unregister_object(lwm2m_interface_t *interface);
#ifdef MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP_QUEUE
/**
 * \brief Set the function to be called, indicating the client
 * is going to sleep when the binding mode is selected with Queue mode.
 * \param interface Context structure.
 * \param cb Function pointer to be called when the client
 * goes to sleep.
 */
void lwm2m_interface_set_queue_sleep_handler(lwm2m_interface_t *interface, interface_callback_handler cb);
#endif //MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP_QUEUE

/**
 * \brief Set the network interface handler used by client to connect
 * to a network over IP.
 * \param interface Context structure.
 * \param handler Network interface handler used by client to connect.
 *  This API is optional but provides a mechanism for different platforms to
 * manage the usage of underlying network interface.
 */
void lwm2m_interface_set_platform_network_handler(lwm2m_interface_t *interface, void *handler);

/**
 * \brief Set the function callback to be called by client for
 * fetching a random number from application to ensure strong entropy.
 * \param interface Context structure.
 * \param callback Function pointer to be called by client
 * while performing a secure handshake.
 * Function signature should be `uint32_t (*random_number_callback)(void);`.
 */
void lwm2m_interface_set_random_number_callback(lwm2m_interface_t *interface, random_number_cb callback);

#ifndef PROTOMAN_OFFLOAD_TLS
/**
 * \brief Set the function callback to be called by client for
 * providing an entropy source from application to ensure strong entropy.
 * \param interface Context structure.
 * \param callback Function pointer to be called by client
 * while performing a secure handshake.
 *
 * If using `mbed-client-mbedtls`, the function signature should be
 * `int (*mbedtls_entropy_f_source_ptr)(void *data, unsigned char *output,
 *                                     size_t len, size_t *olen);`.
 */
void lwm2m_interface_set_entropy_callback(lwm2m_interface_t *interface, entropy_cb callback);
#endif // PROTOMAN_OFFLOAD_TLS

/**
 * \brief Update the endpoint name.
 * \param interface Context structure.
 * \param name New endpoint name.
 */
void lwm2m_interface_update_endpoint(lwm2m_interface_t *interface, const char *name);

/**
 * \brief Update the domain name.
 * \param interface Context structure.
 * \param domain New domain name.
 */
void lwm2m_interface_update_domain(lwm2m_interface_t *interface, const char *domain);

/**
 * \brief Return the internal endpoint name
 * \param interface Context structure.
 * \return Internal endpoint name.
 */
const char *lwm2m_interface_internal_endpoint_name_str(const lwm2m_interface_t *interface);

/**
 * \brief Return error description for the latest error code.
 * \param interface Context structure.
 * \return Error description string.
 */
const char *lwm2m_interface_error_description(const lwm2m_interface_t *interface);

/**
 * \brief Sends CoAP GET request to the server.
 * \param interface Context structure.
 * \param type Download type.
 * \param uri URI path to the data.
 * \param offset Data offset.
 * \param async In async mode, the application must call this API again with the updated offset.
 *        If set to false, the client will automatically download the whole package.
 * \param data_cb Callback triggered once there is data available.
 * \param error_cb Callback triggered in case of an error.
 * \param context Pointer passed as a parameter when calling the callback functions.
 */
void lwm2m_interface_get_data_request(lwm2m_interface_t *interface,
                                      DownloadType type,
                                        const char *uri,
                                        const size_t offset,
                                        const bool async,
                                        get_data_cb data_cb,
                                        get_data_error_cb error_cb,
                                        void *context);

/**
 * \brief Called every time when data has been sent.
 * \param interface Context structure.
 */
void lwm2m_interface_data_sent(lwm2m_interface_t *interface);

/**
 * \brief Set custom URI query paramaters used in LwM2M registration.
 * \param interface Context structure.
 * \param uri_query_params URI query parameters. Parameters must be in key-value format:
 * "a=100&b=200". Maximum length can be up to 64 bytes.
 * \return False if maximum length exceeded, otherwise True.
 */
bool lwm2m_interface_set_uri_query_parameters(lwm2m_interface_t *interface, const char *uri_query_params);

#ifdef MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP_QUEUE
/**
 * \brief Enable or disable queue mode.
 * \param interface Context structure.
 * \return True if queue mode, otherwise false.
 */
bool lwm2m_interface_queue_mode(const lwm2m_interface_t *interface);
#endif

/**
 * \brief Try to send register update message right away.
 *
 * \note This function must not be called before the client has been registered.
 * \note After a successful call, the update register can still fail later.
 *
 * \param interface Context structure.
 *
 * \return true Update register successfully started.
 * \return false Update register could not be started.
 */
bool lwm2m_interface_send_update_registration(lwm2m_interface_t *interface);

#ifdef __cplusplus
}
#endif


#endif //LWM2M_INTERFACE_H
