// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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


#ifndef __MBED_CLOUD_CLIENT_H__
#define __MBED_CLOUD_CLIENT_H__
#ifdef MBED_CONF_MBED_CLIENT_ENABLE_CPP_API
#include "include/ServiceClient.h"
#include "MbedCloudClientConfig.h"
#include "mbed-client/m2mcorememory.h"

/*! \file MbedCloudClient.h
 *  \brief Definition of the MbedCloudClient and MbedCloudClientCallback classes.
 */

class M2MInterface;
/*! \class MbedCloudClientCallback
 * \brief A callback class for informing updated Object and Resource values from the
 * LwM2M server to the user of the MbedCloudClient class. The user MUST instantiate the
 * class derived out of this and pass the object to `MbedCloudClient::set_update_callback()`.
 */
class MbedCloudClientCallback {

public:

    /**
    * \brief A callback indicating that the value of the Resource object is updated
    *  by the LwM2M server.
    * \param base The object whose value is updated.
    * \param type The type of the object.
    */
    virtual void value_updated(M2MBase *base, M2MBase::BaseType type) = 0;
};


/*! \class MbedCloudClient
 *  \brief This class provides an interface for handling all Client Interface operations
 *  including device provisioning, identity setup, device resource management defined in the OMA
 *  LwM2M specifications, and updating firmware.
 *  Device resource management includes bootstrapping, Client registration, device management and
 *  service enablement, and information reporting.
 */
class MbedCloudClient : public ServiceClientCallback,
                        public M2MCoreMemory {

public:

    /**
     * \brief An enum defining different errors
     * that can occur during various Client operations.
     */
    typedef enum {
        ConnectErrorNone                        = 0x0, // Range reserved for Connector Error from 0x30 - 0x3FF
        ConnectAlreadyExists,
        ConnectBootstrapFailed,
        ConnectInvalidParameters,
        ConnectNotRegistered,
        ConnectTimeout,
        ConnectNetworkError,
        ConnectResponseParseFailed,
        ConnectUnknownError,
        ConnectMemoryConnectFail,
        ConnectNotAllowed,
        ConnectSecureConnectionFailed,
        ConnectDnsResolvingFailed,
        ConnectorFailedToStoreCredentials,
        ConnectorFailedToReadCredentials,
        ConnectorInvalidCredentials,
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
        UpdateWarningNoActionRequired           = UpdateClient::WarningBase, // Range reserved for Update Error from 0x0400 - 0x04FF
        UpdateWarningCertificateNotFound        = UpdateClient::WarningCertificateNotFound,
        UpdateWarningIdentityNotFound           = UpdateClient::WarningIdentityNotFound,
        UpdateWarningCertificateInvalid         = UpdateClient::WarningCertificateInvalid,
        UpdateWarningSignatureInvalid           = UpdateClient::WarningSignatureInvalid,
        UpdateWarningBadKeyTable                = UpdateClient::WarningBadKeyTable,
        UpdateWarningVendorMismatch             = UpdateClient::WarningVendorMismatch,
        UpdateWarningClassMismatch              = UpdateClient::WarningClassMismatch,
        UpdateWarningDeviceMismatch             = UpdateClient::WarningDeviceMismatch,
        UpdateWarningURINotFound                = UpdateClient::WarningURINotFound,
        UpdateWarningRollbackProtection         = UpdateClient::WarningRollbackProtection,
        UpdateWarningAuthorizationRejected      = UpdateClient::WarningAuthorizationRejected,
        UpdateWarningAuthorizationUnavailable   = UpdateClient::WarningAuthorizationUnavailable,
        UpdateWarningUnknown                    = UpdateClient::WarningUnknown,
        UpdateErrorUserActionRequired           = UpdateClient::ErrorBase,
        UpdateErrorWriteToStorage               = UpdateClient::ErrorWriteToStorage,
        UpdateErrorInvalidHash                  = UpdateClient::ErrorInvalidHash,
        UpdateErrorConnection                   = UpdateClient::ErrorConnection,
        UpdateFatalRebootRequired
#endif
    }Error;

#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
    /**
     * \brief Enum defining authorization requests from the Update client.
     */
    enum {
        UpdateRequestInvalid                    = UpdateClient::RequestInvalid,
        UpdateRequestDownload                   = UpdateClient::RequestDownload,
        UpdateRequestInstall                    = UpdateClient::RequestInstall
    };
#endif

    /**
     * \brief Constructor
     */
    MbedCloudClient();

    /**
     * \brief Destructor
     */
    virtual ~MbedCloudClient();

    /**
     * \brief Adds a list of objects the application wants to register to the
     * LwM2M server.
     *
     * This function MUST be called before calling the `setup()` API.
     * Otherwise, the application gets the error `ConnectInvalidParameters`
     * when calling `setup()`.
     * \param object_list Objects that contain information about the
     * client attempting to register to the LwM2M server.
     */
    void add_objects(const M2MObjectList& object_list);

    /**
     * \brief Sets the callback function that is called when there is
     * a new update on an Object, Object Instance or Resource from the LwM2M server,
     * typically on receiving PUT commands on the registered objects.
     * \param callback Passes the class object that implements the callback
     * function to handle the incoming PUT request on a given object.
     */
    void set_update_callback(MbedCloudClientCallback *callback);

    /**
     * \brief Initiates the Client setup on the Device Management service.
     *
     * This function manages the first time use through device provisioning or bootstrapping,
     * and registering the client application to the Device Management service.
     * \param iface A handler to the network interface on Mbed OS. This can be NULL on
     * other platforms.
     */
    bool setup(void* iface);

    /**
     * \brief Sets the callback function that is called when the client is registered
     * successfully to Device Management.
     *
     * This is used for a statically defined function.
     * \param fn A function pointer to the function that is called when the client
     * is registered.
     */
    void on_registered(void(*fn)(void));

    /**
    * \brief Sets the callback function that is called when the client is registered
    * successfully to Device Management.
    *
    * This is an overloaded function for a class function.
    * \param object A function pointer to the function that is called when the client
    * is registered.
    */
    template<typename T>
    void on_registered(T *object, void (T::*member)(void));

    /**
     * \brief Sets the callback function that is called when an error
     * occurs in client functionality.
     *
     * The error code can be mapped from the `MbedCloudClient::Error` enum.
     * This is used for a statically defined function.
     * \param fn A function pointer to the function that is called when there
     * is an error in the client.
     */
    void on_error(void(*fn)(int));

    /**
     * \brief Sets the callback function that is called when an error
     * occurs in client functionality.
     *
     * The error code can be mapped from `MbedCloudClient::Error` enum.
     * This is an overloaded function for a class function.
     * \param object A function pointer to the function that is called when there
     * is an error in the client.
     */
    template<typename T>
    void on_error(T *object, void (T::*member)(int));

    /**
     * \brief Sets the callback function that is called when the client is deregistered
     * successfully from Device Management.
     *
     * This is used for a statically defined function.
     * \param fn A function pointer to the function that is called when the client
     * is deregistered.
     */
    void on_unregistered(void(*fn)(void));

    /**
    * \brief Sets the callback function that is called when the client is deregistered
    * successfully from Device Management.
    *
    * This is an overloaded function for a class function.
    * \param object The callback function is part of this object.
    * \param member A function pointer to the function that is called when the client
    * is deregistered.
    */
    template<typename T>
    void on_unregistered(T *object, void (T::*member)(void));

    /**
     * \brief Sets the callback function that is called when the client registration
     * is updated successfully to Device Management.
     *
     * This is used for a statically defined function.
     * \param fn A function pointer to the function that is called when the client
     * registration is updated.
     */
    void on_registration_updated(void(*fn)(void));

    /**
     * \brief Sets the callback function that is called when the client registration
     * is updated successfully to Device Management.
     *
     * This is an overloaded function for a class function.
     * \param object The callback function is part of this object.
     * \param member A function pointer to the function that is called when the client
     * registration is updated.
     */
    template<typename T>
        void on_registration_updated(T *object, void (T::*member)(void));

    /**
    * \brief Sends a registration update message to Device Management when the client is registered
    * successfully and there are no internal connection errors.
    *
    * If the client is not connected and there is an internal network
    * transaction ongoing, this function triggers the error `MbedCloudClient::ConnectNotAllowed`.
    */
    void register_update();

    /**
     * \brief Pauses client's timed functionality and closes network connection
     * to the LwM2M server.
     *
     * After a call to this function, the operation continues by calling `resume()`.
     *
     * \note Must NOT be called after calling `close()`.
     */
    void pause();

    /**
     * \brief Resumes client's timed functionality and network connection
     * to the LwM2M server.
     *
     * Updates registration. Can be only called after a call to `pause()`.
     *
     * \param iface Pointer to the new network interface to be used, or NULL
     *              when the client does not change the network interface.
     *
     * \return True on success, false on failure.
     */
    bool resume(void* iface=NULL);

    /**
    * \brief Closes the connection to Device Management and deregisters the client.
    *
    * This function triggers the `on_unregistered()` callback if set by the application.
    */
    void close();

    /**
     * \brief Get information on a connected endpoint.
     * \param endpoint_info Populated with the endpoint information on a successfull call.
     * \return True in success, false in failure.
     */
    bool endpoint_info(ConnectorClientEndpointInfo *endpoint_info);


    /**
    * \brief Get endpoint name.
    * Can be called before connecting, but must only be called after `setup()`.
    * \param endpoint_name Output buffer that on a succesful call will contain the endpoint name as a C string.
    * \param size The size of the `endpoint_name` buffer. Any data that doesn't fit will be discarded.
    * \return True in success, false in failure.
    */
    bool get_endpoint_name(char *endpoint_name, size_t size);

    /**
    * \brief Get device id of a connected device.
    * \param device_id Output buffer that on a succesful call will contain the device id as a C string.
    * \param size The size of the `device_id` buffer. Any data that doesn't fit will be discarded.
    * \return True in success, false in failure.
    */
    bool get_device_id(char *device_id, size_t size);

#ifdef MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP_QUEUE
    /**
     * \brief Sets the function that is called to indicate that the client.
     * is going to sleep when the binding mode is selected with queue mode.
     * \param handler A function pointer that is called when the client
     * goes to sleep.
     */
    void set_queue_sleep_handler(callback_handler handler);
#endif //MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP_QUEUE

    /**
     * \brief Sets the function callback that is called by the client to
     * fetch a random number from an application to ensure strong entropy.
     * \param callback A function pointer that is called by client
     * while performing a secure handshake.
     * The function signature should be `uint32_t (*random_number_callback)(void);`.
     */
    void set_random_number_callback(random_number_cb callback);

#ifndef PROTOMAN_OFFLOAD_TLS
    /**
     * \brief Sets the function callback that is called by the client to
     * provide an entropy source from an application to ensure strong entropy.
     * \param callback A function pointer that is called by the client
     * while performing a secure handshake.
     * The function signature, if using mbed-client-mbedtls, should be
     * `int (*mbedtls_entropy_f_source_ptr)(void *data, unsigned char *output,
     *                                     size_t len, size_t *olen);`.
     */
    void set_entropy_callback(entropy_cb callback);
#endif // #ifndef PROTOMAN_OFFLOAD_TLS

    /**
     * \brief Sets a Resource value in the device Object.
     *
     * \param resource Device enum to have a value set.
     * \param value String object.
     * \return True if successful, false otherwise.
     */
    bool set_device_resource_value(M2MDevice::DeviceResource resource,
                                   const char *value);

#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
    /**
     * \brief Registers a callback function for authorizing firmware downloads and reboots.
     * \param handler Callback function.
     */
    void set_update_authorize_handler(void (*handler)(int32_t request));

    /**
     * \brief Registers a callback function for authorizing update requests with priority.
     * \param handler Callback function.
     */
    void set_update_authorize_priority_handler(void (*handler)(int32_t request, uint64_t priority));

    /**
     * \brief Authorizes a request passed to the authorization handler.
     * \param request The request being authorized.
     */
    void update_authorize(int32_t request);

    /**
     * \brief Rejects a request passed to the authorization handler.
     * \param request The request being rejected.
     * \param reason The reason for rejecting the request.
     */
    void update_reject(int32_t request, int32_t reason);

    /**
     * \brief Registers a callback function for monitoring the download progress.
     * \param handler Callback function.
     */
    void set_update_progress_handler(void (*handler)(uint32_t progress, uint32_t total));
#endif

    /**
     * @brief Returns the error description for the latest error code.
     * @return Error description string.
     */
    const char *error_description() const;

    /**
     * @brief Returns a pointer to `M2MInterface` class.
     * @note M2MInterface API is not supported for direct usage.
     * Used only as a handle when creating LwM2M objects.
     * @return M2MInterface pointer
     */
    M2MInterface *m2minterface_handle();

protected: // from ServiceClientCallback

    /**
    * \brief Indicates that the setup or close operation is complete
    * with either success or failure.
    * \param status Indicates success or failure in terms of status code.
    */
    virtual void complete(ServiceClientCallbackStatus status);

    /**
    * \brief Indicates an error condition from the underlying clients like
    * identity, connector or Update client.
    * \param error An error code translated to `MbedCloudClient::Error`.
    * \param reason Human readable text for error description.
    */
    virtual void error(int error, const char *reason);

    /**
    * \brief A callback indicating that the value of the resource object is updated
    *  by the LwM2M server.
    * \param base The object whose value is updated.
    * \param type The type of the object.
    */
    virtual void value_updated(M2MBase *base, M2MBase::BaseType type);

private:

    ServiceClient                                   _client;
    MbedCloudClientCallback                         *_value_callback;
    M2MObjectList                                   _object_list;
    FP0<void>                                       _on_registered;
    FP0<void>                                       _on_unregistered;
    FP0<void>                                       _on_registration_updated;
    FP1<void,int>                                   _on_error;
    const char                                      *_error_description;

friend class SimpleM2MResourceBase;
};

template<typename T>
void MbedCloudClient::on_registered(T *object, void (T::*member)(void))
{
    FP0<void> fp(object, member);
    _on_registered = fp;
}

template<typename T>
void MbedCloudClient::on_error(T *object, void (T::*member)(int))
{
    FP1<void, int> fp(object, member);
    _on_error = fp;
}

template<typename T>
void MbedCloudClient::on_unregistered(T *object, void (T::*member)(void))
{
    FP0<void> fp(object, member);
    _on_unregistered = fp;
}

template<typename T>
void MbedCloudClient::on_registration_updated(T *object, void (T::*member)(void))
{
    FP0<void> fp(object, member);
    _on_registration_updated = fp;
}
#endif // MBED_CONF_MBED_CLIENT_ENABLE_CPP_API
#endif // __MBED_CLOUD_CLIENT_H__
