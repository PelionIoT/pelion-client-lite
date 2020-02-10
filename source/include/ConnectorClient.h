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

#ifndef __CONNECTOR_CLIENT_H__
#define __CONNECTOR_CLIENT_H__

#include "mbed-client/functionpointer.h"
#include "mbed-client/lwm2m_constants.h"
#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2mdevice.h"
#include "mbed-client/m2minterfaceobserver.h"
#include "mbed-client/m2minterface.h"
#include "mbed-client/m2mobjectinstance.h"
#include "mbed-client/m2mresource.h"
#include "mbed-client/m2mtimerobserver.h"
#include "mbed-client/m2mtimer.h"
#include "mbed-client/m2mcorememory.h"
#include "include/CloudClientStorage.h"

class ConnectorClientCallback;


/**
 * \brief ConnectorClientEndpointInfo
 * A structure that contains the needed endpoint information to register with the Cloud service.
 * Note: this should be changed to a class instead of struct and/or members changed to "const char*".
 */
struct ConnectorClientEndpointInfo {
    char                            endpoint_name[MAX_ALLOWED_STRING_SIZE];
    char                            account_id[MAX_ALLOWED_STRING_SIZE];
    char                            internal_endpoint_name[MAX_ALLOWED_STRING_SIZE];
    M2MSecurity::SecurityModeType   mode;
};

/**
 * \brief ConnectorClient
 * This class is an interface towards the M2MInterface client to handle all
 * data flow towards Connector through this client.
 * This class is intended to be used via ServiceClient, not directly.
 * This class contains also the bootstrap functionality.
 */
class ConnectorClient : public M2MInterfaceObserver,
                        public M2MCoreMemory {

public:
    /**
     * \brief An enum defining the different states of
     * ConnectorClient during the client flow.
     */
    enum StartupSubStateRegistration {
        State_Bootstrap_Start,
        State_Bootstrap_Started,
        State_Bootstrap_Success,
        State_Bootstrap_Failure,
        State_Registration_Start,
        State_Registration_Started,
        State_Registration_Success,
        State_Registration_Failure,
        State_Registration_Updated,
        State_Unregistered
    };

public:

    /**
    *  \brief Constructor.
    *  \param callback, A callback for the status from ConnectorClient.
    */
    ConnectorClient(ConnectorClientCallback* callback);

    /**
    *  \brief Destructor.
    */
    ~ConnectorClient();

    /**
    *  \brief Starts the bootstrap sequence from the Service Client.
    */
    void start_bootstrap();

    /**
    *  \brief Starts the registration sequence from the Service Client.
    *  \param client_objs, A list of objects to be registered with Cloud.
    */
    void start_registration();

    /**
    *  \brief Sends an update registration message to the LWM2M server.
    */
    void update_registration();

    /**
     * \brief Returns the M2MInterface handler.
     * \return M2MInterface, Handled for M2MInterface.
    */
    M2MInterface * m2m_interface();

    /**
     * \brief Checks whether to go connector registration flow
     * \return True if connector credentials available otherwise false.
    */
    bool connector_credentials_available();

    /**
    * \brief Returns pointer to the ConnectorClientEndpointInfo object.
    * \return ConnectorClientEndpointInfo pointer.
    */
    bool endpoint_info(ConnectorClientEndpointInfo *endpoint_info);

public:
    // implementation of M2MInterfaceObserver:

    /**
     * \brief A callback indicating that the bootstap has been performed successfully.
     * \param server_object, The server object that contains the information fetched
     * about the LWM2M server from the bootstrap server. This object can be used
     * to register with the LWM2M server. The object ownership is passed.
     */
    virtual void bootstrap_done();

    /**
     * \brief A callback indicating that the device object has been registered
     * successfully with the LWM2M server.
     * \param security_object, The server object on which the device object is
     * registered. The object ownership is passed.
     * \param server_object, An object containing information about the LWM2M server.
     * The client maintains the object.
     */
    virtual void object_registered();

    /**
     * \brief A callback indicating that the device object has been successfully unregistered
     * from the LWM2M server.
     * \param server_object, The server object from which the device object is
     * unregistered. The object ownership is passed.
     */
    virtual void object_unregistered();

    /**
     * \brief A callback indicating that the device object registration has been successfully
     * updated on the LWM2M server.
     * \param security_object, The server object on which the device object registration is
     * updated. The object ownership is passed.
     * \param server_object, An object containing information about the LWM2M server.
     * The client maintains the object.
     */
    virtual void registration_updated();

    /**
     * \brief A callback indicating that there was an error during the operation.
     * \param error, An error code for the occurred error.
     */
    virtual void error(M2MInterface::Error error);

    /**
     * \brief A callback indicating that the value of the resource object is updated by the server.
     * \param base, The object whose value is updated.
     * \param type, The type of the object.
     */
    virtual void value_updated(M2MBase *base, M2MBase::BaseType type);

private:

    /**
    * \brief Returns the binding mode selected by the client
    * through the configuration.
    * \return Binding mode of the client.
    */
    static M2MInterface::BindingMode transport_mode();

private:
    // A callback to be called after the sequence is complete.
    ConnectorClientCallback*            _callback;
    M2MInterface                        *_interface;
};

/**
 * \brief ConnectorClientCallback
 * A callback class for passing the client progress and error condition to the
 * ServiceClient class object.
 */
class ConnectorClientCallback {
public:

    /**
    * \brief Indicates that the registration or unregistration operation is complete
    * with success or failure.
    * \param status, Indicates success or failure in terms of status code.
    */
    virtual void registration_process_result(ConnectorClient::StartupSubStateRegistration status) = 0;

    /**
    * \brief Indicates the Connector error condition of an underlying M2MInterface client.
    * \param error, Indicates an error code translated from M2MInterface::Error.
    * \param reason, Indicates human readable text for error description.
    */
    virtual void connector_error(M2MInterface::Error error, const char *reason) = 0;

    /**
    * \brief A callback indicating that the value of the resource object is updated
    *  by the LWM2M Cloud server.
    * \param base, The object whose value is updated.
    * \param type, The type of the object.
    */
    virtual void value_updated(M2MBase *base, M2MBase::BaseType type) = 0;
};

#endif // !__CONNECTOR_CLIENT_H__
