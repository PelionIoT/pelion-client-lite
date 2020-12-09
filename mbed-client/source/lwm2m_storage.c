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

#ifdef MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#include MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#else
#error "User must define MBED_CLOUD_CLIENT_USER_CONFIG_FILE"
#endif

#include "lwm2m_constants.h"
#include "lwm2m_endpoint.h"
#include "lwm2m_heap.h"
#include "lwm2m_registry.h"
#include "lwm2m_storage.h"
#include "mbed-trace/mbed_trace.h"
#include "protoman.h"
#include "include/uriqueryparser.h"

#include <assert.h>
#include <string.h>

#define TRACE_GROUP "lwSt"

#define MAX_QUERY_COUNT 10

#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
#define INTERNAL_ENDPOINT_PARAM     "&iep="
#endif
#define DEFAULT_ENDPOINT            "endpoint"
#define INTERFACE_ERROR             "Client interface is not created. Restart"
#define CREDENTIAL_ERROR            "Failed to read credentials from storage"
#define DEVICE_NOT_PROVISIONED      "Device not provisioned"
#define ERROR_NO_MEMORY             "Not enough memory to store LWM2M credentials"


#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
static char *bootstrap_ca_certificate = NULL;
static char *bootstrap_certificate_key = NULL;
static char *bootstrap_certificate = NULL;
#endif //MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
static char *lwm2m_ca_certificate = NULL;
static char *lwm2m_certificate_key = NULL;
static char *lwm2m_certificate = NULL;
#endif //defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)

#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
#if defined(PROTOMAN_SECURITY_ENABLE_PSK)
#error "Currently both PROTOMAN_SECURITY_ENABLE_CERTIFICATE and PROTOMAN_SECURITY_ENABLE_PSK are not supported at the same time."
#endif
#endif

bool storage_set_parameter(cloud_client_param  key, const uint8_t *buffer, const size_t buffer_size)
{
    return (CCS_STATUS_SUCCESS == set_config_parameter(key, buffer, buffer_size));
}
#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
bool storage_remove_parameter(cloud_client_param  key)
{
    return (CCS_STATUS_SUCCESS == remove_config_parameter(key));
}
#endif

#ifdef MBED_CONF_ZERO_COPY_CONFIG_STORE_ENABLED
ccs_status_e storage_get_parameter_no_copy(cloud_client_param key, const uint8_t **buffer, size_t *value_length)
{
    return get_config_parameter_no_copy(key, buffer, value_length);
}
#endif

//TODO: size checking?
static char *storage_read_field(cloud_client_param field, char *buffer, int32_t *buffer_size)
{
    assert(buffer_size);

    size_t size_written;
    ccs_status_e status;

    if (!buffer) {
        status = size_config_parameter(field, &size_written);
        if (status != CCS_STATUS_SUCCESS) {
            size_written = 0;
        }
        *buffer_size += size_written;
        return NULL;
    }

    status = get_config_parameter(field,  (uint8_t*)buffer, *buffer_size, &size_written);
    if (status == CCS_STATUS_SUCCESS) {

        *buffer_size -= size_written;
        return (buffer + size_written);
    } else {
        *buffer_size = 0;
    }
    return NULL;
}

char *storage_read_endpoint_name(char *buffer, int32_t *buffer_size, const bool bootstrap)
{
    (void) bootstrap;
    return storage_read_field(ENDPOINT_NAME, buffer, buffer_size);
}

char *storage_read_internal_endpoint_name(char *buffer, int32_t *buffer_size, const bool bootstrap)
{
    (void) bootstrap;
    return storage_read_field(INTERNAL_ENDPOINT, buffer, buffer_size);
}

char *storage_read_uri(char *buffer, int32_t *buffer_size, bool bootstrap)
{

#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    if (bootstrap) {
        return storage_read_field(BOOTSTRAP_SERVER_URI, buffer, buffer_size);
    }
#else
    (void)bootstrap;
#endif
    return storage_read_field(LWM2M_SERVER_URI, buffer, buffer_size);
}


bool storage_registration_credentials_available(void)
{
    size_t real_size = 0;
    ccs_status_e success;

#if defined(PROTOMAN_SECURITY_ENABLE_PSK)
    success = size_config_parameter(LWM2M_SERVER_PSK_IDENTITY, &real_size);
    if ((success != CCS_STATUS_SUCCESS) || real_size <= 0) {
        return false;
    }

    success = size_config_parameter(LWM2M_SERVER_PSK_SECRET, &real_size);
    if ((success != CCS_STATUS_SUCCESS) || real_size <= 0) {
        return false;
    }
#endif //defined(PROTOMAN_SECURITY_ENABLE_PSK)

#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
    success = size_config_parameter(LWM2M_DEVICE_CERTIFICATE, &real_size);
    if ((success != CCS_STATUS_SUCCESS) || real_size <= 0) {
        return false;
    }

    success = size_config_parameter(LWM2M_SERVER_ROOT_CA_CERTIFICATE, &real_size);
    if ((success != CCS_STATUS_SUCCESS) || real_size <= 0) {
        return false;
    }

    success = size_config_parameter(LWM2M_DEVICE_PRIVATE_KEY, &real_size);
    if ((success != CCS_STATUS_SUCCESS) || real_size <= 0) {
        return false;
    }
#endif //defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)

    success = size_config_parameter(LWM2M_SERVER_URI, &real_size);
    if ((success != CCS_STATUS_SUCCESS) || real_size <= 0) {
        return false;
    }

    return true;
}

#if defined(PROTOMAN_SECURITY_ENABLE_PSK)
bool storage_read_psk(void *buffer, size_t *buffer_size, bool bootstrap)
{
#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    if (bootstrap) {
        return (CCS_STATUS_SUCCESS == get_config_parameter(BOOTSTRAP_SERVER_PSK_SECRET, buffer, *buffer_size, buffer_size));
    }
#else 
    (void)bootstrap;
#endif //MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    return (CCS_STATUS_SUCCESS == get_config_parameter(LWM2M_SERVER_PSK_SECRET, buffer, *buffer_size, buffer_size));
}

bool storage_read_psk_id(void *buffer, size_t *buffer_size, bool bootstrap)
{
#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    if (bootstrap) {
        return (CCS_STATUS_SUCCESS == get_config_parameter(BOOTSTRAP_SERVER_PSK_IDENTITY, buffer, *buffer_size, buffer_size));
    }
#else
    (void)bootstrap;
#endif //MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    return (CCS_STATUS_SUCCESS == get_config_parameter(LWM2M_SERVER_PSK_IDENTITY, buffer, *buffer_size, buffer_size));
}
#endif

#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
/* This function retrieves connectivity parameters.
The possible parameters : certificate or private key.
The function reads connectivity parameter size,
releases existing parameter buffer, allocates memory for the parameter and reads it.*/
static void *allocate_and_read_connectivity_parameter(cloud_client_param parameter_name, char **parameter_buffer, size_t *actual_parameter_size, bool bootstrap)
{
    size_t temp_parameter_size = 0;

#ifdef MBED_CONF_ZERO_COPY_CONFIG_STORE_ENABLED
    if (!bootstrap && (strcmp(parameter_name, LWM2M_DEVICE_PRIVATE_KEY) != 0)) { //Options: 1.lwm2m ca or device certificates and zero copy enabled
        if (CCS_STATUS_SUCCESS == get_config_parameter_no_copy(parameter_name,  (const uint8_t**)parameter_buffer, &temp_parameter_size)) {
            *actual_parameter_size = temp_parameter_size;
            return *parameter_buffer;
        }
    } else
#endif
    { /*Options : 1.bootstrap ca or device certificates or key
                  2.lwm2m key and zero copy enabled
                  3.lwm2m certificate or key and zero copy disabled*/
        if (CCS_STATUS_SUCCESS == size_config_parameter(parameter_name, &temp_parameter_size)) {
            lwm2m_free(*parameter_buffer);
            *parameter_buffer = lwm2m_alloc(temp_parameter_size);
            if (*parameter_buffer && CCS_STATUS_SUCCESS == get_config_parameter(parameter_name, (uint8_t*)*parameter_buffer, temp_parameter_size, actual_parameter_size)) {
                return *parameter_buffer;//Parameter successfully retrieved
            } else {// get_config_parameter
                lwm2m_free(*parameter_buffer);
            }
        }//size_config_parameter
    }//bootstrap parameter, lwm2m parameter and zero copy disabled
    *parameter_buffer = NULL;
    return NULL;
}

const void *storage_read_certificate(size_t *buffer_size, bool bootstrap)
{
    uint8_t* temp_p = NULL;
#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    if (bootstrap) { //bootstrap device certificate
        temp_p = allocate_and_read_connectivity_parameter(BOOTSTRAP_DEVICE_CERTIFICATE, &bootstrap_certificate, buffer_size, bootstrap);
    } else
#endif
    { //lwm2m device certificate
        temp_p = allocate_and_read_connectivity_parameter(LWM2M_DEVICE_CERTIFICATE, &lwm2m_certificate, buffer_size, bootstrap);
    }
    if (!temp_p) {
        tr_error("storage_read_certificate() failed");
    }
    return temp_p;
}

const void *storage_read_certificate_key(size_t *buffer_size, bool bootstrap)
{
    uint8_t* temp_p = NULL;
#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    if (bootstrap) { //bootstrap device key
        temp_p = allocate_and_read_connectivity_parameter(BOOTSTRAP_DEVICE_PRIVATE_KEY, &bootstrap_certificate_key, buffer_size, bootstrap);
    } else
#endif
    { //lwm2m device key
        temp_p = allocate_and_read_connectivity_parameter(LWM2M_DEVICE_PRIVATE_KEY, &lwm2m_certificate_key, buffer_size, bootstrap);
    }
    if (!temp_p) {
        tr_error("storage_read_certificate_key() failed");
    }
    return temp_p;
}

const void *storage_read_ca_certificate(size_t *buffer_size, bool bootstrap)
{
    uint8_t* temp_p = NULL;

#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    if (bootstrap) { //bootstrap ca certificate
        temp_p = allocate_and_read_connectivity_parameter(BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE, &bootstrap_ca_certificate, buffer_size, bootstrap);
    } else
#endif
    {//lwm2m ca certificate
        temp_p = allocate_and_read_connectivity_parameter(LWM2M_SERVER_ROOT_CA_CERTIFICATE, &lwm2m_ca_certificate, buffer_size, bootstrap);

    }
    if (!temp_p) {
        tr_error("storage_read_ca_certificate() failed");
    }
    return temp_p;
}
#endif //defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
bool storage_set_credentials(registry_t *registry)
{
    registry_path_t path;
#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE) || defined(PROTOMAN_SECURITY_ENABLE_PSK)
    registry_data_opaque_t *public_key = NULL;
    registry_data_opaque_t *sec_key = NULL;
#endif //defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE) || defined(PROTOMAN_SECURITY_ENABLE_PSK)
#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
    registry_data_opaque_t *ca_cert = NULL;
#endif //defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
    const char *server_uri;
    int64_t security;
    tr_debug("storage_set_credentials()");

    registry_set_path(&path, M2M_SECURITY_ID, 0, SECURITY_M2M_SERVER_URI, 0, REGISTRY_PATH_OBJECT_INSTANCE);
    if (REGISTRY_STATUS_OK != registry_path_exists(registry, &path)) {
        tr_info("storage_set_credentials() No credentials available.");
        return false;
    }

    registry_set_path(&path, M2M_SECURITY_ID, 0, SECURITY_SECURITY_MODE, 0, REGISTRY_PATH_RESOURCE);
    if (REGISTRY_STATUS_OK != registry_get_value_int(registry, &path, &security)) {
        tr_error("storage_set_credentials() No security mode set.");
        return false;
    }

#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE) || defined(PROTOMAN_SECURITY_ENABLE_PSK)
    // Security mode 0 = PSK.
    // Security mode 2 = Certificate.
    if (security == 0 || security == 2) {

#ifndef PROTOMAN_OFFLOAD_TLS
        registry_set_path(&path, M2M_SECURITY_ID, 0, SECURITY_PUBLIC_KEY, 0, REGISTRY_PATH_RESOURCE);
        if (REGISTRY_STATUS_OK != registry_get_value_opaque(registry, &path, &public_key)) {
            tr_error("storage_set_credentials() registry_get_value_opaque public_key failed");
            return false;
        }

        registry_set_path(&path, M2M_SECURITY_ID, 0, SECURITY_SECRET_KEY, 0, REGISTRY_PATH_RESOURCE);
        if (REGISTRY_STATUS_OK != registry_get_value_opaque(registry, &path, &sec_key)) {
            tr_error("storage_set_credentials() registry_get_value_opaque sec_key failed");
            return false;
        }
#endif

    }
#endif //defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE) || defined(PROTOMAN_SECURITY_ENABLE_PSK)
#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
    if (security == 2) {
#ifndef PROTOMAN_OFFLOAD_TLS
        registry_set_path(&path, M2M_SECURITY_ID, 0, SECURITY_SERVER_PUBLIC_KEY, 0, REGISTRY_PATH_RESOURCE);
        if (REGISTRY_STATUS_OK != registry_get_value_opaque(registry, &path, &ca_cert)) {
            tr_error("storage_set_credentials() registry_get_value_opaque sec_key failed");
            return false;
        }
#endif

    }
#endif //defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)


    registry_set_path(&path, M2M_SECURITY_ID, 0, SECURITY_M2M_SERVER_URI, 0, REGISTRY_PATH_RESOURCE);
    if (REGISTRY_STATUS_OK != registry_get_value_string(registry, &path, &server_uri)) {
        tr_error("set_connector_credentials() registry_get_value_string server_uri failed");
        return false;
    }

#if defined(PROTOMAN_SECURITY_ENABLE_PSK)
    if (security == 0) {
        if (set_config_parameter(LWM2M_SERVER_PSK_IDENTITY, public_key->data, public_key->size) != CCS_STATUS_SUCCESS) {
            tr_error("storage_set_credentials() set_config_parameter public_key failed");
            return false;
        }

        if (set_config_parameter(LWM2M_SERVER_PSK_SECRET, sec_key->data, sec_key->size) != CCS_STATUS_SUCCESS) {
            tr_error("storage_set_credentials() set_config_parameter sec_key failed");
            return false;
        }
    }
#endif //defined(PROTOMAN_SECURITY_ENABLE_PSK)
#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
    if (security == 2) {
#ifndef PROTOMAN_OFFLOAD_TLS
        if (set_config_parameter(LWM2M_DEVICE_CERTIFICATE, public_key->data, public_key->size) != CCS_STATUS_SUCCESS) {
            tr_error("storage_set_credentials() set_config_parameter public_key failed");
            return false;
        }

        if (set_config_parameter(LWM2M_SERVER_ROOT_CA_CERTIFICATE, ca_cert->data, ca_cert->size) != CCS_STATUS_SUCCESS) {
            tr_error("storage_set_credentials() set_config_parameter ca_cert failed");
            return false;
        }

        if (set_config_parameter(LWM2M_DEVICE_PRIVATE_KEY, sec_key->data, sec_key->size) != CCS_STATUS_SUCCESS) {
            tr_error("storage_set_credentials() set_config_parameter sec_key failed");
            return false;
        }
#endif
    }
#endif //defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)

    if (set_config_parameter(LWM2M_SERVER_URI, (const uint8_t*)server_uri, strlen(server_uri)) != CCS_STATUS_SUCCESS) {
        tr_error("storage_set_credentials() set_config_parameter server_uri failed");
        return false;
    }

#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    if (security == 0 || security == 2) {
        tr_info("storage_set_credentials() set_config_parameter ok");
        const char *iep_ptr = NULL;
        const int iep_len = parse_query_parameter_value_from_query(server_uri, "iep", &iep_ptr);
        if (iep_ptr && iep_len > 0) {
            if (!storage_set_internal_endpoint_name(iep_ptr)) {
                return false;
            }
        }
    }
#endif // MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE

    //TODO: Should this be done by the caller?
    //registry_set_path(&path, M2M_SECURITY_ID, 0, 0, 0, REGISTRY_PATH_OBJECT);
    //registry_remove_object(registry, &path, REGISTRY_REMOVE);

    return true;
}
#endif
#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
bool storage_clear_credentials(registry_t *registry)
{
    registry_path_t path;
    int64_t security;
    registry_set_path(&path, M2M_SECURITY_ID, 0, SECURITY_SECURITY_MODE, 0, REGISTRY_PATH_RESOURCE);
    if (REGISTRY_STATUS_OK != registry_get_value_int(registry, &path, &security)) {
        tr_error("storage_clear_credentials() No security mode set.");
        return false;
    }

#if defined(PROTOMAN_SECURITY_ENABLE_PSK)
    if (security == 0) {
        if (remove_config_parameter(LWM2M_SERVER_PSK_IDENTITY) != CCS_STATUS_SUCCESS) {
            tr_error("storage_clear_credentials() remove_config_parameter public_key failed");
        }
        if (remove_config_parameter(LWM2M_SERVER_PSK_SECRET, sec_key->data, sec_key->size) != CCS_STATUS_SUCCESS) {
            tr_error("storage_clear_credentials() remove_config_parameter sec_key failed");
        }
    }
#endif //defined(PROTOMAN_SECURITY_ENABLE_PSK)
#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
    if (security == 2) {
#ifndef PROTOMAN_OFFLOAD_TLS
        if (remove_config_parameter(LWM2M_DEVICE_CERTIFICATE) != CCS_STATUS_SUCCESS) {
            tr_error("storage_clear_credentials() remove_config_parameter public_key failed");
        }
        if (remove_config_parameter(LWM2M_SERVER_ROOT_CA_CERTIFICATE) != CCS_STATUS_SUCCESS) {
            tr_error("storage_clear_credentials() remove_config_parameter ca_cert failed");
        }
        if (remove_config_parameter(LWM2M_DEVICE_PRIVATE_KEY) != CCS_STATUS_SUCCESS) {
            tr_error("storage_clear_credentials() remove_config_parameter sec_key failed");
        }
#endif
    }
#endif //defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)

    if (remove_config_parameter(LWM2M_SERVER_URI) != CCS_STATUS_SUCCESS) {
        tr_error("storage_clear_credentials() remove_config_parameter server_uri failed");
    }
    return true;
}
#endif
#endif // MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
bool storage_set_bootstrap_credentials(registry_t *registry)
{
#if defined(PROTOMAN_SECURITY_ENABLE_PSK)
    registry_path_t path;

    registry_data_opaque_t *public_key;
    registry_data_opaque_t *sec_key;
    char *server_uri;

    tr_debug("set_bootstrap_credentials()");

    registry_set_path(&path, M2M_SECURITY_ID, 0, SECURITY_PUBLIC_KEY, 0, REGISTRY_PATH_RESOURCE);
    if (REGISTRY_STATUS_OK != registry_get_value_opaque(registry, &path, &public_key)) {
        return false;
    }

    registry_set_path(&path, M2M_SECURITY_ID, 0, SECURITY_SECRET_KEY, 0, REGISTRY_PATH_RESOURCE);
    if (REGISTRY_STATUS_OK != registry_get_value_opaque(registry, &path, &sec_key)) {
        return false;
    }

    registry_set_path(&path, M2M_SECURITY_ID, 0, SECURITY_M2M_SERVER_URI, 0, REGISTRY_PATH_RESOURCE);
    if (REGISTRY_STATUS_OK != registry_get_value_string(registry, &path, &server_uri)) {
        return false;
    }

    if (set_config_parameter(BOOTSTRAP_SERVER_PSK_IDENTITY, public_key->data, public_key->size) != CCS_STATUS_SUCCESS) {
        return false;
    }

    if (set_config_parameter(BOOTSTRAP_SERVER_PSK_SECRET, sec_key->data, sec_key->size) != CCS_STATUS_SUCCESS) {
        return false;
    }

    if (set_config_parameter(BOOTSTRAP_SERVER_URI, (const uint8_t*) server_uri, strlen(server_uri))!= CCS_STATUS_SUCCESS) {
        return false;
    }

    registry_set_path(&path, M2M_SECURITY_ID, 0, 0, 0, REGISTRY_PATH_OBJECT);
    registry_remove_object(registry, &path, REGISTRY_REMOVE);

    return true;
#else
    tr_error("set_bootstrap_credentials() Redirecting bootstrap not supported.");
    return false;
#endif //defined(PROTOMAN_SECURITY_ENABLE_PSK)
}
#endif

bool storage_set_internal_endpoint_name(const char *iep)
{
    if (!iep || (set_config_parameter(INTERNAL_ENDPOINT, (const uint8_t*) iep, strlen(iep)) != CCS_STATUS_SUCCESS)) {
        tr_error("storage_set_internal_endpoint_name() setting iep failed");
        return false;
    }

    tr_info("Internal Endpoint ID %s", iep);

    return true;
}
