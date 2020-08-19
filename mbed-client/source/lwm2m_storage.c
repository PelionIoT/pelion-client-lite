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
static char *bootstrap_ca_certificate = NULL;
static size_t bootstrap_ca_certificate_size = 0;
static char *lwm2m_ca_certificate = NULL;
static size_t lwm2m_ca_certificate_size = 0;

static char *bootstrap_certificate_key = NULL;
static size_t bootstrap_certificate_key_size = 0;
static char *lwm2m_certificate_key = NULL;
static size_t lwm2m_certificate_key_size = 0;

static char *bootstrap_certificate = NULL;
static size_t bootstrap_certificate_size = 0;
static char *lwm2m_certificate = NULL;
static size_t lwm2m_certificate_size = 0;
#endif


#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
#if defined(PROTOMAN_SECURITY_ENABLE_PSK)
#error "Currently both PROTOMAN_SECURITY_ENABLE_CERTIFICATE and PROTOMAN_SECURITY_ENABLE_PSK are not supported at the same time."
#endif
#endif

bool storage_set_parameter(cloud_client_param  key, const uint8_t *buffer, const size_t buffer_size)
{
    return (CCS_STATUS_SUCCESS == set_config_parameter(key, buffer, buffer_size));
}

static ccs_status_e storage_get_parameter(cloud_client_param key, char *buffer, const size_t buffer_size, size_t *value_length)
{
    return get_config_parameter(key, (uint8_t*)buffer, buffer_size, value_length);
}

#ifdef MBED_CONF_ZERO_COPY_CONFIG_STORE_ENABLED
ccs_status_e storage_get_parameter_no_copy(cloud_client_param key, const uint8_t **buffer, size_t *value_length)
{
    return get_config_parameter_no_copy(key, buffer, value_length);
}
#endif

static ccs_status_e storage_parameter_size(cloud_client_param field, size_t* size)
{
    return size_config_parameter(field, size);
}

//TODO: size checking?
static char *storage_read_field(cloud_client_param field, char *buffer, int32_t *buffer_size)
{
    assert(buffer_size);

    size_t size_written;
    ccs_status_e status;

    if (!buffer) {
        status = storage_parameter_size(field, &size_written);
        if (status != CCS_STATUS_SUCCESS) {
            size_written = 0;
        }
        *buffer_size += size_written;
        return NULL;
    }

    status = storage_get_parameter(field, buffer, *buffer_size, &size_written);
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
    if (bootstrap) {
        return storage_read_field(BOOTSTRAP_SERVER_URI, buffer, buffer_size);
    }
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
    if (bootstrap) {
        return (CCS_STATUS_SUCCESS == storage_get_parameter(BOOTSTRAP_SERVER_PSK_SECRET, buffer, *buffer_size, buffer_size));
    }
    return (CCS_STATUS_SUCCESS == storage_get_parameter(LWM2M_SERVER_PSK_SECRET, buffer, *buffer_size, buffer_size));
}

bool storage_read_psk_id(void *buffer, size_t *buffer_size, bool bootstrap)
{
    if (bootstrap) {
        return (CCS_STATUS_SUCCESS == storage_get_parameter(BOOTSTRAP_SERVER_PSK_IDENTITY, buffer, *buffer_size, buffer_size));
    }
    return (CCS_STATUS_SUCCESS == storage_get_parameter(LWM2M_SERVER_PSK_IDENTITY, buffer, *buffer_size, buffer_size));
}
#endif

#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
const void *storage_read_certificate(size_t *buffer_size, bool bootstrap)
{
    if (bootstrap) {
        if (CCS_STATUS_SUCCESS == storage_parameter_size(BOOTSTRAP_DEVICE_CERTIFICATE, &bootstrap_certificate_size)) {
            lwm2m_free(bootstrap_certificate);
            bootstrap_certificate = lwm2m_alloc(bootstrap_certificate_size);
            if (bootstrap_certificate && CCS_STATUS_SUCCESS == storage_get_parameter(BOOTSTRAP_DEVICE_CERTIFICATE, bootstrap_certificate,
                                                            bootstrap_certificate_size, buffer_size)) {
                return bootstrap_certificate;
            } else {
                lwm2m_free(bootstrap_certificate);
            }
        }
    } else {
#ifndef MBED_CONF_ZERO_COPY_CONFIG_STORE_ENABLED
        if (CCS_STATUS_SUCCESS == storage_parameter_size(LWM2M_DEVICE_CERTIFICATE, &lwm2m_certificate_size)) {
            lwm2m_free(lwm2m_certificate);
            lwm2m_certificate = lwm2m_alloc(lwm2m_certificate_size);
            if (lwm2m_certificate && CCS_STATUS_SUCCESS == storage_get_parameter(LWM2M_DEVICE_CERTIFICATE, lwm2m_certificate,
                                                            lwm2m_certificate_size, buffer_size)) {
                return lwm2m_certificate;
            } else {
                lwm2m_free(lwm2m_certificate);
            }
        }
#else
        if (CCS_STATUS_SUCCESS == storage_get_parameter_no_copy(LWM2M_DEVICE_CERTIFICATE, &lwm2m_certificate, &lwm2m_certificate_size)) {
            *buffer_size = lwm2m_certificate_size;
            return lwm2m_certificate;
        }
#endif
    }
    tr_error("storage_read_certificate() failed");
    return NULL;
}

const void *storage_read_certificate_key(size_t *buffer_size, bool bootstrap)
{
    if (bootstrap) {
        if (CCS_STATUS_SUCCESS == storage_parameter_size(BOOTSTRAP_DEVICE_PRIVATE_KEY, &bootstrap_certificate_key_size)) {
            lwm2m_free(bootstrap_certificate_key);
            bootstrap_certificate_key = lwm2m_alloc(bootstrap_certificate_key_size);
            if (bootstrap_certificate_key && CCS_STATUS_SUCCESS == storage_get_parameter(BOOTSTRAP_DEVICE_PRIVATE_KEY, bootstrap_certificate_key,
                                                            bootstrap_certificate_key_size, buffer_size)) {
                return bootstrap_certificate_key;
            } else {
                lwm2m_free(bootstrap_certificate_key);
            }
        }
    } else {

        if (CCS_STATUS_SUCCESS == storage_parameter_size(LWM2M_DEVICE_PRIVATE_KEY, &lwm2m_certificate_key_size)) {
            lwm2m_free(lwm2m_certificate_key);
            lwm2m_certificate_key = lwm2m_alloc(lwm2m_certificate_key_size);
            if (lwm2m_certificate_key && CCS_STATUS_SUCCESS == storage_get_parameter(LWM2M_DEVICE_PRIVATE_KEY, lwm2m_certificate_key,
                                                            lwm2m_certificate_key_size, buffer_size)) {
                return lwm2m_certificate_key;
            } else {
                lwm2m_free(lwm2m_certificate_key);
            }
        }
    }
    tr_error("storage_read_certificate_key() failed");
    return NULL;
}

const void *storage_read_ca_certificate(size_t *buffer_size, bool bootstrap)
{
    if (bootstrap) {
        if (CCS_STATUS_SUCCESS == storage_parameter_size(BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE, &bootstrap_ca_certificate_size)) {
            lwm2m_free(bootstrap_ca_certificate);
            bootstrap_ca_certificate = lwm2m_alloc(bootstrap_ca_certificate_size);
            if (bootstrap_ca_certificate && CCS_STATUS_SUCCESS == storage_get_parameter(BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE, bootstrap_ca_certificate,
                                                            bootstrap_ca_certificate_size, buffer_size)) {
                return bootstrap_ca_certificate;
            } else {
                lwm2m_free(bootstrap_ca_certificate);
            }
        }
    } else {
#ifndef MBED_CONF_ZERO_COPY_CONFIG_STORE_ENABLED
        if (CCS_STATUS_SUCCESS == storage_parameter_size(LWM2M_SERVER_ROOT_CA_CERTIFICATE, &lwm2m_ca_certificate_size)) {
            lwm2m_free(lwm2m_ca_certificate);
            lwm2m_ca_certificate = lwm2m_alloc(lwm2m_ca_certificate_size);
            if (lwm2m_ca_certificate && CCS_STATUS_SUCCESS == storage_get_parameter(LWM2M_SERVER_ROOT_CA_CERTIFICATE, lwm2m_ca_certificate,
                                                            lwm2m_ca_certificate_size, buffer_size)) {
                return lwm2m_ca_certificate;
            } else {
                lwm2m_free(lwm2m_ca_certificate);
            }
        }
#else
        if (CCS_STATUS_SUCCESS == storage_get_parameter_no_copy(LWM2M_SERVER_ROOT_CA_CERTIFICATE, &lwm2m_ca_certificate, &lwm2m_ca_certificate_size)) {
            *buffer_size = lwm2m_ca_certificate_size;
            return lwm2m_ca_certificate;
        }
#endif
    }
    tr_error("storage_read_ca_certificate() failed");
    return NULL;
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
    tr_debug("set_connector_credentials()");

    registry_set_path(&path, M2M_SECURITY_ID, 0, SECURITY_M2M_SERVER_URI, 0, REGISTRY_PATH_OBJECT_INSTANCE);
    if (REGISTRY_STATUS_OK != registry_path_exists(registry, &path)) {
        tr_info("set_connector_credentials() No credentials available.");
        return false;
    }

    registry_set_path(&path, M2M_SECURITY_ID, 0, SECURITY_SECURITY_MODE, 0, REGISTRY_PATH_RESOURCE);
    if (REGISTRY_STATUS_OK != registry_get_value_int(registry, &path, &security)) {
        tr_error("set_connector_credentials() No security mode set.");
        return false;
    }

#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE) || defined(PROTOMAN_SECURITY_ENABLE_PSK)
    // Security mode 0 = PSK.
    // Security mode 2 = Certificate.
    if (security == 0 || security == 2) {

#ifndef PROTOMAN_OFFLOAD_TLS
        registry_set_path(&path, M2M_SECURITY_ID, 0, SECURITY_PUBLIC_KEY, 0, REGISTRY_PATH_RESOURCE);
        if (REGISTRY_STATUS_OK != registry_get_value_opaque(registry, &path, &public_key)) {
            tr_error("set_connector_credentials() registry_get_value_opaque public_key failed");
            return false;
        }

        registry_set_path(&path, M2M_SECURITY_ID, 0, SECURITY_SECRET_KEY, 0, REGISTRY_PATH_RESOURCE);
        if (REGISTRY_STATUS_OK != registry_get_value_opaque(registry, &path, &sec_key)) {
            tr_error("set_connector_credentials() registry_get_value_opaque sec_key failed");
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
            tr_error("set_connector_credentials() registry_get_value_opaque sec_key failed");
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
        if (!storage_set_parameter(LWM2M_SERVER_PSK_IDENTITY, public_key->data, public_key->size)) {
            tr_error("set_connector_credentials() storage_set_parameter public_key failed");
            return false;
        }

        if (!storage_set_parameter(LWM2M_SERVER_PSK_SECRET, sec_key->data, sec_key->size)) {
            tr_error("set_connector_credentials() storage_set_parameter sec_key failed");
            return false;
        }
    }
#endif //defined(PROTOMAN_SECURITY_ENABLE_PSK)
#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
    if (security == 2) {
#ifndef PROTOMAN_OFFLOAD_TLS
        if (!storage_set_parameter(LWM2M_DEVICE_CERTIFICATE, public_key->data, public_key->size)) {
            tr_error("set_connector_credentials() storage_set_parameter public_key failed");
            return false;
        }

        if (!storage_set_parameter(LWM2M_SERVER_ROOT_CA_CERTIFICATE, ca_cert->data, ca_cert->size)) {
            tr_error("set_connector_credentials() storage_set_parameter ca_cert failed");
            return false;
        }

        if (!storage_set_parameter(LWM2M_DEVICE_PRIVATE_KEY, sec_key->data, sec_key->size)) {
            tr_error("set_connector_credentials() storage_set_parameter sec_key failed");
            return false;
        }
#endif
    }
#endif //defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)

    if (!storage_set_parameter(LWM2M_SERVER_URI, (const uint8_t*)server_uri, strlen(server_uri))) {
        tr_error("set_connector_credentials() storage_set_parameter server_uri failed");
        return false;
    }

#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    if (security == 0 || security == 2) {
        tr_info("set_connector_credentials() storage_set_parameter ok");
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
    registry_set_path(&path, M2M_SECURITY_ID, 0, 0, 0, REGISTRY_PATH_OBJECT);
    registry_remove_object(registry, &path, REGISTRY_REMOVE);

    return true;
}
#endif

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

    if (!storage_set_parameter(BOOTSTRAP_SERVER_PSK_IDENTITY, public_key->data, public_key->size)) {
        return false;
    }

    if (!storage_set_parameter(BOOTSTRAP_SERVER_PSK_SECRET, sec_key->data, sec_key->size)) {
        return false;
    }

    if (!storage_set_parameter(BOOTSTRAP_SERVER_URI, (const uint8_t*) server_uri, strlen(server_uri))) {
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
    if (!iep || !storage_set_parameter(INTERNAL_ENDPOINT, (const uint8_t*) iep, strlen(iep))) {
        tr_error("storage_set_internal_endpoint_name() setting iep failed");
        return false;
    }

    tr_info("Internal Endpoint ID %s", iep);

    return true;
}
