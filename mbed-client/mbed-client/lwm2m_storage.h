/*
 * Copyright (c) 2018 - 2019 ARM Limited. All rights reserved.
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

#ifndef LWM2M_STORAGE_H
#define LWM2M_STORAGE_H

/*! \file lwm2m_storage.h
 *  \brief Client Lite internal LwM2M and Device Management endpoint logic API.
 */

#include "include/CloudClientStorage.h"

#ifdef __cplusplus
extern "C" {
#endif

bool storage_set_parameter(cloud_client_param  key, const uint8_t *buffer, const size_t buffer_size);

char *storage_read_endpoint_name(char *buffer, int32_t *buffer_size, const bool bootstrap);

char *storage_read_uri(char *buffer, int32_t *buffer_size, bool bootstrap);

bool storage_registration_credentials_available(void);

#if defined(PROTOMAN_SECURITY_ENABLE_PSK)
bool storage_read_psk(void *buffer, size_t *buffer_size, bool bootstrap);

bool storage_read_psk_id(void *buffer, size_t *buffer_size, bool bootstrap);
#endif //defined(PROTOMAN_SECURITY_ENABLE_PSK)

#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)
const void *storage_read_certificate(size_t *buffer_size, bool bootstrap);

const void *storage_read_certificate_key(size_t *buffer_size, bool bootstrap);

const void *storage_read_ca_certificate(size_t *buffer_size, bool bootstrap);
#endif //defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE)

bool storage_set_credentials(registry_t *registry);

bool storage_set_bootstrap_credentials(registry_t *registry);

char *storage_read_internal_endpoint_name(char *buffer, int32_t *buffer_size, const bool bootstrap);
bool storage_set_internal_endpoint_name(const char *iep);

#ifdef __cplusplus
}
#endif

#endif //LWM2M_STORAGE_H
