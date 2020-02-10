/*
 * PackageLicenseDeclared: Apache-2.0
 * Copyright (c) 2017-2018 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#ifndef PROTOMAN_LAYER_MBEDTLS_SSLKEYLOG_H
#define PROTOMAN_LAYER_MBEDTLS_SSLKEYLOG_H

#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"

#include "mbed-protocol-manager/protoman.h"
#include "mbed-protocol-manager/protoman_layer.h"
#include "mbed-protocol-manager/protoman_layer_mbedtls.h"

#ifndef PROTOMAN_SSLKEYLOG

#define protoman_sslkeylog_snapshot_client_random(layer)
#define protoman_sslkeylog_snapshot_master_secret(layer)
#define protoman_sslkeylog_update_file(layer)
#define protoman_sslkeylog_update_entry(layer)

#else /* PROTOMAN_SSLKEYLOG is defined */

#error "WARNING: defining PROTOMAN_SSLKEYLOG will make the secure connection secrets to be printed to the debug log. It makes the connection vulnerable."
#define protoman_sslkeylog_snapshot_client_random(layer) _sslkeylog_snapshot_client_random(layer)
#define protoman_sslkeylog_snapshot_master_secret(layer) _sslkeylog_snapshot_master_secret(layer)
#define protoman_sslkeylog_update_file(layer) _sslkeylog_update_file(layer)
#define protoman_sslkeylog_update_entry(layer) _sslkeylog_update_entry(layer)

/**
 * @brief      Takes a snapshot of client random to own memory. This needs to be
 *             captured when on ssl.state == MBEDTLS_SSL_CLIENT_HELLO.
 *
 * @param      layer  Pointer to the mbedtls layer
 */
void _sslkeylog_snapshot_client_random(struct protoman_layer_s *layer);

/**
 * @brief      Takes a snapshot of master secret to own memory
 *
 * @param      layer  Pointer to the mbedtls layer
 */
void _sslkeylog_snapshot_master_secret(struct protoman_layer_s *layer);

/**
 * @brief      Write layer->sslkeylog_entry to file.
 *
 * @param      layer  Pointer to the mbedtls layer
 */
void _sslkeylog_update_file(struct protoman_layer_s *layer);

/**
 * @brief      Create layer->sslkeylog_entry string.
 *
 * @param      layer  Pointer to the mbedtls layer
 */
void _sslkeylog_update_entry(struct protoman_layer_s *layer);
#endif // PROTOMAN_SSLKEYLOG
#endif // PROTOMAN_LAYER_MBEDTLS_SSLKEYLOG_H

#ifdef __cplusplus
}
#endif //__cplusplus
