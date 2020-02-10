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

#ifndef PROTOMAN_LAYER_MBEDTLS_H
#define PROTOMAN_LAYER_MBEDTLS_H

#include "mbed-protocol-manager/protoman_config.h"

#ifndef PROTOMAN_OFFLOAD_TLS

#include "stdlib.h"

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/hmac_drbg.h"

#include "mbed-protocol-manager/protoman.h"
#include "mbed-protocol-manager/protoman_layer.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* https://github.com/ARMmbed/mbedtls/blob/0884f4811bc3fa272bec5e978fe8b759fef0ce9e/include/mbedtls/ssl_internal.h#L270 */
#define SSLKEYLOG_CLIENT_RANDOM_SIZE 32 /* actually 64 but we copy only first 32 of it */
/* https://github.com/ARMmbed/mbedtls/blob/0884f4811bc3fa272bec5e978fe8b759fef0ce9e/include/mbedtls/ssl.h#L557 */
#define SSLKEYLOG_MASTER_SECRET_SIZE 48
/* CLIENT_HELLO " " SSLKEYLOG_CLIENT_RANDOM_SIZE*2 + " " + SSLKEYLOG_MASTER_SECRET_SIZE*2 + \n + \0 */
#define SSLKEYLOG_ENTRY_LEN (15 + SSLKEYLOG_CLIENT_RANDOM_SIZE*2 + SSLKEYLOG_MASTER_SECRET_SIZE*2 + 1 + 1)

#if (PROTOMAN_MTU < 512 + 200)
#error "PROTOMAN_MTU must be atleast 712"
#endif
#if (MBEDTLS_SSL_MAX_CONTENT_LEN < 512 + 200)
#error "MBEDTLS_SSL_MAX_CONTENT_LEN must be atleast 712"
#endif

// Make sure that blockwise size is correctly set to match fragmentation length paramater
#if ((PROTOMAN_MTU >= 4096 * 4) && MBEDTLS_SSL_MAX_CONTENT_LEN >= 4096 * 4)
#define PROTOMAN_LAYER_MBEDTLS_MAX_FRAG_LEN MBEDTLS_SSL_MAX_FRAG_LEN_NONE
#elif ((PROTOMAN_MTU >= 4096 + 200) && MBEDTLS_SSL_MAX_CONTENT_LEN >= 4096 + 200)
#define PROTOMAN_LAYER_MBEDTLS_MAX_FRAG_LEN MBEDTLS_SSL_MAX_FRAG_LEN_4096
#elif ((PROTOMAN_MTU >= 2048 + 200) && MBEDTLS_SSL_MAX_CONTENT_LEN >= 2048 + 200)
#define PROTOMAN_LAYER_MBEDTLS_MAX_FRAG_LEN MBEDTLS_SSL_MAX_FRAG_LEN_2048
#elif (PROTOMAN_MTU >= 1024 + 200 && MBEDTLS_SSL_MAX_CONTENT_LEN >= 1024 + 200)
#define PROTOMAN_LAYER_MBEDTLS_MAX_FRAG_LEN MBEDTLS_SSL_MAX_FRAG_LEN_1024
#else
#define PROTOMAN_LAYER_MBEDTLS_MAX_FRAG_LEN MBEDTLS_SSL_MAX_FRAG_LEN_512
#endif

// Fragmentation length set to 512 bytes
#if defined (PROTOMAN_LAYER_MBEDTLS_MAX_FRAG_LEN) && (PROTOMAN_LAYER_MBEDTLS_MAX_FRAG_LEN == 1) && (SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE > 256)
#error "Blockwise size does not match to fragmentation length. SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE must be 256 or lower."
#endif

// Fragmentation length set to 1024 bytes
#if defined (PROTOMAN_LAYER_MBEDTLS_MAX_FRAG_LEN) && (PROTOMAN_LAYER_MBEDTLS_MAX_FRAG_LEN == 2) && (SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE > 512)
#error "Blockwise size does not match to fragmentation length. SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE must be 512 or lower."
#endif

void timer_set(void *timer_ctx, uint32_t int_ms, uint32_t fin_ms);
int timer_get(void *timer_ctx);
int wrapper_write(void *ctx, const uint8_t *buf, size_t len);
int wrapper_read(void *ctx, uint8_t *buf, size_t len);
int wrapper_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout);

extern void protoman_add_layer_mbedtls(struct protoman_s *protoman, struct protoman_layer_s *layer);

struct protoman_layer_mbedtls_common_s {
    struct protoman_layer_s layer;
    uint8_t handshakes_failed;
    uint8_t handshakes_max;
    uint32_t handshakes_delay_ms;
    uint32_t mbedtls_timer_started_ticks;
    uint32_t mbedtls_timer_int_ms;
    uint32_t mbedtls_timer_fin_ms;
#if !defined(MBEDTLS_SSL_CONF_RNG)
    mbedtls_entropy_context entropy;
    mbedtls_hmac_drbg_context hmac_drbg;
#endif
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
#ifdef PROTOMAN_SSLKEYLOG
    int sslkeylog_connection_id; /* used to determine reconnection number */
    int sslkeylog_previous_ssl_state; /* used to detect CLIENT_HELLO -> SERVER_HELLO transition*/
    char sslkeylog_entry[SSLKEYLOG_ENTRY_LEN]; /* store NSS key log string here */
    uint8_t sslkeylog_client_random[SSLKEYLOG_CLIENT_RANDOM_SIZE]; /* store client random here for later use */
    uint8_t sslkeylog_master_secret[SSLKEYLOG_MASTER_SECRET_SIZE]; /* store master secret here and monitor for change */
#endif // PROTOMAN_SSLKEYLOG
};

#ifdef PROTOMAN_SECURITY_ENABLE_CERTIFICATE
struct protoman_layer_mbedtls_certificate_s {
    struct protoman_layer_mbedtls_common_s common; /* must be first entry */
    struct protoman_config_tls_certificate_s config; /* must be second element */
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt owncert;
    mbedtls_pk_context ownkey;
};
#endif // PROTOMAN_SECURITY_ENABLE_CERTIFICATE

struct protoman_layer_mbedtls_psk_s {
    struct protoman_layer_mbedtls_common_s common; /* must be first entry */
    struct protoman_config_tls_psk_s config;  /* must be second element */
};

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // PROTOMAN_OFFLOAD_TLS
#endif // PROTOMAN_LAYER_MBEDTLS_H
