// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
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

#ifndef MBEDTLS_CUSTOM_CONFIG_H
#define MBEDTLS_CUSTOM_CONFIG_H

/* System support */
#define MBEDTLS_HAVE_ASM

/* Crypto flags */
#define MBEDTLS_X509_CSR_WRITE_C
#define MBEDTLS_X509_CREATE_C

/* mbed TLS feature support */
#undef MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_PROTO_DTLS
#define MBEDTLS_SSL_DTLS_ANTI_REPLAY
#define MBEDTLS_SSL_DTLS_HELLO_VERIFY
#define MBEDTLS_SSL_EXPORT_KEYS

/* mbed TLS modules */
#define MBEDTLS_AES_C
#define MBEDTLS_AES_FEWER_TABLES
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_HMAC_DRBG_C
#undef MBEDTLS_ECP_C // MBEDTLS_USE_TINYCRYPT can't be enabled together with this one
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_MD_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_SSL_COOKIE_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_CIPHER_MODE_CTR

// Use global functions for timer get/set
//#define MBEDTLS_SSL_CONF_GET_TIMER timer_get
//#define MBEDTLS_SSL_CONF_SET_TIMER timer_set

// Use global read/write/read_timeout functions
//#define MBEDTLS_SSL_CONF_RECV wrapper_read
//#define MBEDTLS_SSL_CONF_SEND wrapper_write
//#define MBEDTLS_SSL_CONF_RECV_TIMEOUT wrapper_recv_timeout
//#define MBEDTLS_SSL_CONF_RNG global_rng

// XXX mbedclient needs these: mbedtls_x509_crt_free, mbedtls_x509_crt_init, mbedtls_x509_crt_parse
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
// a bit wrong way to get mbedtls_ssl_conf_psk:

#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA256_SMALLER
#undef MBEDTLS_ECDH_C
#undef MBEDTLS_ECDSA_C

// Remove RSA, save 20KB at total
#undef MBEDTLS_RSA_C
#undef MBEDTLS_PK_RSA_ALT_SUPPORT
#undef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED

// Remove error messages, save 10KB of ROM
#undef MBEDTLS_ERROR_C

// Remove selftesting and save 11KB of ROM
#undef MBEDTLS_SELF_TEST

// Reduces ROM size by 30 kB
#undef MBEDTLS_ERROR_STRERROR_DUMMY
#undef MBEDTLS_VERSION_FEATURES
#undef MBEDTLS_DEBUG_C

// Reduce IO buffer to save RAM, default is 16KB
#define MBEDTLS_SSL_MAX_CONTENT_LEN 1024

// define to save 8KB RAM at the expense of ROM
#define MBEDTLS_AES_ROM_TABLES

// Save ROM and a few bytes of RAM by specifying our own ciphersuite list
#define MBEDTLS_SSL_CIPHERSUITES MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8

// Enable usage of Connection ID
#undef MBEDTLS_SSL_DTLS_CONNECTION_ID

#undef MBEDTLS_SHA512_C

/* Charger requires DTLS server */
#if MBED_CONF_CONNECTION_SERVICE_ENABLE_SERVER
#define MBEDTLS_SSL_SRV_C
#else
#undef MBEDTLS_SSL_SRV_C
#endif

// Default timeouts need increasing as the handshakes take now longer
// due to sidechannel countermeasures.
#undef MBEDTLS_SSL_CONF_HS_TIMEOUT_MIN
#define MBEDTLS_SSL_CONF_HS_TIMEOUT_MIN 20000

#undef MBEDTLS_SSL_CONF_HS_TIMEOUT_MAX
#define MBEDTLS_SSL_CONF_HS_TIMEOUT_MAX 60000

#undef MBEDTLS_ECP_DP_SECP192R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP224R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP384R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP521R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP192K1_ENABLED
#undef MBEDTLS_ECP_DP_SECP224K1_ENABLED
#undef MBEDTLS_ECP_DP_SECP256K1_ENABLED
#undef MBEDTLS_ECP_DP_BP256R1_ENABLED
#undef MBEDTLS_ECP_DP_BP384R1_ENABLED
#undef MBEDTLS_ECP_DP_BP512R1_ENABLED
#undef MBEDTLS_ECP_DP_CURVE25519_ENABLED

#undef MBEDTLS_VERSION_C
#undef MBEDTLS_CERTS_C

#undef MBEDTLS_CHACHA20_C
#undef MBEDTLS_CHACHAPOLY_C
#undef MBEDTLS_POLY1305_C

#undef MBEDTLS_PEM_PARSE_C

// Reduces ROM size by 2kB
#undef MBEDTLS_GCM_C

// Try to make the TCP&TLS work on pmi-arm-firmware's mbedtls,
// which has now disabled the TLS support by default.
#if defined(MBEDTLS_SSL_PROTO_NO_TLS) && defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP)
#undef MBEDTLS_SSL_PROTO_NO_TLS
#endif

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CUSTOM_CONFIG_H */
