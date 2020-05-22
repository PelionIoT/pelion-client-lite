#!/bin/bash
#
# Copyright (c) 2020 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an AS IS BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Purpose
#
# Comments and uncomments #define lines in the given configuration header file
# to configure the file for use in mbed OS.
#
# Usage: adjust-config.sh [path to config script] [path to config file]
#
set -eu

if [ $# -ne 2 ]; then
    echo "Usage: $0 path/to/config.pl path/to/config.h" >&2
    exit 1
fi

SCRIPT=$1
FILE=$2

conf() {
    $SCRIPT -f $FILE --force $@
}

add_code() {
    MATCH_PATTERN="$1"
    shift
    CODE=$(IFS=""; printf "%s" "$*")

    perl -i -pe                                    \
        "s/$MATCH_PATTERN/$MATCH_PATTERN$CODE/igs" \
        "$FILE"
}

# add an #ifndef to include config-no-entropy.h when the target does not have
# an entropy source we can use.
add_code                                                                                          \
    "#ifndef MBEDTLS_CONFIG_H\n"                                                                  \
    "\n"                                                                                          \
    "#include \"platform\/inc\/platform_mbed.h\"\n"                                               \
    "\n"                                                                                          \
    "\/*\n"                                                                                       \
    " * Only use features that do not require an entropy source when\n"                           \
    " * DEVICE_ENTROPY_SOURCE is not defined in mbed OS.\n"                                       \
    " *\/\n"                                                                                      \
    "#if !defined(MBEDTLS_ENTROPY_HARDWARE_ALT) && !defined(MBEDTLS_TEST_NULL_ENTROPY) && \\\\\n" \
    "    !defined(MBEDTLS_ENTROPY_NV_SEED)\n"                                                     \
    "#include \"mbedtls\/config-no-entropy.h\"\n"                                                 \
    "\n"                                                                                          \
    "#if defined(MBEDTLS_USER_CONFIG_FILE)\n"                                                     \
    "#include MBEDTLS_USER_CONFIG_FILE\n"                                                         \
    "#endif\n"                                                                                    \
    "\n"                                                                                          \
    "#else\n"

add_code                                                                                                       \
    "#include \"check_config.h\"\n"                                                                            \
    "\n"                                                                                                       \
    "#endif \/* !MBEDTLS_ENTROPY_HARDWARE_ALT && !MBEDTLS_TEST_NULL_ENTROPY && !MBEDTLS_ENTROPY_NV_SEED *\/\n" \
    "\n"                                                                                                       \
    "#if defined(MBEDTLS_TEST_NULL_ENTROPY)\n"                                                                 \
    "#warning \"MBEDTLS_TEST_NULL_ENTROPY has been enabled. This \" \\\\\n"                                    \
    "    \"configuration is not secure and is not suitable for production use\"\n"                             \
    "#endif\n"                                                                                                 \
    "\n"                                                                                                       \
    "#if defined(MBEDTLS_SSL_TLS_C) && !defined(MBEDTLS_TEST_NULL_ENTROPY) && \\\\\n"                          \
    "    !defined(MBEDTLS_ENTROPY_HARDWARE_ALT) && !defined(MBEDTLS_ENTROPY_NV_SEED)\n"                        \
    "#error \"No entropy source was found at build time, so TLS \" \\\\\n"                                     \
    "    \"functionality is not available\"\n"                                                                 \
    "#endif\n"

# not supported on mbed OS, nor used by mbed Client
conf unset MBEDTLS_NET_C
conf unset MBEDTLS_TIMING_C

# not supported on all targets with mbed OS, nor used by mbed Client
conf unset MBEDTLS_HAVE_TIME_DATE
conf unset MBEDTLS_FS_IO
conf set MBEDTLS_NO_PLATFORM_ENTROPY

conf unset MBEDTLS_CIPHER_MODE_CFB
conf unset MBEDTLS_CIPHER_MODE_OFB
conf unset MBEDTLS_CIPHER_MODE_CTR
conf unset MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS
conf unset MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN
conf unset MBEDTLS_CIPHER_PADDING_ZEROS
conf unset MBEDTLS_CIPHER_MODE_XTS
conf unset MBEDTLS_ECP_DP_SECP192R1_ENABLED
conf unset MBEDTLS_ECP_DP_SECP224R1_ENABLED
conf unset MBEDTLS_ECP_DP_SECP521R1_ENABLED
conf unset MBEDTLS_ECP_DP_SECP192K1_ENABLED
conf unset MBEDTLS_ECP_DP_SECP224K1_ENABLED
conf unset MBEDTLS_ECP_DP_SECP256K1_ENABLED
conf unset MBEDTLS_ECP_DP_SECP384R1_ENABLED
conf unset MBEDTLS_ECP_DP_SECP256R1_ENABLED
conf unset MBEDTLS_ECP_DP_BP256R1_ENABLED
conf unset MBEDTLS_ECP_DP_BP384R1_ENABLED
conf unset MBEDTLS_ECP_DP_BP512R1_ENABLED
conf unset MBEDTLS_ECP_DP_CURVE448_ENABLED
conf unset MBEDTLS_ECP_DP_CURVE25519_ENABLED

conf unset MBEDTLS_PK_PARSE_EC_EXTENDED

conf set MBEDTLS_ECP_WINDOW_SIZE                        2
conf set MBEDTLS_ECP_FIXED_POINT_OPTIM                  0
conf set MBEDTLS_ECP_MAX_BITS                           256
conf set MBEDTLS_MPI_MAX_SIZE                           32     # 256 bits = 32 bytes

conf set MBEDTLS_SSL_CONF_SINGLE_EC
conf set MBEDTLS_SSL_CONF_SINGLE_EC_GRP_ID MBEDTLS_ECP_DP_SECP256R1
conf set MBEDTLS_SSL_CONF_SINGLE_EC_TLS_ID 23
conf set MBEDTLS_SSL_CONF_SINGLE_UECC_GRP_ID MBEDTLS_UECC_DP_SECP256R1
conf set MBEDTLS_SSL_CONF_SINGLE_SIG_HASH
conf set MBEDTLS_SSL_CONF_SINGLE_SIG_HASH_MD_ID         MBEDTLS_MD_SHA256
conf set MBEDTLS_SSL_CONF_SINGLE_SIG_HASH_TLS_ID        MBEDTLS_SSL_HASH_SHA256

conf set MBEDTLS_MD_SINGLE_HASH MBEDTLS_MD_INFO_SHA256
conf set MBEDTLS_PK_SINGLE_TYPE MBEDTLS_PK_INFO_ECKEY

conf set MBEDTLS_X509_MAX_INTERMEDIATE_CA 2

conf unset MBEDTLS_AESNI_C
conf unset MBEDTLS_ARC4_C
conf unset MBEDTLS_BLOWFISH_C
conf unset MBEDTLS_CAMELLIA_C
conf unset MBEDTLS_DES_C
conf unset MBEDTLS_DHM_C
conf unset MBEDTLS_GENPRIME
conf unset MBEDTLS_MD5_C
conf unset MBEDTLS_PADLOCK_C
conf unset MBEDTLS_PEM_WRITE_C
conf unset MBEDTLS_PKCS5_C
conf unset MBEDTLS_PKCS12_C
conf unset MBEDTLS_RIPEMD160_C
conf unset MBEDTLS_SHA1_C
conf unset MBEDTLS_XTEA_C
conf unset MBEDTLS_SHA512_C
conf set MBEDTLS_CMAC_C

conf set MBEDTLS_SHA256_NO_SHA224

# Disable TLS
conf set MBEDTLS_SSL_PROTO_NO_TLS

# Disable everything related to session resumption
conf unset MBEDTLS_SSL_SESSION_TICKETS
conf set MBEDTLS_SSL_NO_SESSION_CACHE
conf set MBEDTLS_SSL_NO_SESSION_RESUMPTION

# X.509 related optimization options
conf set MBEDTLS_X509_REMOVE_INFO            # No xxx_info() API
conf set MBEDTLS_X509_CRT_REMOVE_TIME
conf set MBEDTLS_X509_CRT_REMOVE_SUBJECT_ISSUER_ID
conf unset MBEDTLS_SSL_KEEP_PEER_CERTIFICATE # Don't keep CRT
conf set MBEDTLS_X509_ON_DEMAND_PARSING      # Minimize RAM usage of X.509
conf set MBEDTLS_X509_ALWAYS_FLUSH

conf set MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION
conf set MBEDTLS_X509_REMOVE_VERIFY_CALLBACK

# Hardcoding of SSL configuration
conf set MBEDTLS_SSL_CONF_CERT_REQ_CA_LIST               MBEDTLS_SSL_CERT_REQ_CA_LIST_DISABLED

# TODO - Endpoint needs to be changed to be dependent on the target
# configuration eg. holder or charger
#conf set MBEDTLS_SSL_CONF_ENDPOINT MBEDTLS_SSL_IS_CLIENT

conf set MBEDTLS_SSL_DTLS_CONNECTION_ID
conf set MBEDTLS_SSL_CONF_CID_LEN                        0
conf set MBEDTLS_SSL_CONF_IGNORE_UNEXPECTED_CID          MBEDTLS_SSL_UNEXPECTED_CID_IGNORE
conf set MBEDTLS_SSL_CONF_ALLOW_LEGACY_RENEGOTIATION     MBEDTLS_SSL_SECURE_RENEGOTIATION
conf set MBEDTLS_SSL_CONF_AUTHMODE                       MBEDTLS_SSL_VERIFY_REQUIRED
conf set MBEDTLS_SSL_CONF_BADMAC_LIMIT                   0
conf set MBEDTLS_SSL_CONF_ANTI_REPLAY                    MBEDTLS_SSL_ANTI_REPLAY_ENABLED
conf set MBEDTLS_SSL_CONF_EXTENDED_MASTER_SECRET         MBEDTLS_SSL_EXTENDED_MS_ENABLED
conf set MBEDTLS_SSL_CONF_ENFORCE_EXTENDED_MASTER_SECRET MBEDTLS_SSL_EXTENDED_MS_ENFORCE_ENABLED
conf set MBEDTLS_SSL_CONF_READ_TIMEOUT 0
conf set MBEDTLS_SSL_CONF_HS_TIMEOUT_MIN 1000
conf set MBEDTLS_SSL_CONF_HS_TIMEOUT_MAX 16000

conf set MBEDTLS_SSL_CONF_MIN_MINOR_VER MBEDTLS_SSL_MINOR_VERSION_3
conf set MBEDTLS_SSL_CONF_MAX_MINOR_VER MBEDTLS_SSL_MINOR_VERSION_3
conf set MBEDTLS_SSL_CONF_MIN_MAJOR_VER MBEDTLS_SSL_MAJOR_VERSION_3
conf set MBEDTLS_SSL_CONF_MAX_MAJOR_VER MBEDTLS_SSL_MAJOR_VERSION_3

conf set MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE MBEDTLS_SUITE_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8

conf set MBEDTLS_SSL_CONF_RNG global_rng

conf set MBEDTLS_USE_TINYCRYPT

conf unset MBEDTLS_ECP_C
conf unset MBEDTLS_ECDH_C
conf unset MBEDTLS_ECDSA_C

conf set MBEDTLS_DEPRECATED_REMOVED

conf set MBEDTLS_HMAC_DRBG_C
conf unset MBEDTLS_CTR_DRBG_C
conf unset MBEDTLS_PK_RSA_ALT_SUPPORT

conf unset MBEDTLS_RSA_C
conf unset MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED


#TODO - need to enable the hardwired functions
#conf set MBEDTLS_SSL_CONF_GET_TIMER mbedtls_timing_get_delay
#conf set MBEDTLS_SSL_CONF_SET_TIMER mbedtls_timing_set_delay
#conf set MBEDTLS_SSL_CONF_RECV mbedtls_net_recv
#conf set MBEDTLS_SSL_CONF_SEND mbedtls_net_send
#conf set MBEDTLS_SSL_CONF_RECV_TIMEOUT mbedtls_net_recv_timeout

conf set MBEDTLS_AES_ROM_TABLES
conf set MBEDTLS_AES_FEWER_TABLES
conf set MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH
conf set MBEDTLS_AES_ONLY_ENCRYPT
conf set MBEDTLS_AES_SCA_COUNTERMEASURES

conf set MBEDTLS_ENTROPY_MAX_SOURCES 3

conf unset MBEDTLS_X509_RSASSA_PSS_SUPPORT

conf unset MBEDTLS_X509_CSR_PARSE_C
conf unset MBEDTLS_X509_CREATE_C
conf unset MBEDTLS_X509_CRT_WRITE_C
conf unset MBEDTLS_X509_CSR_WRITE_C

conf unset MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
conf unset MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
conf unset MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
conf unset MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
conf unset MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
conf unset MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
conf unset MBEDTLS_SSL_FALLBACK_SCSV
conf unset MBEDTLS_SSL_CBC_RECORD_SPLITTING
conf unset MBEDTLS_SSL_PROTO_TLS1
conf unset MBEDTLS_SSL_PROTO_TLS1_1
conf unset MBEDTLS_SSL_TRUNCATED_HMAC

conf unset MBEDTLS_PLATFORM_TIME_TYPE_MACRO
