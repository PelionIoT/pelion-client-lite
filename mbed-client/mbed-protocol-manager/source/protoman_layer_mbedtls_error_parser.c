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

#include "mbed-protocol-manager/protoman_config.h"

#ifndef PROTOMAN_OFFLOAD_TLS

#include "include/protoman_layer_mbedtls_error_parser.h"

#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

#include <stdint.h>

#ifdef PROTOMAN_ERROR_STRING
const char *protoman_strmbedtls_handshake(int state)
{
    switch (state) {
        case MBEDTLS_SSL_HELLO_REQUEST:
            return "MBEDTLS_SSL_HELLO_REQUEST";
        case MBEDTLS_SSL_CLIENT_HELLO:
            return "MBEDTLS_SSL_CLIENT_HELLO";
        case MBEDTLS_SSL_SERVER_HELLO:
            return "MBEDTLS_SSL_SERVER_HELLO";
        case MBEDTLS_SSL_SERVER_CERTIFICATE:
            return "MBEDTLS_SSL_SERVER_CERTIFICATE";
        case MBEDTLS_SSL_SERVER_KEY_EXCHANGE:
            return "MBEDTLS_SSL_SERVER_KEY_EXCHANGE";
        case MBEDTLS_SSL_CERTIFICATE_REQUEST:
            return "MBEDTLS_SSL_CERTIFICATE_REQUEST";
        case MBEDTLS_SSL_SERVER_HELLO_DONE:
            return "MBEDTLS_SSL_SERVER_HELLO_DONE";
        case MBEDTLS_SSL_CLIENT_CERTIFICATE:
            return "MBEDTLS_SSL_CLIENT_CERTIFICATE";
        case MBEDTLS_SSL_CLIENT_KEY_EXCHANGE:
            return "MBEDTLS_SSL_CLIENT_KEY_EXCHANGE";
        case MBEDTLS_SSL_CERTIFICATE_VERIFY:
            return "MBEDTLS_SSL_CERTIFICATE_VERIFY";
        case MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC:
            return "MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC";
        case MBEDTLS_SSL_CLIENT_FINISHED:
            return "MBEDTLS_SSL_CLIENT_FINISHED";
        case MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC:
            return "MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC";
        case MBEDTLS_SSL_SERVER_FINISHED:
            return "MBEDTLS_SSL_SERVER_FINISHED";
        case MBEDTLS_SSL_FLUSH_BUFFERS:
            return "MBEDTLS_SSL_FLUSH_BUFFERS";
        case MBEDTLS_SSL_HANDSHAKE_WRAPUP:
            return "MBEDTLS_SSL_HANDSHAKE_WRAPUP";
        case MBEDTLS_SSL_HANDSHAKE_OVER:
            return "MBEDTLS_SSL_HANDSHAKE_OVER";
        case MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET:
            return "MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET";
        case MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT:
            return "MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT";
        default:
            return "UNKNOWN";
    }
}

const char *protoman_strmbedtls(int errcode)
{
    switch (errcode) {
        case MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE:
            return "MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE";
        case MBEDTLS_ERR_SSL_BAD_INPUT_DATA:
            return "MBEDTLS_ERR_SSL_BAD_INPUT_DATA";
        case MBEDTLS_ERR_SSL_INVALID_MAC:
            return "MBEDTLS_ERR_SSL_INVALID_MAC";
        case MBEDTLS_ERR_SSL_INVALID_RECORD:
            return "MBEDTLS_ERR_SSL_INVALID_RECORD";
        case MBEDTLS_ERR_SSL_CONN_EOF:
            return "MBEDTLS_ERR_SSL_CONN_EOF";
        case MBEDTLS_ERR_SSL_UNKNOWN_CIPHER:
            return "MBEDTLS_ERR_SSL_UNKNOWN_CIPHER";
        case MBEDTLS_ERR_SSL_NO_CIPHER_CHOSEN:
            return "MBEDTLS_ERR_SSL_NO_CIPHER_CHOSEN";
        case MBEDTLS_ERR_SSL_NO_RNG:
            return "MBEDTLS_ERR_SSL_NO_RNG";
        case MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE:
            return "MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE";
        case MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE:
            return "MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE";
        case MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED:
            return "MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED";
        case MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED:
            return "MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED";
        case MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED:
            return "MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED";
        case MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE:
            return "MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE";
        case MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE:
            return "MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE";
        case MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED:
            return "MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED";
        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
            return "MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY";
        case MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO:
            return "MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO";
        case MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO:
            return "MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO";
        case MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE:
            return "MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE";
        case MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST:
            return "MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST";
        case MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE:
            return "MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE";
        case MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO_DONE:
            return "MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO_DONE";
        case MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE:
            return "MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE";
        case MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP:
            return "MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP";
        case MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS:
            return "MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS";
        case MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY:
            return "MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY";
        case MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC:
            return "MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC";
        case MBEDTLS_ERR_SSL_BAD_HS_FINISHED:
            return "MBEDTLS_ERR_SSL_BAD_HS_FINISHED";
        case MBEDTLS_ERR_SSL_ALLOC_FAILED:
            return "MBEDTLS_ERR_SSL_ALLOC_FAILED";
        case MBEDTLS_ERR_SSL_HW_ACCEL_FAILED:
            return "MBEDTLS_ERR_SSL_HW_ACCEL_FAILED";
        case MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH:
            return "MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH";
        case MBEDTLS_ERR_SSL_COMPRESSION_FAILED:
            return "MBEDTLS_ERR_SSL_COMPRESSION_FAILED";
        case MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION:
            return "MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION";
        case MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET:
            return "MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET";
        case MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED:
            return "MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED";
        case MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH:
            return "MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH";
        case MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY:
            return "MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY";
        case MBEDTLS_ERR_SSL_INTERNAL_ERROR:
            return "MBEDTLS_ERR_SSL_INTERNAL_ERROR";
        case MBEDTLS_ERR_SSL_COUNTER_WRAPPING:
            return "MBEDTLS_ERR_SSL_COUNTER_WRAPPING";
        case MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO:
            return "MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO";
        case MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED:
            return "MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED";
        case MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL:
            return "MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL";
        case MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE:
            return "MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE";
        case MBEDTLS_ERR_SSL_WANT_READ:
            return "MBEDTLS_ERR_SSL_WANT_READ";
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            return "MBEDTLS_ERR_SSL_WANT_WRITE";
        case MBEDTLS_ERR_SSL_TIMEOUT:
            return "MBEDTLS_ERR_SSL_TIMEOUT";
        case MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
            return "MBEDTLS_ERR_SSL_CLIENT_RECONNECT";
        case MBEDTLS_ERR_SSL_UNEXPECTED_RECORD:
            return "MBEDTLS_ERR_SSL_UNEXPECTED_RECORD";
        case MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE:
            return "MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE";
        case MBEDTLS_ERR_X509_UNKNOWN_OID:
            return "MBEDTLS_ERR_X509_UNKNOWN_OID";
        case MBEDTLS_ERR_X509_INVALID_FORMAT:
            return "MBEDTLS_ERR_X509_INVALID_FORMAT";
        case MBEDTLS_ERR_X509_INVALID_VERSION:
            return "MBEDTLS_ERR_X509_INVALID_VERSION";
        case MBEDTLS_ERR_X509_INVALID_SERIAL:
            return "MBEDTLS_ERR_X509_INVALID_SERIAL";
        case MBEDTLS_ERR_X509_INVALID_ALG:
            return "MBEDTLS_ERR_X509_INVALID_ALG";
        case MBEDTLS_ERR_X509_INVALID_NAME:
            return "MBEDTLS_ERR_X509_INVALID_NAME";
        case MBEDTLS_ERR_X509_INVALID_DATE:
            return "MBEDTLS_ERR_X509_INVALID_DATE";
        case MBEDTLS_ERR_X509_INVALID_SIGNATURE:
            return "MBEDTLS_ERR_X509_INVALID_SIGNATURE";
        case MBEDTLS_ERR_X509_INVALID_EXTENSIONS:
            return "MBEDTLS_ERR_X509_INVALID_EXTENSIONS";
        case MBEDTLS_ERR_X509_UNKNOWN_VERSION:
            return "MBEDTLS_ERR_X509_UNKNOWN_VERSION";
        case MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG:
            return "MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG";
        case MBEDTLS_ERR_X509_SIG_MISMATCH:
            return "MBEDTLS_ERR_X509_SIG_MISMATCH";
        case MBEDTLS_ERR_X509_CERT_VERIFY_FAILED:
            return "MBEDTLS_ERR_X509_CERT_VERIFY_FAILED";
        case MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT:
            return "MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT";
        case MBEDTLS_ERR_X509_BAD_INPUT_DATA:
            return "MBEDTLS_ERR_X509_BAD_INPUT_DATA";
        case MBEDTLS_ERR_X509_ALLOC_FAILED:
            return "MBEDTLS_ERR_X509_ALLOC_FAILED";
        case MBEDTLS_ERR_X509_FILE_IO_ERROR:
            return "MBEDTLS_ERR_X509_FILE_IO_ERROR";
        case MBEDTLS_ERR_X509_BUFFER_TOO_SMALL:
            return "MBEDTLS_ERR_X509_BUFFER_TOO_SMALL";
#if defined(MBEDTLS_ERR_PLATFORM_FAULT_DETECTED)
        case MBEDTLS_ERR_PLATFORM_FAULT_DETECTED:
            return "MBEDTLS_ERR_PLATFORM_FAULT_DETECTED";
#endif
        default:
            return "UNKNOWN";
    }
}
#endif // PROTOMAN_ERROR_STRING
#endif // !PROTOMAN_OFFLOAD_TLS
