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
#include <stdio.h>
#include <stdint.h>
#include <stddef.h> /* offsetof() */
#include <string.h>

#include "nanostack-event-loop/eventOS_event.h"
#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"

#include "mbed-protocol-manager/protoman_layer_mbedtls.h"

#define TRACE_GROUP  "mTLS"
#include "include/protoman_internal.h"
#include "include/protoman_layer_mbedtls_timer.h"
#include "include/protoman_layer_mbedtls_sslkeylog.h"
#include "include/protoman_layer_mbedtls_error_parser.h"

static void layer_event(struct protoman_layer_s *layer, int event_id);

static int _do_init(struct protoman_layer_s *layer);
static int _do_connect(struct protoman_layer_s *layer);
static int _do_write(struct protoman_layer_s *layer);
static int _do_read(struct protoman_layer_s *layer);
static int _do_disconnect(struct protoman_layer_s *layer);
static int _do_resume(struct protoman_layer_s *layer);
//static int _do_pause(struct protoman_layer_s *layer);
static void layer_free(struct protoman_layer_s *layer);
static void print_cid(struct protoman_layer_s *layer, const char* prefix);
/* macro's for checking defines */
#define MAKE_CHECK_T( X ) X ## _check
#define MAKE_CHECK( X ) MAKE_CHECK_T( X )

/* Mbed TLS contains secure memcpy, use if available */
#if defined(MBEDTLS_ERR_PLATFORM_FAULT_DETECTED)
#define PROTOMAN_MEMCPY mbedtls_platform_memcpy
#define PROTOMAN_MEMSET mbedtls_platform_memset
#else
#define PROTOMAN_MEMCPY memcpy
#define PROTOMAN_MEMSET memset
#endif

#ifdef PROTOMAN_ERROR_STRING
static const char _mbedtls_error[] = "mbedTLS passes read and write errors through it, this error can be from mbedTLS or underlaying layer";
#endif // PROTOMAN_ERROR_STRING

#ifdef PROTOMAN_USE_SSL_SESSION_RESUME
#include "storage/include/CloudClientStorage.h"

/** Following items need to be stored from mbedtlsssl_session info structure
    to do the ssl session resumption.*/
//int ciphersuite;            /*!< chosen ciphersuite */
//size_t id_len;              /*!< session id length  */
//unsigned char id[32];       /*!< session identifier */
//unsigned char master[48];   /*!< the master secret  */

// Size of the session data
static const int ssl_session_size = 92;

static void store_ssl_session(struct protoman_layer_s *layer);
static void load_ssl_session(struct protoman_layer_s *layer);
#endif //PROTOMAN_USE_SSL_SESSION_RESUME

static const struct protoman_layer_callbacks_s callbacks = {
    NULL,
    &protoman_generic_bytes_layer_read,
    &protoman_generic_bytes_layer_write,
    &layer_event,
    &layer_free,
    &_do_init,
    &_do_connect,
    &_do_read,
    &_do_write,
    &_do_disconnect,
    NULL, // &_do_pause
    _do_resume  // &_do_resume
};

void protoman_add_layer_mbedtls(struct protoman_s *protoman, struct protoman_layer_s *layer)
{
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *)layer;

    /* layer struct initial values */
#ifdef MBED_CONF_MBED_TRACE_ENABLE
    layer->name = "mbed TLS"; // must be set before first print from this layer
#else
    layer->name = NULL;
#endif

    protoman_debug("");

    // XXX: ugh, a pointer arithmetic inside a struct, there must be a better way to do this.
    // Even a union would be better than this.
    layer->config = ((uint8_t*)layer + offsetof(struct protoman_layer_mbedtls_psk_s, config)); /* both certificate and psk have config as second element */

    layer->callbacks = &callbacks;

    /* mbedtls common initial values */
    layer_mbedtls_common->handshakes_failed = 0;
    layer_mbedtls_common->handshakes_max = 10;
    layer_mbedtls_common->handshakes_delay_ms = 5000;

    protoman_add_layer(protoman, layer);
}

#if defined(MBEDTLS_DEBUG_C)
//void(*)(           void *,    int,       const char *,     int,      const char *)
static void _wrapper_print(void *ctx, int level, const char *file, int line, const char *str)
{
#ifdef PROTOMAN_VERBOSE
    struct protoman_layer_s *layer = ctx;

    const char *pos = strrchr(file, '/');

    int str_len = (int)strlen(str);
    if ((str_len > 0) && (str[str_len - 1] == '\n')) {
        // Strip the trailing 'LF' added by mbedtls' debug macro so there will not be empty lines
        // between trace lines as the mbed-trace also adds a linefeed.
        str_len--;
    }
    protoman_verbose("%s:%04d: %.*s", pos == NULL ? file : pos, line, str_len, str);
    // Get rid of warnings in case tracing disabled or not at specific level
    (void)pos;
    (void)str_len;
#endif
    (void)ctx;
    (void)level;
    (void)file;
    (void)line;
    (void)str;
}
#endif

/* New replacement write */
int wrapper_write(void *ctx, const uint8_t *buf, size_t len)
{
    struct protoman_layer_s *layer = ctx;
    ssize_t retval;

    protoman_verbose("");

    /* Do operation */
    struct protoman_io_bytes_s op_bytes;
    op_bytes.header.type = PROTOMAN_IO_BYTES;
    op_bytes.buf = (uint8_t *)buf; /* The data will be copied in next layer without modifications */
    op_bytes.len = len;
    retval = (int)protoman_layer_write_next(layer, (struct protoman_io_header_s *)&op_bytes);

    /* Error translation */
    if (PROTOMAN_ERR_WOULDBLOCK == retval) {
        retval = MBEDTLS_ERR_SSL_WANT_WRITE;
    }

    return retval;
}

int wrapper_read(void *ctx, uint8_t *buf, size_t len)
{
    struct protoman_layer_s *layer = ctx;
    ssize_t retval;

    protoman_verbose("");

    /* Do operation */
    struct protoman_io_bytes_s op_bytes;
    op_bytes.header.type = PROTOMAN_IO_BYTES;
    op_bytes.buf = buf;
    op_bytes.len = len;
    retval = (int)protoman_layer_read_next(layer, (struct protoman_io_header_s *)&op_bytes);

    /* Error translation */
    if (PROTOMAN_ERR_WOULDBLOCK == retval) {
        retval = MBEDTLS_ERR_SSL_WANT_READ;
    }

    return retval;
}

int wrapper_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout)
{
    return 0;
}

static int _conn_error_status_get(int mbedtls_error_code)
{
    int protoman_error_code;

    switch (mbedtls_error_code) {
        case MBEDTLS_ERR_X509_CERT_VERIFY_FAILED:
            protoman_error_code = PROTOMAN_ERR_CERTIFICATE_CHECK_FAILED;
        break;
#if defined(MBEDTLS_ERR_PLATFORM_FAULT_DETECTED)
        case MBEDTLS_ERR_PLATFORM_FAULT_DETECTED:
            protoman_error_code = PROTOMAN_ERR_PLATFORM_FAULT;
        break;
#endif /* MBEDTLS_ERR_PLATFORM_FAULT_DETECTED */
        case MBEDTLS_ERR_SSL_INTERNAL_ERROR:
            protoman_error_code = PROTOMAN_ERR_INTERNAL_ERROR;
        break;
        default:
            protoman_error_code = PROTOMAN_ERR_SECURE_CONNECTION_FAILED;
        break;
    }

    return protoman_error_code;
}

static int _do_configuration(struct protoman_layer_s *layer)
{
    struct protoman_s *protoman = layer->protoman;
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *)layer;
    int retval;

    protoman_verbose("");

    /* mbedtls init */
    mbedtls_ssl_init(&layer_mbedtls_common->ssl);
    mbedtls_ssl_config_init(&layer_mbedtls_common->conf);

#if !defined(MBEDTLS_SSL_CONF_RNG)
    mbedtls_hmac_drbg_init(&layer_mbedtls_common->hmac_drbg);
    mbedtls_entropy_init(&layer_mbedtls_common->entropy);

    /*  Seed rng */
    retval = mbedtls_hmac_drbg_seed(&layer_mbedtls_common->hmac_drbg, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), mbedtls_entropy_func, &layer_mbedtls_common->entropy, NULL, 0);
    if (retval != 0) {
        protoman_err("mbedtls_hmac_drbg_seed() failed with %s (%d)", protoman_strmbedtls(retval), retval);
        protoman_layer_record_error(layer, _conn_error_status_get(retval), retval, protoman_strmbedtls(retval));
        return PROTOMAN_STATE_RETVAL_ERROR;
    }
#endif
    /*  Defaults */
    int mbedtls_endpoint = protoman->config.is_client ? MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER;
    int mbedtls_transport = protoman->config.is_dgram ? MBEDTLS_SSL_TRANSPORT_DATAGRAM : MBEDTLS_SSL_TRANSPORT_STREAM;

    retval = mbedtls_ssl_config_defaults(&layer_mbedtls_common->conf, mbedtls_endpoint, mbedtls_transport, MBEDTLS_SSL_PRESET_DEFAULT); /* MBEDTLS_SSL_TRANSPORT_STREAM */
    if (retval != 0) {
        protoman_err("mbedtls_ssl_config_defaults() failed with %d", retval);
        protoman_layer_record_error(layer, PROTOMAN_ERR_NOMEM, retval, protoman_strmbedtls(retval));
        return PROTOMAN_STATE_RETVAL_ERROR;
    }

#ifdef PROTOMAN_SECURITY_ENABLE_CERTIFICATE
#if defined(MBEDTLS_SSL_PROTO_NO_TLS)
    if (mbedtls_transport == MBEDTLS_SSL_TRANSPORT_STREAM) {
        protoman_err("mbedtls_ssl_config_defaults() failed because of invalid mbedtls_transport for TLS");
        return PROTOMAN_STATE_RETVAL_ERROR;
    }
#endif
#if !defined(MBEDTLS_SSL_PROTO_DTLS)
    if (mbedtls_transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        protoman_err("mbedtls_ssl_config_defaults() failed because of invalid mbedtls_transport for DTLS");
        return PROTOMAN_STATE_RETVAL_ERROR;
    }
#endif

    struct protoman_config_tls_common_s *config_common = (struct protoman_config_tls_common_s *)layer->config;
    /* Set authmode */
    switch(config_common->security_mode) {
        case PROTOMAN_SECURITY_MODE_CERTIFICATE:
#if defined(PROTOMAN_SECURITY_ENABLE_CERTIFICATE_HOSTNAME_CHECK) && defined(MBEDTLS_X509_CRT_PARSE_C) && !defined(MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION)
            /* If we have a fixed root CA, checking the certificate CN may not benefit us much. It just brings */
            /* more code and breaks the testing environments, which may share server cert between sandboxes. */
            /* mbedtls_ssl_set_hostname() returns MBEDTLS_ERR_SSL_BAD_INPUT_DATA with NULL hostname */
            const char *hostname = (const char *)protoman_get_info(protoman, NULL, PROTOMAN_INFO_HOSTNAME);
            retval = mbedtls_ssl_set_hostname(&layer_mbedtls_common->ssl, hostname);
            if (0 != retval) {
                protoman_err("mbedtls_ssl_set_hostname() failed with %d", retval);
                protoman_layer_record_error(layer, PROTOMAN_ERR_NOMEM, retval, protoman_strmbedtls(retval));
                return PROTOMAN_STATE_RETVAL_ERROR;
            }
            protoman_info("certificate common name authentication enabled to check \"%s\"", hostname);
#else
            protoman_info("certificate common name authentication check disabled");
#endif // PROTOMAN_SECURITY_ENABLE_CERTIFICATE_HOSTNAME_CHECK
            mbedtls_ssl_conf_authmode(&layer_mbedtls_common->conf, MBEDTLS_SSL_VERIFY_REQUIRED); /* must be called before mbedtls_ssl_setup() */
            break;
        case PROTOMAN_SECURITY_MODE_CERTIFICATE_VERIFY_NONE:
            protoman_warn("certificate common name authentication disabled");
            mbedtls_ssl_conf_authmode(&layer_mbedtls_common->conf, MBEDTLS_SSL_VERIFY_NONE);
            break;
        default:
            protoman_err("config_common->security_mode not set");
            return PROTOMAN_STATE_RETVAL_ERROR;
    }
#endif // PROTOMAN_SECURITY_ENABLE_CERTIFICATE

#if !defined(MBEDTLS_SSL_CONF_RNG)
    /*  Random number generator */
    mbedtls_ssl_conf_rng(&layer_mbedtls_common->conf, mbedtls_hmac_drbg_random, &layer_mbedtls_common->hmac_drbg);
#endif

    /*  Debug messages */
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_ssl_conf_dbg(&layer_mbedtls_common->conf, _wrapper_print, layer);
    mbedtls_debug_set_threshold(4);
#endif

// Defines MBEDTLS_SSL_CONF_RECV/SEND/RECV_TIMEOUT define global functions which should be the same for all
// callers of mbedtls_ssl_set_bio_ctx.
#if !defined(MBEDTLS_SSL_CONF_RECV) && !defined(MBEDTLS_SSL_CONF_SEND) && !defined(MBEDTLS_SSL_CONF_RECV_TIMEOUT)
    /*  Binary Input/Output callbacks */
    mbedtls_ssl_set_bio(&layer_mbedtls_common->ssl, layer, wrapper_write, wrapper_read, NULL); /* mbedtls write/recv API happens to identically match PROTOMAN's */
#else

/* sanity check for correct defines */
#define wrapper_read_check 1
#define wrapper_write_check 2
#define wrapper_recv_timeout_check 3
#if MAKE_CHECK( MBEDTLS_SSL_CONF_RECV ) != wrapper_read_check
#error "MBEDTLS_SSL_CONF_RECV is not defined as wrapper_read"
#endif
#if MAKE_CHECK( MBEDTLS_SSL_CONF_SEND ) != wrapper_write_check
#error "MBEDTLS_SSL_CONF_SEND is not defined as wrapper_write"
#endif
#if MAKE_CHECK( MBEDTLS_SSL_CONF_RECV_TIMEOUT ) != wrapper_recv_timeout_check
#error "MBEDTLS_SSL_CONF_RECV_TIMEOUT is not defined as wrapper_recv_timeout"
#endif

    mbedtls_ssl_set_bio_ctx(&layer_mbedtls_common->ssl, layer);
#endif

// Defines MBEDTLS_SSL_CONF_SET_TIMER/GET_TIMER define global functions which should be the same for all
// callers of mbedtls_ssl_set_timer_cb.
#if !defined(MBEDTLS_SSL_CONF_SET_TIMER) && !defined(MBEDTLS_SSL_CONF_GET_TIMER)
    /*  Timer Set/Get callbacks */
    mbedtls_ssl_set_timer_cb(&layer_mbedtls_common->ssl, layer, timer_set, timer_get);
#else
#define timer_set_check 1
#define timer_get_check 2
#if MAKE_CHECK( MBEDTLS_SSL_CONF_SET_TIMER ) != timer_set_check
#error "MBEDTLS_SSL_CONF_SET_TIMER is not defined as timer_set"
#endif
#if MAKE_CHECK( MBEDTLS_SSL_CONF_GET_TIMER ) != timer_get_check
#error "MBEDTLS_SSL_CONF_GET_TIMER is not defined as timer_get"
#endif
    mbedtls_ssl_set_timer_cb_ctx(&layer_mbedtls_common->ssl, layer);
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    /* Set packet/fragment size options to make sure the TLS packets fit in our data buffers. */
    mbedtls_ssl_set_mtu(&layer_mbedtls_common->ssl, PROTOMAN_MTU);
    protoman_debug("Setting ssl mtu: %d", PROTOMAN_MTU);
#endif // MBEDTLS_SSL_PROTO_DTLS

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    protoman_debug("Setting ssl max_content_len: %d, max_frag_len: %d", MBEDTLS_SSL_MAX_CONTENT_LEN, PROTOMAN_LAYER_MBEDTLS_MAX_FRAG_LEN);

    retval = mbedtls_ssl_conf_max_frag_len(&layer_mbedtls_common->conf, PROTOMAN_LAYER_MBEDTLS_MAX_FRAG_LEN);
    if (retval != 0) {
        protoman_err("mbedtls_ssl_conf_max_frag_len() failed with %d", retval);
        protoman_layer_record_error(layer, PROTOMAN_ERR_INVALID_INPUT, retval, protoman_strmbedtls(retval));
        return PROTOMAN_STATE_RETVAL_ERROR;
    }
#endif // MBEDTLS_SSL_MAX_FRAGMENT_LENGTH

    /*  Setup */
    retval = mbedtls_ssl_setup(&layer_mbedtls_common->ssl, &layer_mbedtls_common->conf);
    if (retval) {
        protoman_err("mbedtls_ssl_setup() failed with %d", retval);
        protoman_layer_record_error(layer, PROTOMAN_ERR_NOMEM, retval, protoman_strmbedtls(retval));
        return PROTOMAN_STATE_RETVAL_ERROR;
    }

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID) && defined(MBEDTLS_SSL_CID_ENABLED)
    if (protoman->config.is_dgram) {
        protoman_debug("Setting cid enabled");
        retval = mbedtls_ssl_set_cid(&layer_mbedtls_common->ssl, MBEDTLS_SSL_CID_ENABLED, NULL, 0);
        if (retval != 0) {
            protoman_err("mbedtls_ssl_set_cid() failed with %d", retval);
            protoman_layer_record_error(layer, PROTOMAN_ERR_INVALID_INPUT, retval, protoman_strmbedtls(retval));
            return PROTOMAN_STATE_RETVAL_ERROR;
        }
    }
#endif

#ifdef PROTOMAN_USE_SSL_SESSION_RESUME
    struct protoman_config_tls_certificate_s *config_cert = (struct protoman_config_tls_certificate_s *)layer->config;
    if (!config_cert->bootstrap) {
        load_ssl_session(layer);
    } else {
        protoman_info("Do not try to load ssl session in bootstrap mode");
    }
#endif

    if (layer_mbedtls_common->conf.mfl_code == PROTOMAN_LAYER_MBEDTLS_MAX_FRAG_LEN) {
        // CFI (Control Flow Integrity) check to confirm basic initialization before returning success
        protoman_info("Configuration succesfull");
        return PROTOMAN_STATE_RETVAL_FINISHED;
    }

    protoman_err("_do_configuration() fault");
    protoman_layer_record_error(layer, PROTOMAN_ERR_PLATFORM_FAULT, PROTOMAN_ERR_PLATFORM_FAULT, "Fault");
    return PROTOMAN_STATE_RETVAL_ERROR;    
}

#if defined(PROTOMAN_SECURITY_ENABLE_PSK)
static int _do_psk_client(struct protoman_layer_s *layer)
{
    int retval;
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *)layer;
    struct protoman_config_tls_psk_s *config_psk = (struct protoman_config_tls_psk_s *)layer->config;

    protoman_verbose("");

    /* Set PSK keys */
    retval = mbedtls_ssl_conf_psk(
        &layer_mbedtls_common->conf,
        config_psk->psk.buf,
        config_psk->psk.len,
        config_psk->psk_identity.buf,
        config_psk->psk_identity.len
        );

    if (0 != retval) {
        /* mbedtls only defines MBEDTLS_ERR_SSL_ALLOC_FAILED as possible error */
        protoman_err("mbedtls_ssl_conf_psk*() failed with %s", protoman_strmbedtls(retval));
        protoman_layer_record_error(layer, PROTOMAN_ERR_NOMEM, retval, protoman_strmbedtls(retval));
        return PROTOMAN_STATE_RETVAL_ERROR;
    }
#if !defined(MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE)
    /* Set supported ciphersuites */
    /* mbedtls_ssl_conf_ciphersuites() documentation in
     *   https://tls.mbed.org/api/ssl_8h.html#ac8e4df37cadda8f743ed45501a51fec1 */
    /* mbedTLS supported ciphersuites here:
     *   https://tls.mbed.org/supported-ssl-ciphersuites */
    /* TODO REMOVE THIS!!!! */
    static const int ciphersuites[] = {MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8, MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256, 0};
    mbedtls_ssl_conf_ciphersuites(&layer_mbedtls_common->conf, ciphersuites);
#else
#if MBEDTLS_SSL_SUITE_ID(MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE) != MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8 && \
    MBEDTLS_SSL_SUITE_ID(MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE) != MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256
    #error "Using PSK mode although ciphersuite defined is not PSK"
#endif
#endif /* !defined(MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE) */

    protoman_info("PSK configuration succesfull");
    return PROTOMAN_STATE_RETVAL_FINISHED;
}

static int _do_psk_server(struct protoman_layer_s *layer)
{
    protoman_err("NOT IMPLEMENTED");
    //retval = mbedtls_ssl_conf_psk_cb(NULL, NULL, NULL, NULL, NULL, NULL); //https://tls.mbed.org/api/ssl_8h.html
    protoman_layer_record_error(layer, PROTOMAN_ERR_NOT_IMPLEMENTED, PROTOMAN_ERR_NOT_IMPLEMENTED, "_do_psk_server() is not implemented");
    return PROTOMAN_STATE_RETVAL_ERROR;
}

static int _do_psk(struct protoman_layer_s *layer)
{
    struct protoman_s *protoman = layer->protoman;

    protoman_verbose("");

    if (protoman->config.is_client) {
        return _do_psk_client(layer);
    } else {
        return _do_psk_server(layer);
    }
}
#endif // PROTOMAN_SECURITY_ENABLE_PSK

#ifdef PROTOMAN_SECURITY_ENABLE_CERTIFICATE
static int _do_certificates(struct protoman_layer_s *layer)
{
    //struct protoman_s *protoman = layer->protoman;
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *)layer;
    struct protoman_layer_mbedtls_certificate_s *layer_mbedtls_cert = (struct protoman_layer_mbedtls_certificate_s *)layer;
    struct protoman_config_tls_certificate_s *config_cert = (struct protoman_config_tls_certificate_s *)layer->config;
    int retval;
    volatile int flow_control = 0;   // to check control path validity 

    protoman_verbose("");

    mbedtls_x509_crt_init(&layer_mbedtls_cert->cacert);
    mbedtls_x509_crt_init(&layer_mbedtls_cert->owncert);
    mbedtls_pk_init(&layer_mbedtls_cert->ownkey);

    /*  mbedtls - cacert
     * ================== */
    switch (config_cert->cacert.header.type) {
#ifdef MBEDTLS_FS_IO
        case PROTOMAN_IO_CERTFILE:
            protoman_debug("cacert is PROTOMAN_IO_CERTFILE");
            retval = mbedtls_x509_crt_parse_file(&layer_mbedtls_cert->cacert,
                (const char *)config_cert->cacert.buf);
            flow_control++;
            break;
#endif //MBEDTLS_FS_IO

        case PROTOMAN_IO_CERTBUF:
            protoman_debug("cacert is PROTOMAN_IO_CERTBUF");
#if defined(MBEDTLS_PEM_PARSE_C)
            retval = mbedtls_x509_crt_parse(&layer_mbedtls_cert->cacert,
                (const unsigned char *)config_cert->cacert.buf, config_cert->cacert.len);
#else
            retval = mbedtls_x509_crt_parse_der_nocopy(&layer_mbedtls_cert->cacert,
                (const unsigned char *)config_cert->cacert.buf, config_cert->cacert.len);
#endif // MBEDTLS_PEM_PARSE_C
            flow_control++;
            break;

        default:
            protoman_err("unsupported cacert type %d", config_cert->cacert.header.type);
            retval = -1;
            break;
    }

    if (retval < 0) {
        protoman_err("cacert parsing failed with %s (%d)", protoman_strmbedtls(retval), retval);
        protoman_layer_record_error(layer, _conn_error_status_get(retval), retval, protoman_strmbedtls(retval));
        return PROTOMAN_STATE_RETVAL_ERROR;
    }

    /*  mbedtls - owncert
     * =================== */
    switch (config_cert->owncert.header.type) {
#ifdef MBEDTLS_FS_IO
        case PROTOMAN_IO_CERTFILE:
            protoman_debug("owncert is PROTOMAN_IO_CERTFILE");
            retval = mbedtls_x509_crt_parse_file(&layer_mbedtls_cert->owncert,
                (const char *)config_cert->owncert.buf);
            flow_control++;
            break;
#endif //MBEDTLS_FS_IO

        case PROTOMAN_IO_CERTBUF:
            protoman_debug("owncert is PROTOMAN_IO_CERTBUF");
#if defined(MBEDTLS_PEM_PARSE_C)
            retval = mbedtls_x509_crt_parse(&layer_mbedtls_cert->owncert,
                (const unsigned char *)config_cert->owncert.buf, config_cert->owncert.len);
#else
            retval = mbedtls_x509_crt_parse_der_nocopy(&layer_mbedtls_cert->owncert,
                (const unsigned char *)config_cert->owncert.buf, config_cert->owncert.len);
#endif // MBEDTLS_PEM_PARSE_C
            flow_control++;
            break;

        default:
            protoman_err("unsupported owncert type %d", config_cert->owncert.header.type);
            retval = -1;
            break;
    }

    if (retval < 0) {
        protoman_err("owncert parsing failed with %s (%d)", protoman_strmbedtls(retval), retval);
        protoman_layer_record_error(layer, _conn_error_status_get(retval), retval, protoman_strmbedtls(retval));
        return PROTOMAN_STATE_RETVAL_ERROR;
    }

    /*  mbedtls - ownkey
     * ================== */
    switch (config_cert->ownkey.header.type) {
#ifdef MBEDTLS_FS_IO
        case PROTOMAN_IO_KEYFILE:
            protoman_debug("ownkey is PROTOMAN_IO_KEYFILE");
            retval = mbedtls_pk_parse_keyfile(
                &layer_mbedtls_cert->ownkey,
                (const char *)config_cert->ownkey.buf,
                config_cert->ownpass);
            flow_control++;
            break;
#endif //MBEDTLS_FS_IO

        case PROTOMAN_IO_KEYBUF:
            protoman_debug("ownkey is PROTOMAN_IO_KEYBUF");

#ifndef TLS_HANDSHAKE_USE_RAW_FORMAT_PRIVATE_KEY
            /* device key in DER format */
            
            size_t ownpass_len;
            /* No NULL check in strlen() */
            if (config_cert->ownpass) {
                ownpass_len = strlen(config_cert->ownpass);
            } else {
                ownpass_len = 0;
            }
            /* Parse key in DER format to pk_context structure */
            retval = mbedtls_pk_parse_key(
                &layer_mbedtls_cert->ownkey,
                (const unsigned char *)config_cert->ownkey.buf,
                config_cert->ownkey.len,
                (const unsigned char *)config_cert->ownpass,
                ownpass_len);

#else
            /* device key in RAW format */

#if defined(MBEDTLS_PK_SINGLE_TYPE)
            /* Copy raw key to single pk_ctx buffer */
            PROTOMAN_MEMCPY(&layer_mbedtls_cert->ownkey.pk_ctx, config_cert->ownkey.buf, config_cert->ownkey.len);
            retval = 0;
#else
            /* Parse raw key to pk_ctx */
            retval = mbedtls_pk_setup(&layer_mbedtls_cert->ownkey, mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY ));
            if (retval == 0) {
                mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(layer_mbedtls_cert->ownkey);
                retval = mbedtls_ecp_group_load(&ecp->grp, MBEDTLS_ECP_DP_SECP256R1);
                if (retval == 0) {
                    retval = mbedtls_mpi_read_binary(&ecp->d, config_cert->ownkey.buf, config_cert->ownkey.len);
                }
            }
#endif // MBEDTLS_PK_SINGLE_TYPE

#endif // TLS_HANDSHAKE_USE_RAW_FORMAT_PRIVATE_KEY

            flow_control++;
            break;

        default:
            protoman_err("unsupported ownkey type %d", config_cert->ownkey.header.type);
            retval = -1;
            break;
    }

    // ownkey is copied or parsed (or failed), it should be cleared from the memory
    PROTOMAN_MEMSET(config_cert->ownkey.buf, 0, config_cert->ownkey.len);

    if (retval < 0) {
        protoman_err("ownkey parsing failed with %s (%d)", protoman_strmbedtls(retval), retval);
        protoman_layer_record_error(layer, _conn_error_status_get(retval), retval, protoman_strmbedtls(retval));
        return PROTOMAN_STATE_RETVAL_ERROR;
    }

    /*  mbedtls - use certs
     * ===================== */
    //TODO: If needed in server mode, this won't work
    retval = mbedtls_ssl_conf_own_cert(&layer_mbedtls_common->conf, &layer_mbedtls_cert->owncert, &layer_mbedtls_cert->ownkey);
    flow_control++;
    if (0 != retval) {
        protoman_err("mbedtls_ssl_conf_own_cert() failed with %s (%d)", protoman_strmbedtls(retval), retval);
        protoman_layer_record_error(layer, _conn_error_status_get(retval), retval, protoman_strmbedtls(retval));
        return PROTOMAN_STATE_RETVAL_ERROR;
    }

    mbedtls_ssl_conf_ca_chain(&layer_mbedtls_common->conf, &layer_mbedtls_cert->cacert, NULL);

    if (flow_control == 4) {
        // CFI (Control Flow Integrity) check to ensure that we are following the right control path before returning success
        return PROTOMAN_STATE_RETVAL_FINISHED;
    }

    retval = PROTOMAN_STATE_RETVAL_ERROR;

    protoman_err("Platform fault - flow control failed");
    protoman_layer_record_error(layer, PROTOMAN_ERR_PLATFORM_FAULT, retval, "Fault");
    return retval;
}
#endif // PROTOMAN_SECURITY_ENABLE_CERTIFICATE

static int _do_connect(struct protoman_layer_s *layer)
{
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *)layer;
    int retval;

    retval = mbedtls_ssl_handshake_step(&layer_mbedtls_common->ssl);
    protoman_verbose("mbedtls_ssl_handshake_step()");

    switch (retval) {
        case 0:
            protoman_debug("mbedtls_ssl_handshake_step(), OK, ssl.state = %s (%d)", protoman_strmbedtls_handshake(layer_mbedtls_common->ssl.state), layer_mbedtls_common->ssl.state);

            /* Capture client random for TLS decryption in Wireshark */
            protoman_sslkeylog_snapshot_client_random(layer);

            /* Handshake done */
            if (MBEDTLS_SSL_HANDSHAKE_OVER == layer_mbedtls_common->ssl.state) {
                protoman_info("mbedtls_ssl_handshake_step(), finish");
                print_cid(layer, "do_connect");

                /* Capture master secret for TLS decryption in Wireshark */
                protoman_sslkeylog_snapshot_master_secret(layer);

#ifdef PROTOMAN_USE_SSL_SESSION_RESUME
                struct protoman_config_tls_certificate_s *config_cert = (struct protoman_config_tls_certificate_s *)layer->config;
                if (!config_cert->bootstrap) {
                    store_ssl_session(layer);
                } else {
                    protoman_info("Do not store ssl session in bootstrap mode");
                }
#endif

                layer_mbedtls_common->handshakes_failed = 0;
                return PROTOMAN_STATE_RETVAL_FINISHED;
            }
            protoman_verbose("mbedtls_ssl_handshake_step(), continue");
            break;

        case MBEDTLS_ERR_SSL_WANT_READ:
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            protoman_verbose("mbedtls_ssl_handshake_step(), WOULDBLOCK");
            /* No PROTOMAN_EVENT_RUN event scheduled here because there
             * will be PROTOMAN_DATA_AVAIL or PROTOMAN_DATA_WRITTEN event from below */
            return PROTOMAN_STATE_RETVAL_WAIT;

        case MBEDTLS_ERR_SSL_BAD_INPUT_DATA:
        default:
            protoman_err("mbedtls_ssl_handshake_step() returned %s (%d)", protoman_strmbedtls(retval), retval);
            protoman_layer_record_error(layer, _conn_error_status_get(retval), retval, _mbedtls_error);
            return PROTOMAN_STATE_RETVAL_ERROR;
    }
    return PROTOMAN_STATE_RETVAL_AGAIN;
}

static int _do_write(struct protoman_layer_s *layer)
{
    struct protoman_s *protoman = layer->protoman;
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *)layer;

    int retval;
    int state_retval = PROTOMAN_STATE_RETVAL_WAIT;

    protoman_verbose("");

    if (NULL == layer->tx_buf) {
        protoman_verbose("layer->tx_buf is empty");
        goto exit;
    }

    retval = mbedtls_ssl_write(&layer_mbedtls_common->ssl, layer->tx_buf + layer->tx_offset, layer->tx_len - layer->tx_offset);
    if (retval < 0 && retval != MBEDTLS_ERR_SSL_WANT_READ && retval != MBEDTLS_ERR_SSL_WANT_WRITE) {
        protoman_warn("mbedtls_ssl_write() returned %s (%X)", protoman_strmbedtls(retval), retval);
    }

    /* Capture master secret for TLS decryption in Wireshark */
    protoman_sslkeylog_snapshot_master_secret(layer);

    switch (retval) {
        case MBEDTLS_ERR_SSL_WANT_READ:
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            /* Wait for PROTOMAN_EVENT_DATA_WRITTEN from below */
            goto exit;

        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
            state_retval = PROTOMAN_STATE_RETVAL_DISCONNECT;
            goto exit;

        case MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
            state_retval = PROTOMAN_STATE_RETVAL_DISCONNECT;
            goto exit;

        default:
            if (retval < 0) { /* some other error */
                protoman_layer_record_error(layer, _conn_error_status_get(retval), retval, _mbedtls_error);
                state_retval = PROTOMAN_STATE_RETVAL_ERROR;
                goto exit;
            }

            /* retval >= 0 all OK */
            layer->tx_offset += retval;
            protoman_verbose("wrote %d bytes of %lu bytes", retval, (unsigned long)layer->tx_len);

            /* Is all data sent? */
            if ((int)layer->tx_offset == layer->tx_len) {
                protoman_event(protoman, layer, PROTOMAN_EVENT_DATA_WRITTEN, PROTOMAN_EVENT_PRIORITY_LOW, 0);

                PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer->tx_buf);
                protoman_tx_free(protoman, layer->tx_buf);
                layer->tx_buf = NULL;
            }
    }

exit:
    return state_retval;
}

static int _do_read(struct protoman_layer_s *layer)
{
    struct protoman_s *protoman = layer->protoman;
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *)layer;

    int state_retval = PROTOMAN_STATE_RETVAL_WAIT;
    int retval;

    protoman_verbose("");

    /* Own input buffer is not empty */
    if (NULL != layer->rx_buf) {
        protoman_verbose("layer->rx_buf is not empty");
        goto exit;
    }

    /*  Allocate space for receiving data */
    layer->rx_buf = protoman_rx_alloc(protoman, protoman->config.mtu);
    if (NULL == layer->rx_buf) {
        protoman_warn("layer->rx_buf malloc(%lu) failed", (unsigned long)protoman->config.mtu);
        state_retval = PROTOMAN_STATE_RETVAL_AGAIN;
        goto exit;
    }
    PROTOMAN_DEBUG_PRINT_ALLOC(layer->name, protoman->config.mtu, layer->rx_buf);

    /*  Read - https://tls.mbed.org/api/ssl_8h.html#aa2c29eeb1deaf5ad9f01a7515006ede5
     * ------ */
    retval = mbedtls_ssl_read(&layer_mbedtls_common->ssl, layer->rx_buf, protoman->config.mtu);

    /* Capture master secret for TLS decryption in Wireshark */
    protoman_sslkeylog_snapshot_master_secret(layer);

    switch (retval) {
        case MBEDTLS_ERR_SSL_WANT_READ:
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            goto cleanup;

        case MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
            state_retval = PROTOMAN_STATE_RETVAL_DISCONNECT;
            goto print_as_error;

        case 0: /* EOF */
        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
            if (PROTOMAN_STATE_DISCONNECTED == protoman->target_state) {
                state_retval = PROTOMAN_STATE_RETVAL_DISCONNECT;
            } else {
                protoman_layer_record_error(layer, PROTOMAN_ERR_CONNECTION_CLOSED, retval, "EOF");
                state_retval = PROTOMAN_STATE_RETVAL_ERROR;
            }
            protoman_info("mbedtls_ssl_read() returned %s (%X)", protoman_strmbedtls(retval), retval);
            goto cleanup;

        default:
            if (retval < 0) {
                protoman_layer_record_error(layer, _conn_error_status_get(retval), retval, _mbedtls_error);
                state_retval = PROTOMAN_STATE_RETVAL_ERROR;
                goto print_as_error;
            }

            /* OK */
            layer->rx_len = retval;
            layer->rx_offset = 0;
            protoman_verbose("mbedtls_ssl_read() read %ld bytes", (signed long)layer->rx_len);
            protoman_event(protoman, layer, PROTOMAN_EVENT_DATA_AVAIL, PROTOMAN_EVENT_PRIORITY_LOW, 0);
            goto exit;
    }
print_as_error:
    protoman_err("mbedtls_ssl_read() returned %s (%X)", protoman_strmbedtls(retval), retval);
cleanup:
    PROTOMAN_DEBUG_PRINT_FREE(layer->name, layer->rx_buf);
    protoman_rx_free(protoman, layer->rx_buf);
    layer->rx_buf = NULL;
exit:
    return state_retval;
}

static int _do_disconnect(struct protoman_layer_s *layer)
{
    struct protoman_s *protoman = layer->protoman;
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *)layer;
    int retval;

    protoman_verbose("");

    /* Send close notification to (D)TLS server if doing graceful disconnection */
    if (0 == layer->protoman_error) {
        retval = mbedtls_ssl_close_notify(&layer_mbedtls_common->ssl);
        switch (retval) {
            case 0:
                protoman_verbose("mbedtls_ssl_close_notify() OK");
                /* continue to session reset */
                break;

            case MBEDTLS_ERR_SSL_WANT_READ:
            case MBEDTLS_ERR_SSL_WANT_WRITE:
                protoman_verbose("mbedtls_ssl_close_notify() WOULDBLOCK, try again");
                protoman_event(protoman, layer, PROTOMAN_EVENT_RUN, PROTOMAN_EVENT_PRIORITY_LOW, 10);
                return PROTOMAN_STATE_RETVAL_WAIT; /* stay in disconnectin state and try again */

            default:
                protoman_warn("mbedtls_ssl_close_notify() failed with %X", retval);
        }
    }

    /* Reset mbed TLS session
     * https://tls.mbed.org/api/ssl_8h.html#a21432367cbce428f10dcb62d9456fa7e */
    retval = mbedtls_ssl_session_reset(&layer_mbedtls_common->ssl);
    switch (retval) {
        case 0:
            protoman_verbose("mbedtls_ssl_session_reset(), OK");
            break;

        case MBEDTLS_ERR_SSL_ALLOC_FAILED:
        default:
            protoman_err("mbedtls_ssl_session_reset(), failed with %s (%X)", protoman_strmbedtls(retval), retval);
            protoman_layer_record_error(layer, PROTOMAN_ERR_NOMEM, retval, protoman_strmbedtls(retval));
            return PROTOMAN_STATE_RETVAL_ERROR;
    }
    return PROTOMAN_STATE_RETVAL_FINISHED;
}

static int _do_resume(struct protoman_layer_s *layer)
{
    print_cid(layer, "do_resume");
    return PROTOMAN_STATE_RETVAL_FINISHED;
}

static int _do_init(struct protoman_layer_s *layer)
{
    struct protoman_config_tls_common_s *config_common = (struct protoman_config_tls_common_s *)layer->config;
    int retval;

    protoman_verbose("");

    /* Do configuration */
    retval = _do_configuration(layer);
    if (PROTOMAN_STATE_RETVAL_FINISHED != retval) {
        protoman_err("_do_configuration() failed with %s", protoman_strstateretval(retval));
        return PROTOMAN_STATE_RETVAL_ERROR;
    }

    /* Do security configuration */
    if (PROTOMAN_SECURITY_MODE_CERTIFICATE == config_common->security_mode) {
#ifdef PROTOMAN_SECURITY_ENABLE_CERTIFICATE
        retval = _do_certificates(layer);
#else
        retval = PROTOMAN_STATE_RETVAL_ERROR;
#endif
    } else {
#ifdef PROTOMAN_SECURITY_ENABLE_PSK
        retval = _do_psk(layer);
#else
        retval = PROTOMAN_STATE_RETVAL_ERROR;
#endif
    }

    /* Init doesn't currently support PROTOMAN_STATE_RETVAL_AGAIN -> raise an error if this is the case */
    if (PROTOMAN_STATE_RETVAL_FINISHED != retval) {
        protoman_err("_do_certificates() or _do_psk() failed with %s", protoman_strstateretval(retval));
        return PROTOMAN_STATE_RETVAL_ERROR;
    }
#if defined(MBEDTLS_SSL_CONF_RNG)
    init_global_rng();
#endif
    return retval;
}

static void layer_event(struct protoman_layer_s *layer, int event_id)
{
    struct protoman_s *protoman = layer->protoman;

    /* Generic logic is just fine here */
    protoman_generic_layer_event(layer, event_id);

    /* Prevent event exhaustion by trying to re-schedule mbedTLS timer run event.
        This is needed because only one active run event fits in the layer event storage
        at layer->protoman_event_storage->run. The system overwrites old run events
        if the new event executes earlier. This becomes an issue in the handshake phase
        if the first package is lost and mbedtls_ssl_handshake_step() is called but
        the set period is not done yet. Here mbedTLS remains to wait the event it requested
        earlier but there will be none as it was overwritten by some faster run event earlier
        by protoman.And because the first package was lost, there will not be any incoming
        packets that would trigger a new layer run for the mbedTLS. To make sure mbedTLS does
        get the timer event it requested, we need to try to reschedule it here after executing
        layer run */
    timer_rearm(protoman, layer);
}

static void layer_free(struct protoman_layer_s *layer)
{
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *)layer;

    protoman_verbose("");

    /* Do generic layer free */
    protoman_generic_layer_free(layer);

#if !defined(MBEDTLS_SSL_CONF_RNG)
    /* Do layer specific free */
    mbedtls_entropy_free(&layer_mbedtls_common->entropy);
    mbedtls_hmac_drbg_free(&layer_mbedtls_common->hmac_drbg);
#endif

#ifdef PROTOMAN_SECURITY_ENABLE_CERTIFICATE
    struct protoman_layer_mbedtls_certificate_s *layer_mbedtls_cert = (struct protoman_layer_mbedtls_certificate_s *)layer;
    struct protoman_config_tls_common_s *config_common = (struct protoman_config_tls_common_s *)layer->config;
    if (PROTOMAN_SECURITY_MODE_CERTIFICATE == config_common->security_mode) {
        mbedtls_x509_crt_free(&layer_mbedtls_cert->cacert);
        mbedtls_x509_crt_free(&layer_mbedtls_cert->owncert);
        mbedtls_pk_free(&layer_mbedtls_cert->ownkey);
    }
#endif // PROTOMAN_SECURITY_ENABLE_CERTIFICATE
    mbedtls_ssl_config_free(&layer_mbedtls_common->conf);
    mbedtls_ssl_free(&layer_mbedtls_common->ssl);
}
#endif

#ifdef PROTOMAN_USE_SSL_SESSION_RESUME
static void store_ssl_session(struct protoman_layer_s *layer)
{
    protoman_debug("");
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *)layer;
    mbedtls_ssl_session ssl_session = {0};
    int session_status = mbedtls_ssl_get_session(&layer_mbedtls_common->ssl, &ssl_session);

    if (session_status != 0) {
        protoman_debug("mbedtls_ssl_get_session failed: %d", session_status);
        return;
    }

    uint8_t session_buffer[ssl_session_size];

    PROTOMAN_MEMCPY(session_buffer, (uint8_t*)&ssl_session.id_len, sizeof(ssl_session.id_len));
    PROTOMAN_MEMCPY(session_buffer + sizeof(ssl_session.id_len),
           (uint8_t*)&ssl_session.id, sizeof(ssl_session.id));
    PROTOMAN_MEMCPY(session_buffer + sizeof(ssl_session.id_len) + sizeof(ssl_session.id),
           (uint8_t*)&ssl_session.master, sizeof(ssl_session.master));
#if !defined(MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE)
    PROTOMAN_MEMCPY(session_buffer + sizeof(ssl_session.id_len) + sizeof(ssl_session.id) + sizeof(ssl_session.master),
           (uint8_t*)&ssl_session.ciphersuite, sizeof(ssl_session.ciphersuite));
#endif

    bool replace = false;
    size_t data_size = 0;

    if (CCS_STATUS_SUCCESS != size_config_parameter(SSL_SESSION_DATA, &data_size)) {
        protoman_err("failed to read SSL_SESSION_DATA");
        replace = true;
    }

    // Check existing data before writing it again to storage
    ccs_status_e status;
    if (!replace) {
        replace = true;
        uint8_t existing_session[ssl_session_size];
        status = get_config_parameter(SSL_SESSION_DATA, existing_session, ssl_session_size, &data_size);

        // Session data not changed, use existing one
        if (status == CCS_STATUS_SUCCESS && memcmp(session_buffer, existing_session, ssl_session_size) == 0) {
            replace = false;
        }
    }

    // Store only if session has changed
    if (replace) {
        protoman_info("save a new session");

        status = set_config_parameter(SSL_SESSION_DATA, session_buffer, ssl_session_size);
        if (status != CCS_STATUS_SUCCESS) {
            protoman_err("failed to store new session: %d", status);
        }
    } else {
        protoman_info("keep old session");
    }

    mbedtls_ssl_session_free(&ssl_session);
}

void load_ssl_session(struct protoman_layer_s *layer)
{
    protoman_debug("");
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *)layer;
    size_t data_size = 0;

    uint8_t ssl_session_buffer[ssl_session_size];
    ccs_status_e status = get_config_parameter(SSL_SESSION_DATA, ssl_session_buffer, ssl_session_size, &data_size);
    if (status != CCS_STATUS_SUCCESS) {
        protoman_info("failed to read session data info from storage: %d", status);
        return;
    }

    mbedtls_ssl_session ssl_session = {0};
    PROTOMAN_MEMCPY(&ssl_session.id_len, ssl_session_buffer, sizeof(ssl_session.id_len));
    PROTOMAN_MEMCPY(&ssl_session.id, ssl_session_buffer + sizeof(ssl_session.id_len), sizeof(ssl_session.id));
    PROTOMAN_MEMCPY(&ssl_session.master, ssl_session_buffer + sizeof(ssl_session.id_len) + sizeof(ssl_session.id), sizeof(ssl_session.master));
#if !defined(MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE)
    PROTOMAN_MEMCPY(&ssl_session.ciphersuite, ssl_session_buffer + sizeof(ssl_session.id_len) + sizeof(ssl_session.id) + sizeof(ssl_session.master), sizeof(ssl_session.ciphersuite));
#endif

    if (mbedtls_ssl_set_session(&layer_mbedtls_common->ssl, &ssl_session) != 0) {
        protoman_err("mbedtls_ssl_set_session - failed!");
    }
}
#endif //PROTOMAN_USE_SSL_SESSION_RESUME

static void print_cid(struct protoman_layer_s *layer, const char* prefix)
{
    (void) layer; // quiet compiler
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID) && defined(MBEDTLS_SSL_CID_ENABLED)
#ifdef PROTOMAN_VERBOSE
    struct protoman_layer_mbedtls_common_s *layer_mbedtls_common = (struct protoman_layer_mbedtls_common_s *)layer;
    if (layer->protoman->config.is_dgram) {
        int enabled = 0;
        size_t peer_cid_len = 0;
        unsigned char peer_cid[MBEDTLS_SSL_CID_OUT_LEN_MAX];
        if (!mbedtls_ssl_get_peer_cid(&layer_mbedtls_common->ssl, &enabled, peer_cid, &peer_cid_len)) {
            if (enabled) {
                protoman_verbose("%s PEER CID: %s.", prefix, tr_array(peer_cid, peer_cid_len));
            } else {
                protoman_verbose("PEER CID: disabled");
            }
        } else {
            protoman_err("mbedtls_ssl_get_peer_cid() failed");
        }
    }
#endif
#endif
}
