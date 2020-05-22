// ----------------------------------------------------------------------------
// Copyright 2018-2019 ARM Ltd.
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

#ifndef __FOTA_CRYPTO_H_
#define __FOTA_CRYPTO_H_

#include "fota/fota_base.h"
#include "fota/fota_crypto_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_ASN1_ENUMERATED              0x0A

/*
        Encryption Metadata structure
    +++++++++++++++++++++++++++++++++++++++
    + ENCRYPTION_METADATA_MAGIC (4 bytes) +
    +++++++++++++++++++++++++++++++++++++++
    +     Tags area length (4 bytes)      +
    +++++++++++++++++++++++++++++++++++++++
    +           Salt (16 Bytes)           +
    +++++++++++++++++++++++++++++++++++++++
    +              Tags                   +
    +              Tags                   +
    +              Tags                   +
    +              Tags                   +
    +++++++++++++++++++++++++++++++++++++++
*/



typedef struct fota_encrypt_context_s fota_encrypt_context_t;

int fota_encrypt_decrypt_start(fota_encrypt_context_t **ctx, const fota_encrypt_config_t *encrypt_config,
                               const uint8_t *key, uint32_t key_size, bool encrypt);

// reset stream
// reset iv and buffering states
void fota_encryption_stream_reset(fota_encrypt_context_t *ctx);

void fota_encryption_iv_increment(fota_encrypt_context_t *ctx);

int fota_encryption_metadata_start(fota_encrypt_context_t *ctx, uint8_t *salt, uint32_t salt_len,
                                   uint32_t fw_size, uint8_t *metadata, uint32_t metdata_buffer_size,
                                   uint32_t *metadata_start_size, uint32_t *metadata_tags_size);
// used in bootloader and tests
bool fota_encryption_metadata_parse(uint8_t *buffer, uint32_t buffer_len,
                                    uint32_t *tags_size, uint8_t *salt, uint32_t salt_len);

int fota_encrypt_data(
    fota_encrypt_context_t *ctx,
    const uint8_t *in_buf, uint32_t buf_size, uint8_t *out_buf,
    uint8_t *metadata_buf, uint32_t metadata_buf_size, uint32_t *metadata_actual_size);
int fota_decrypt_data(
    fota_encrypt_context_t *ctx,
    const uint8_t *in_buf, uint32_t buf_size, uint8_t *out_buf,
    uint8_t *metadata_buf, uint32_t metadata_buf_size);
int fota_encrypt_finalize(fota_encrypt_context_t **ctx);

typedef struct fota_hash_context_s fota_hash_context_t;

int fota_hash_start(fota_hash_context_t **ctx);
int fota_hash_update(fota_hash_context_t *ctx, const uint8_t *buf, uint32_t buf_size);
int fota_hash_result(fota_hash_context_t *ctx, uint8_t *hash_buf);
int fota_hash_finish(fota_hash_context_t **ctx);

int fota_random_init(const uint8_t *seed, uint32_t seed_size);
int fota_gen_random(uint8_t *buf, uint32_t buf_size);
int fota_random_deinit(void);

int fota_get_derived_key(const uint8_t *key, size_t key_size, const uint8_t *input, size_t input_size,
                         uint8_t *derived_key);

// FI mitigation APIs
int fota_random_delay(void);
// TODO: check if should return volatile
int fota_fi_memcmp(const uint8_t *ptr1, const uint8_t *ptr2, size_t num, volatile size_t *loop_check);

#if defined(FOTA_FI_MITIGATION_ENABLE) && FOTA_FI_MITIGATION_ENABLE
// This handles a a fault injection safe condition - desired condition tested 3 times with random delay between checks
// (to prevent power glitch attacks).
// In case of a bad case scenario, error message is displayed (if not null), variable ret (must exist) is filled with RET
// and we jump to label "fail", which must exist.
#define FOTA_FI_SAFE_COND(DESIRED_COND, RET, MSG) \
do { \
    if (!(DESIRED_COND)) { \
        if (MSG) { \
            FOTA_TRACE_ERROR(MSG); \
        } \
        ret = RET; \
        goto fail; \
    } \
    fota_random_delay(); \
    if (!(DESIRED_COND)) { \
        if (MSG) { \
            FOTA_TRACE_ERROR(MSG); \
        } \
        ret = RET; \
        goto fail; \
    } \
    fota_random_delay(); \
    if (!(DESIRED_COND)) { \
        if (MSG) { \
            FOTA_TRACE_ERROR(MSG); \
        } \
        ret = RET; \
        goto fail; \
    } \
} while (0)

// specific case, safe memcmp (desired condition is equal strings)
#define FOTA_FI_SAFE_MEMCMP(PTR1, PTR2, NUM, RET, MSG) \
do { \
    size_t volatile loop_check; \
    FOTA_FI_SAFE_COND((!fota_fi_memcmp((PTR1), (PTR2), (NUM), &loop_check) && (loop_check == (NUM))), RET, MSG); \
} while (0)

#else // no FI support

// No FI mitigation, simple handling
#define FOTA_FI_SAFE_COND(DESIRED_COND, RET, MSG) \
do { \
    if (!(DESIRED_COND)) { \
        if (MSG) { \
            FOTA_TRACE_ERROR(MSG); \
        } \
        ret = RET; \
        goto fail; \
    } \
} while (0)

// specific case, regular memcmp (desired condition is equal strings)
#define FOTA_FI_SAFE_MEMCMP(PTR1, PTR2, NUM, RET, MSG) \
    FOTA_FI_SAFE_COND(!memcmp((PTR1), (PTR2), (NUM)), RET, MSG)

#endif // FI


int mbedtls_asn1_get_enumerated_value(unsigned char **p,
                                      const unsigned char *end,
                                      int *val);
int mbedtls_asn1_get_int64(unsigned char **p,
                           const unsigned char *end,
                           int64_t *val);
typedef struct mbedtls_x509_crt mbedtls_x509_crt;
int fota_verify_signature(
    const uint8_t *signed_data, size_t signed_data_size,
    const uint8_t *sig, size_t sig_len,
    mbedtls_x509_crt *cert
);

#ifdef __cplusplus
}
#endif

#endif // __FOTA_CRYPTO_H_
