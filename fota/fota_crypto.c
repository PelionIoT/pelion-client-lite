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

#include "fota/fota_base.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#include "fota/fota_crypto.h"
#include "fota/fota_status.h"
#include "fota/fota_crypto_defs.h"
#include "mbedtls/sha256.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ccm.h"
#include "mbedtls/aes.h"
#include "mbedtls/asn1.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"

#if defined(REMOVE_MBEDTLS_SSL_CONF_RNG) || (defined(FOTA_SIMULATE_RANDOM) && FOTA_SIMULATE_RANDOM)
#undef MBEDTLS_SSL_CONF_RNG
#endif

#if defined(MBEDTLS_SSL_CONF_RNG)
#include "shared_rng.h"
#endif

#include <stdlib.h>

#define HASH_KEY ((uint8_t *) "FotaHashMainKey.")
#define TAG_SIZE 8

#if !defined(MBEDTLS_SSL_CONF_RNG)
static bool random_initialized = false;
#if defined(FOTA_SIMULATE_RANDOM) && FOTA_SIMULATE_RANDOM
static uint32_t random_seed_pos = 0;
static uint32_t random_seed_size = 0;
static uint8_t *random_seed = NULL;
#else
static mbedtls_entropy_context entropy_ctx;
#endif
#endif // !defined(MBEDTLS_SSL_CONF_RNG)

typedef struct fota_hash_context_s {
    mbedtls_sha256_context sha256_ctx;
} fota_hash_context_t;

typedef struct fota_encrypt_context_s {
    mbedtls_ccm_context ccm_ctx;
    fota_encrypt_config_t config;
    bool encrypt;
    bool got_partial_block;
    bool effective_block_size;
    uint64_t iv;
} fota_encrypt_context_t;

#define FOTA_TRACE_TLS_ERR(err) FOTA_TRACE_DEBUG("mbedTLS error %d", err)

int fota_encrypt_decrypt_start(fota_encrypt_context_t **ctx, const fota_encrypt_config_t *encrypt_config,
                               const uint8_t *key, uint32_t key_size, bool encrypt)
{
    FOTA_DBG_ASSERT(ctx);
    int ret;

    *ctx = NULL;

    fota_encrypt_context_t *enc_ctx = (fota_encrypt_context_t *) malloc(sizeof(fota_encrypt_context_t));
    if (!enc_ctx) {
        return FOTA_STATUS_OUT_OF_MEMORY;
    }

    memcpy(&enc_ctx->config, encrypt_config, sizeof(fota_encrypt_config_t));
    mbedtls_ccm_init(&enc_ctx->ccm_ctx);
    enc_ctx->iv = 0;
    enc_ctx->encrypt = encrypt;
    enc_ctx->got_partial_block = false;
    enc_ctx->effective_block_size = 0;

    ret = mbedtls_ccm_setkey(&enc_ctx->ccm_ctx, MBEDTLS_CIPHER_ID_AES, key, key_size * 8);
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        mbedtls_ccm_free(&enc_ctx->ccm_ctx);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }

    *ctx = enc_ctx;

    return FOTA_STATUS_SUCCESS;
}

void fota_encryption_stream_reset(fota_encrypt_context_t *ctx)
{
    FOTA_DBG_ASSERT(ctx);
    ctx->iv = 0;
    ctx->got_partial_block = false;
    ctx->effective_block_size = 0;

}

void fota_encryption_iv_increment(fota_encrypt_context_t *ctx)
{
    FOTA_DBG_ASSERT(ctx);
    ctx->iv++;
}

int fota_encryption_metadata_start(fota_encrypt_context_t *ctx, uint8_t *salt, uint32_t salt_len,
                                   uint32_t fw_size, uint8_t *metadata, uint32_t metdata_buffer_size,
                                   uint32_t *metadata_start_size, uint32_t *metadata_tags_size)
{
    FOTA_DBG_ASSERT(ctx);
    FOTA_DBG_ASSERT(salt);
    FOTA_DBG_ASSERT(salt_len == FOTA_ENCRYPT_METADATA_SALT_LEN);
    FOTA_DBG_ASSERT(metdata_buffer_size >= FOTA_ENCRYPT_METADATA_START_SIZE);
    FOTA_DBG_ASSERT(metadata);
    FOTA_DBG_ASSERT(metadata_start_size);
    FOTA_DBG_ASSERT(metadata_tags_size);

    uint32_t magic = FOTA_ENCRYPT_METADATA_MAGIC;

    uint32_t tags_size = (fw_size / ctx->config.encrypt_block_size);
    tags_size *= TAG_SIZE;
    if (fw_size % ctx->config.encrypt_block_size) {
        tags_size += TAG_SIZE;
    }

    // We need one additional tag for the fw header
    tags_size += TAG_SIZE;

    memcpy(metadata, &magic, sizeof(magic));
    metadata += sizeof(magic);

    memcpy(metadata, &tags_size, sizeof(tags_size));
    metadata += sizeof(tags_size);
    memcpy(metadata, salt, FOTA_ENCRYPT_METADATA_SALT_LEN);

    *metadata_start_size = FOTA_ENCRYPT_METADATA_START_SIZE;
    *metadata_tags_size = tags_size;

    return FOTA_STATUS_SUCCESS;
}

bool fota_encryption_metadata_parse(uint8_t *buffer, uint32_t buffer_len,
                                    uint32_t *tags_size, uint8_t *salt, uint32_t salt_len)
{

    if ((buffer_len < FOTA_ENCRYPT_METADATA_START_SIZE) ||
            (salt_len < FOTA_ENCRYPT_METADATA_SALT_LEN) ||
            (buffer == NULL) || (tags_size == NULL) || (salt == NULL)) {
        return false;
    }

    uint32_t magic;

    memcpy(&magic, buffer, sizeof(magic));
    if (magic != FOTA_ENCRYPT_METADATA_MAGIC) {
        return false;
    }

    buffer += sizeof(magic);
    memcpy(tags_size, buffer, sizeof(*tags_size));
    buffer += sizeof(*tags_size);
    memcpy(salt, buffer, FOTA_ENCRYPT_METADATA_SALT_LEN);

    return true;
}

int fota_encrypt_data(
    fota_encrypt_context_t *ctx,
    const uint8_t *in_buf, uint32_t buf_size, uint8_t *out_buf,
    uint8_t *metadata_buf, uint32_t metadata_buf_size, uint32_t *metadata_actual_size)
{
    FOTA_DBG_ASSERT(ctx);
    FOTA_DBG_ASSERT(in_buf);
    FOTA_DBG_ASSERT(out_buf);
    FOTA_DBG_ASSERT(metadata_buf);
    FOTA_DBG_ASSERT(metadata_actual_size);
    FOTA_DBG_ASSERT(ctx->encrypt);
    FOTA_DBG_ASSERT(metadata_buf_size >= TAG_SIZE);
    FOTA_DBG_ASSERT(buf_size <= ctx->config.encrypt_block_size);

    int ret;

    // Make sure partial blocks are only received once at the end
    FOTA_DBG_ASSERT(!ctx->got_partial_block);
    if (!ctx->effective_block_size) {
        ctx->effective_block_size = buf_size;
    } else if (buf_size < ctx->effective_block_size) {
        ctx->got_partial_block = true;
    }

    ret = mbedtls_ccm_encrypt_and_tag(
              &ctx->ccm_ctx, buf_size,
              (const unsigned char *) &ctx->iv, sizeof(ctx->iv),
              NULL, 0,
              in_buf, out_buf,
              metadata_buf, TAG_SIZE);

    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }

    fota_encryption_iv_increment(ctx);
    *metadata_actual_size = TAG_SIZE;

    return FOTA_STATUS_SUCCESS;
}

int fota_decrypt_data(
    fota_encrypt_context_t *ctx,
    const uint8_t *in_buf, uint32_t buf_size, uint8_t *out_buf,
    uint8_t *metadata_buf, uint32_t metadata_buf_size)
{
    FOTA_DBG_ASSERT(ctx);
    FOTA_DBG_ASSERT(in_buf);
    FOTA_DBG_ASSERT(out_buf);
    FOTA_DBG_ASSERT(metadata_buf);
    FOTA_DBG_ASSERT(!(ctx->encrypt));
    FOTA_DBG_ASSERT(metadata_buf_size >= TAG_SIZE);
    int ret;

    ret = mbedtls_ccm_auth_decrypt(
              &ctx->ccm_ctx, buf_size,
              (const unsigned char *) &ctx->iv, sizeof(ctx->iv),
              NULL, 0,
              in_buf, out_buf,
              metadata_buf, TAG_SIZE);

    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }

    fota_encryption_iv_increment(ctx);

    return FOTA_STATUS_SUCCESS;
}

int fota_encrypt_finalize(fota_encrypt_context_t **ctx)
{
    FOTA_DBG_ASSERT(ctx);
    if (*ctx) {
        mbedtls_ccm_free(&(*ctx)->ccm_ctx);
        free(*ctx);
        *ctx = NULL;
    }

    return FOTA_STATUS_SUCCESS;
}

int fota_hash_start(fota_hash_context_t **ctx)
{
    FOTA_DBG_ASSERT(ctx);
    int ret;
    *ctx = NULL;

    fota_hash_context_t *hash_ctx = (fota_hash_context_t *) malloc(sizeof(fota_hash_context_t));
    if (!hash_ctx) {
        return FOTA_STATUS_OUT_OF_MEMORY;
    }

    mbedtls_sha256_init(&hash_ctx->sha256_ctx);

    ret = mbedtls_sha256_starts_ret(&hash_ctx->sha256_ctx, 0);
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }

    *ctx = hash_ctx;
    return FOTA_STATUS_SUCCESS;
}

int fota_hash_update(fota_hash_context_t *ctx, const uint8_t *buf, uint32_t buf_size)
{
    FOTA_DBG_ASSERT(ctx);
    int ret = mbedtls_sha256_update_ret(&ctx->sha256_ctx, buf, buf_size);
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }
    return FOTA_STATUS_SUCCESS;
}

int fota_hash_result(fota_hash_context_t *ctx, uint8_t *hash_buf)
{
    FOTA_DBG_ASSERT(ctx);
    int ret = mbedtls_sha256_finish_ret(&ctx->sha256_ctx, hash_buf);
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }

    return FOTA_STATUS_SUCCESS;
}

int fota_hash_finish(fota_hash_context_t **ctx)
{
    FOTA_DBG_ASSERT(ctx);
    if (*ctx) {
        mbedtls_sha256_free(&(*ctx)->sha256_ctx);
        free(*ctx);
        *ctx = NULL;
    }

    return FOTA_STATUS_SUCCESS;
}

int fota_random_init(const uint8_t *seed, uint32_t seed_size)
{
#if !defined(MBEDTLS_SSL_CONF_RNG)
    if (!random_initialized) {
#if defined(FOTA_SIMULATE_RANDOM) && FOTA_SIMULATE_RANDOM
        FOTA_DBG_ASSERT(seed);
        FOTA_DBG_ASSERT(seed_size);
        random_seed_pos = 0;
        random_seed_size = seed_size;
        random_seed = (uint8_t *) malloc(random_seed_size);
        if (!random_seed) {
            return FOTA_STATUS_OUT_OF_MEMORY;
        }
        memcpy(random_seed, seed, random_seed_size);
#else
        mbedtls_entropy_init(&entropy_ctx);
#endif
        random_initialized = true;
    }
#endif // !defined(MBEDTLS_SSL_CONF_RNG)
    return FOTA_STATUS_SUCCESS;
}

#if !defined(MBEDTLS_SSL_CONF_RNG)
int fota_gen_random(uint8_t *buf, uint32_t buf_size)
{
    FOTA_DBG_ASSERT(random_initialized);

#if defined(FOTA_SIMULATE_RANDOM) && FOTA_SIMULATE_RANDOM
    for (uint32_t i = 0; i < buf_size; i++) {
        buf[i] = random_seed[random_seed_pos] + (uint8_t) i;
        random_seed_pos = (random_seed_pos + 1) % random_seed_size;
    }
#else
    int ret = mbedtls_entropy_func(&entropy_ctx, buf, buf_size);
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }
#endif
    return FOTA_STATUS_SUCCESS;
}
#else
int fota_gen_random(uint8_t *buf, uint32_t buf_size)
{
    int ret = global_rng(NULL, buf, buf_size);
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }
    return FOTA_STATUS_SUCCESS;
}
#endif // !defined(MBEDTLS_SSL_CONF_RNG)

int fota_random_deinit(void)
{
#if !defined(MBEDTLS_SSL_CONF_RNG)
    if (random_initialized) {
#if defined(FOTA_SIMULATE_RANDOM) && FOTA_SIMULATE_RANDOM
        free(random_seed);
#else
        mbedtls_entropy_free(&entropy_ctx);
#endif
        random_initialized = false;
    }
#endif // !defined(MBEDTLS_SSL_CONF_RNG)    
    return FOTA_STATUS_SUCCESS;
}

int fota_get_derived_key(const uint8_t *key, size_t key_size, const uint8_t *input, size_t input_size,
                         uint8_t *derived_key)
{
    uint8_t sha256_buf[FOTA_CRYPTO_HASH_SIZE];
    int ret;

    /* We will only be using 128 bits secret key for key derivation.
     * Larger input keys will be truncated to 128 bit length */
    FOTA_DBG_ASSERT(key_size >= FOTA_ENCRYPT_KEY_SIZE);

    ret = mbedtls_sha256_ret(input, input_size, sha256_buf, 0);
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }

    mbedtls_aes_context ctx = {0};
    mbedtls_aes_init(&ctx);

    ret = mbedtls_aes_setkey_enc(&ctx, key, key_size * 8);
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }

    /* Encrypting only first 128 bits, the reset is discarded */
    ret = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, sha256_buf, derived_key);
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }

    mbedtls_aes_free(&ctx);

    return FOTA_STATUS_SUCCESS;
}

int fota_fi_memcmp(const uint8_t *ptr1, const uint8_t *ptr2, size_t num, volatile size_t *loop_check)
{
    volatile int is_diff = 0;
    uint16_t start_pos = 0;
    volatile size_t pos;
    fota_gen_random((uint8_t *)&start_pos, sizeof(start_pos));
    start_pos %= num;

    for (*loop_check = 0; *loop_check < num; (*loop_check)++) {
        pos = (*loop_check + start_pos) % num;
        is_diff |= (ptr1[pos] ^ ptr2[pos]);
    }
    return is_diff;
}

int fota_random_delay(void)
{
    uint8_t spin_count;
    volatile int i = 0;
    // generate a random delay
    int ret = fota_gen_random((uint8_t *)&spin_count, sizeof(spin_count));
    if (ret) {
        return ret;
    }
    spin_count = spin_count % 100;

start:
    for (i = 0; i < spin_count; ++i) { } // spin delay

    // FI mitigation
    if (i < spin_count) {
        goto start;
    }

    return FOTA_STATUS_SUCCESS;
}

int fota_verify_signature(
    const uint8_t *signed_data, size_t signed_data_size,
    const uint8_t *sig, size_t sig_len,
    mbedtls_x509_crt *cert
)
{
    uint8_t digest[FOTA_CRYPTO_HASH_SIZE] = {0};
    mbedtls_sha256_context sha256_ctx = {0};
    mbedtls_sha256_init(&sha256_ctx);

    mbedtls_pk_context *pk_ctx_ptr = NULL;

    int fota_status = FOTA_STATUS_INTERNAL_ERROR;
    volatile int tls_status;
    int tmp_status;

// supporting both cripto lib api
#ifdef MBEDTLS_X509_ON_DEMAND_PARSING
    mbedtls_pk_context pk_ctx;
    pk_ctx_ptr = &pk_ctx;
    mbedtls_pk_init(pk_ctx_ptr);
    tls_status = mbedtls_x509_crt_get_pk(cert, pk_ctx_ptr);
    if (tls_status) {
        goto fail;
    }
#else
    pk_ctx_ptr = &cert->pk;
#endif

    tls_status = mbedtls_sha256_starts_ret(&sha256_ctx, 0);

    if (tls_status) {
        goto fail;
    }
    tls_status = mbedtls_sha256_update_ret(&sha256_ctx, signed_data, signed_data_size);
    if (tls_status) {
        goto fail;
    }

    tls_status = mbedtls_sha256_finish_ret(&sha256_ctx, digest);
    if (tls_status) {
        goto fail;
    }

    tls_status = mbedtls_pk_verify(
                     pk_ctx_ptr, MBEDTLS_MD_SHA256,
                     digest, sizeof(digest),
                     sig, sig_len);

    if (tls_status) {
        FOTA_TRACE_ERROR("Manifest signature verification failed (%d)", tls_status);
        fota_status = FOTA_STATUS_MANIFEST_SIGNATURE_INVALID;
        goto fail;
    }

    // FI mitigation - re-evaluating if to make sure FI are harder to implement
    tmp_status = fota_random_delay();
    if (tmp_status) {
        fota_status = tmp_status;
        goto fail;
    }

    if (tls_status) {
        FOTA_TRACE_ERROR("Manifest signature verification failed (%d)", tls_status);
        fota_status = FOTA_STATUS_MANIFEST_SIGNATURE_INVALID;
        goto fail;
    }

    // FI mitigation - re-evaluating if to make sure FI are harder to implement
    tmp_status = fota_random_delay();
    if (tmp_status) {
        fota_status = tmp_status;
        goto fail;
    }

    // re-evaluating if to make sure FI are harder to implement
    if (tls_status) {
        fota_status = FOTA_STATUS_MANIFEST_SIGNATURE_INVALID;
        goto fail;
    }
    fota_status = FOTA_STATUS_SUCCESS;

fail:
    if (tls_status) {
        FOTA_TRACE_ERROR("mbedtls failure %d", tls_status);
    }

#ifdef MBEDTLS_X509_ON_DEMAND_PARSING
    mbedtls_pk_free(pk_ctx_ptr);
#endif

    mbedtls_sha256_free(&sha256_ctx);
    return fota_status;
}

/*----------------------------mbedtls patch-----------------------------------*/
int mbedtls_asn1_get_enumerated_value(unsigned char **p,
                                      const unsigned char *end,
                                      int *val)
{
    int ret;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_ENUMERATED)) != 0) {
        return (ret);
    }

    if (len == 0 || len > sizeof(int) || (**p & 0x80) != 0) {
        return (MBEDTLS_ERR_ASN1_INVALID_LENGTH);
    }

    *val = 0;

    while (len-- > 0) {
        *val = (*val << 8) | **p;
        (*p)++;
    }

    return (0);
}

int mbedtls_asn1_get_int64(unsigned char **p,
                           const unsigned char *end,
                           int64_t *val)
{
    int ret;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_INTEGER)) != 0) {
        return (ret);
    }

    if (len == 0 || len > sizeof(int64_t) || (**p & 0x80) != 0) {
        return (MBEDTLS_ERR_ASN1_INVALID_LENGTH);
    }

    *val = 0;

    while (len-- > 0) {
        *val = (*val << 8) | **p;
        (*p)++;
    }

    return (0);
}

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
