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

#include "fota/fota_candidate.h"
#include "fota/fota_status.h"
#include "fota/fota_block_device.h"
#include "fota/fota_crypto.h"
#include "fota/fota_block_device.h"
#include "fota/fota_nvm.h"
#include <stdlib.h>
#include <inttypes.h>

#define MIN_FRAG_SIZE 128
#define TAGS_BUF_SIZE 128

typedef struct {
    fota_header_info_t header_info;
    uint8_t salt[FOTA_ENCRYPT_METADATA_SALT_LEN];
    uint32_t bd_read_size;
    uint32_t bd_prog_size;
    uint32_t curr_addr;
    uint32_t tags_addr;
    uint32_t data_start_addr;
    uint32_t frag_size;
    uint32_t bytes_completed;
    uint32_t next_pct;
    uint32_t tags_buf_size;
    uint32_t curr_tag_offs;
    uint8_t  *fragment_buf;
    uint8_t  *tags_buf;
    fota_encrypt_context_t *enc_ctx;
    bool is_encrypted;
} candidate_contex_t;

static fota_candidate_config_t fota_candidate_config = {
    .storage_start_addr     = 0,
    .storage_size           = 0,
    .encrypt_block_size     = 0
};

static candidate_contex_t *ctx = NULL;

uint32_t fota_bd_physical_addr_to_logical_addr(uint32_t phys_addr);

void fota_candidate_set_config(fota_candidate_config_t *in_fota_candidate_config)
{
    FOTA_ASSERT(in_fota_candidate_config->storage_size);
    memcpy(&fota_candidate_config, in_fota_candidate_config, sizeof(fota_candidate_config_t));
}

const fota_candidate_config_t *fota_candidate_get_config(void)
{
    if (!fota_candidate_config.storage_size) {
        fota_candidate_config_t fota_candidate_init_config = {
            .storage_start_addr     = fota_bd_physical_addr_to_logical_addr(MBED_CLOUD_CLIENT_FOTA_STORAGE_START_ADDR),
            .storage_size           = MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE,
            .encrypt_block_size     = MBED_CLOUD_CLIENT_FOTA_ENCRYPT_BLOCK_SIZE
        };
        fota_candidate_set_config(&fota_candidate_init_config);
    }
    return (const fota_candidate_config_t *) &fota_candidate_config;
}

static int bd_has_image(uint32_t *addr, const char *expected_comp_name)
{
    int ret = FOTA_STATUS_SUCCESS;
// Return success on non BL ready headers (let parse_header deal with it)
#if FOTA_HEADER_HAS_CANDIDATE_READY
    FOTA_DBG_ASSERT(ctx);
    uint8_t read_buf[sizeof(fota_candidate_ready_header_t)];
    uint8_t *aligned_read_buf = read_buf;
    fota_candidate_ready_header_t *header;
    uint32_t chunk_size = fota_align_up(sizeof(fota_candidate_ready_header_t), ctx->bd_read_size);

    if (chunk_size > sizeof(read_buf)) {
        // This is very unlikely to happen, as read size is usually 1.
        // So prefer the buffer to be allocated on stack, which is the likely case.
        aligned_read_buf = (uint8_t *) malloc(chunk_size);
        FOTA_ASSERT(aligned_read_buf);
    }
    ret = fota_bd_read(aligned_read_buf, *addr, chunk_size);
    if (ret) {
        ret = FOTA_STATUS_STORAGE_READ_FAILED;
        goto end;
    }

    // Advance read address for next calls
    *addr += fota_align_up(chunk_size, ctx->bd_prog_size);

    header = (fota_candidate_ready_header_t *) aligned_read_buf;
    if (header->magic != FOTA_CANDIDATE_READY_MAGIC) {
        FOTA_TRACE_INFO("No image found on storage");
        ret = FOTA_STATUS_NOT_FOUND;
        goto end;
    }

    if (strncmp(header->comp_name, expected_comp_name, strlen(expected_comp_name))) {
        FOTA_TRACE_ERROR("Unexpected component candidate found");
        ret = FOTA_STATUS_UNEXPECTED_COMPONENT;
        goto end;
    }

end:
    if (chunk_size > sizeof(read_buf)) {
        free(aligned_read_buf);
    }
#endif
    return ret;
}

static int bd_has_encrypted_image(uint32_t *addr, uint32_t *tags_size)
{
    int ret = FOTA_STATUS_NOT_FOUND;
#if FOTA_HEADER_SUPPORTS_ENCRYPTION
    FOTA_DBG_ASSERT(ctx);
    uint8_t read_buf[FOTA_ENCRYPT_METADATA_START_SIZE];
    uint8_t *aligned_read_buf = read_buf;
    uint32_t chunk_size = fota_align_up(FOTA_ENCRYPT_METADATA_START_SIZE, ctx->bd_read_size);

    if (chunk_size > sizeof(read_buf)) {
        // This is very unlikely to happen, as read size is usually 1.
        // So prefer the buffer to be allocated on stack, which is the likely case.
        aligned_read_buf = (uint8_t *) malloc(chunk_size);
        FOTA_ASSERT(aligned_read_buf);
    }
    ret = fota_bd_read(aligned_read_buf, *addr, chunk_size);
    if (ret) {
        ret = FOTA_STATUS_STORAGE_READ_FAILED;
        goto end;
    }

    if (!fota_encryption_metadata_parse(aligned_read_buf, chunk_size, tags_size, ctx->salt,
                                        FOTA_ENCRYPT_METADATA_SALT_LEN)) {
        FOTA_TRACE_INFO("Image on storage is not encrypted");
        ret = FOTA_STATUS_NOT_FOUND;
        goto end;
    }

    // Advance read address for next calls
    *addr += fota_align_up(chunk_size, ctx->bd_prog_size);

end:
    if (chunk_size > sizeof(read_buf)) {
        free(aligned_read_buf);
    }

#endif
    return ret;
}

static void cleanup()
{
    if (!ctx) {
        return;
    }
    if (ctx->enc_ctx) {
        fota_encrypt_finalize(&ctx->enc_ctx);
    }
    free(ctx->tags_buf);
    free(ctx->fragment_buf);
    free(ctx);
    ctx = 0;
}

static int parse_header(uint32_t *addr, bool encrypted, fota_header_info_t *header)
{
    uint32_t header_size = (uint32_t) fota_get_header_size();
    uint32_t read_size = fota_align_up(header_size, ctx->bd_read_size);

    FOTA_DBG_ASSERT(ctx);
    int ret = fota_bd_read(ctx->fragment_buf, *addr, read_size);
    *addr += fota_align_up(header_size, ctx->bd_prog_size);

    if (ret) {
        goto end;
    }

    if (encrypted) {
#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
        ret = fota_decrypt_data(ctx->enc_ctx, ctx->fragment_buf, header_size, ctx->fragment_buf,
                                ctx->tags_buf, FOTA_ENCRYPT_METADATA_MAX_SIZE);
        if (ret) {
            goto end;
        }
        ctx->curr_tag_offs += FOTA_ENCRYPT_METADATA_MAX_SIZE;
#endif
    }

    ret = fota_deserialize_header(ctx->fragment_buf, header_size, header);
    if (ret) {
        goto end;
    }

end:
    return ret;
}

static int fota_candidate_extract_start(bool force_encrypt, const char *expected_comp_name)
{
    int ret;
    uint32_t tags_size;

    if (!ctx) {
        ctx = (candidate_contex_t *) malloc(sizeof(candidate_contex_t));
        FOTA_ASSERT(ctx);
        memset(ctx, 0, sizeof(candidate_contex_t));
    }

    ctx->bd_read_size = fota_bd_get_read_size();
    if (!ctx->bd_read_size) {
        ret = FOTA_STATUS_INTERNAL_ERROR;
        goto fail;
    }

    ctx->bd_prog_size = fota_bd_get_program_size();
    if (!ctx->bd_prog_size) {
        ret = FOTA_STATUS_INTERNAL_ERROR;
        goto fail;
    }

    ctx->curr_addr = fota_candidate_get_config()->storage_start_addr;
    ret = bd_has_image(&ctx->curr_addr, expected_comp_name);
    if (ret) {
        goto fail;
    }

    ret = bd_has_encrypted_image(&ctx->curr_addr, &tags_size);
    if (!ret) {
#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 0)
        FOTA_TRACE_ERROR("Encrypted candidate image - not supported");
        ret = FOTA_STATUS_UNSUPPORTED;
        goto fail;
#endif
        ctx->is_encrypted = true;
        ctx->frag_size = MAX(MIN_FRAG_SIZE, fota_candidate_get_config()->encrypt_block_size);
        ctx->frag_size = fota_align_up(ctx->frag_size, ctx->bd_read_size);
        FOTA_TRACE_INFO("Found an encrypted image at address 0x%" PRIx32, fota_candidate_get_config()->storage_start_addr);
    } else if (ret == FOTA_STATUS_NOT_FOUND) {
        if (force_encrypt) {
            FOTA_TRACE_ERROR("Non-encrypted image found, but this is not allowed for this candidate type.");
            ret = FOTA_STATUS_NOT_ALLOWED;
            goto fail;
        }
        ctx->is_encrypted = false;
        ctx->frag_size = fota_align_up(MIN_FRAG_SIZE, ctx->bd_read_size);
        FOTA_TRACE_INFO("Found a non-encrypted image at address 0x%" PRIx32, fota_candidate_get_config()->storage_start_addr);
    } else {
        goto fail;
    }

    ctx->fragment_buf = (uint8_t *) malloc(ctx->frag_size);
    FOTA_ASSERT(ctx->fragment_buf);

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    if (ctx->is_encrypted) {
        fota_encrypt_config_t encrypt_config;
        uint8_t fw_enc_key[FOTA_ENCRYPT_KEY_SIZE];
        uint8_t derived_key[FOTA_ENCRYPT_KEY_SIZE];

        ret = fota_nvm_fw_encryption_key_get(fw_enc_key);
        if (ret) {
            FOTA_TRACE_ERROR("FW encryption key get failed. ret %d", ret);
            goto fail;
        }

        ret = fota_get_derived_key(fw_enc_key, sizeof(fw_enc_key), ctx->salt,
                                   sizeof(ctx->salt), derived_key);
        if (ret) {
            FOTA_TRACE_ERROR("Derived key get failed. ret %d", ret);
            goto fail;
        }

        encrypt_config.encrypt_block_size = fota_candidate_get_config()->encrypt_block_size;
        ret = fota_encrypt_decrypt_start(&ctx->enc_ctx, &encrypt_config, derived_key, FOTA_ENCRYPT_KEY_SIZE, false);
        if (ret) {
            FOTA_TRACE_ERROR("Decrypt start failed. ret %d", ret);
            goto fail;
        }

        // Make sure we don't read partial tags
        FOTA_DBG_ASSERT(!((ctx->bd_read_size % FOTA_ENCRYPT_METADATA_MAX_SIZE) &&
                          (FOTA_ENCRYPT_METADATA_MAX_SIZE % ctx->bd_read_size)));

        ctx->tags_buf_size = fota_align_up(TAGS_BUF_SIZE, ctx->bd_read_size);
        ctx->tags_buf_size = fota_align_up(ctx->tags_buf_size, FOTA_ENCRYPT_METADATA_MAX_SIZE);

        ctx->tags_buf = (uint8_t *) malloc(ctx->tags_buf_size);
        if (!ctx->tags_buf) {
            FOTA_TRACE_ERROR("Unable to allocate tags buffer");
            ret = FOTA_STATUS_OUT_OF_MEMORY;
            goto fail;
        }

        ctx->curr_tag_offs = 0;
        ctx->tags_addr = ctx->curr_addr;
        ret = fota_bd_read(ctx->tags_buf, ctx->tags_addr, ctx->tags_buf_size);
        if (ret) {
            FOTA_TRACE_ERROR("Reading tags failed. ret %d", ret);
            goto fail;
        }
        ctx->curr_addr = fota_align_up(ctx->curr_addr + tags_size, ctx->bd_prog_size);
    }
#endif

    ret = parse_header(&ctx->curr_addr, ctx->is_encrypted, &ctx->header_info);
    if (ret) {
        FOTA_TRACE_ERROR("Header parsing failed. ret %d", ret);
        goto fail;
    }

    ctx->data_start_addr = ctx->curr_addr;

    return FOTA_STATUS_SUCCESS;

fail:
    cleanup();
    return ret;
}

static int fota_candidate_extract_fragment(uint8_t **buf, uint32_t *actual_size)
{
    uint32_t chunk, read_size;
    int ret;

    FOTA_DBG_ASSERT(ctx);
    chunk = MIN(ctx->header_info.fw_size - ctx->bytes_completed, ctx->frag_size);
    *actual_size = chunk;
    if (!chunk) {
        return FOTA_STATUS_SUCCESS;
    }

    if (ctx->is_encrypted) {
        // encrypted blocks are aligned to program size
        read_size = fota_align_up(chunk, ctx->bd_prog_size);
    } else {
        read_size = fota_align_up(chunk, ctx->bd_read_size);
    }

    ret = fota_bd_read(ctx->fragment_buf, ctx->curr_addr, read_size);
    if (ret) {
        FOTA_TRACE_ERROR("storage read failed, ret %d", ret);
        return ret;
    }

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    if (ctx->is_encrypted) {
        // exhausted tag group, read next one
        if (!(ctx->curr_tag_offs % ctx->tags_buf_size)) {
            ret = fota_bd_read(ctx->tags_buf, ctx->tags_addr + ctx->curr_tag_offs, ctx->tags_buf_size);
            if (ret) {
                FOTA_TRACE_ERROR("Reading tags failed. ret %d", ret);
                return ret;
            }
        }

        ret = fota_decrypt_data(ctx->enc_ctx, ctx->fragment_buf, read_size, ctx->fragment_buf,
                                ctx->tags_buf + ctx->curr_tag_offs % ctx->tags_buf_size, FOTA_ENCRYPT_METADATA_MAX_SIZE);
        ctx->curr_tag_offs += FOTA_ENCRYPT_METADATA_MAX_SIZE;
        if (ret) {
            FOTA_TRACE_ERROR("decrypt data failed, ret %d", ret);
            return ret;
        }
    }
#endif

    ctx->bytes_completed += chunk;
    ctx->curr_addr += chunk;
    *buf = ctx->fragment_buf;

    return FOTA_STATUS_SUCCESS;
}

int fota_candidate_extract_finish()
{
    cleanup();
    return FOTA_STATUS_SUCCESS;
}

int fota_candidate_iterate_image(bool validate, bool force_encrypt, const char *expected_comp_name,
                                 fota_candidate_iterate_handler_t handler)
{
    int ret;
    fota_candidate_iterate_callback_info cb_info;
    uint32_t actual_size;
    uint8_t *buf;
    fota_hash_context_t *hash_ctx = NULL;

    FOTA_ASSERT(handler);
    ret = fota_candidate_extract_start(force_encrypt, expected_comp_name);
    if (ret) {
        goto fail;
    }

    if (validate) {
        FOTA_TRACE_INFO("Validating image...");
        uint8_t hash_output[FOTA_CRYPTO_HASH_SIZE];

        ret = fota_hash_start(&hash_ctx);
        if (ret) {
            goto fail;
        }
        do {
            ret = fota_candidate_extract_fragment(&buf, &actual_size);
            if (ret) {
                goto fail;
            }
            ret = fota_hash_update(hash_ctx, buf, actual_size);
            if (ret) {
                goto fail;
            }

        } while (actual_size);

        ret = fota_hash_result(hash_ctx, hash_output);
        if (ret) {
            goto fail;
        }

        fota_hash_finish(&hash_ctx);

        FOTA_FI_SAFE_MEMCMP(hash_output, ctx->header_info.digest, FOTA_CRYPTO_HASH_SIZE,
                            FOTA_STATUS_MANIFEST_PAYLOAD_CORRUPTED,
                            "Hash mismatch - corrupted candidate");

        // No need to call start extract again as it's quite heavy.
        // Return to the state at the beginning of the data
        ctx->curr_addr = ctx->data_start_addr;
        ctx->bytes_completed = 0;
#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
        if (ctx->is_encrypted) {
            ret = fota_bd_read(ctx->tags_buf, ctx->tags_addr, ctx->tags_buf_size);
            if (ret) {
                FOTA_TRACE_ERROR("Reading tags failed. ret %d", ret);
                goto fail;
            }
            // Skip header tag
            ctx->curr_tag_offs = FOTA_ENCRYPT_METADATA_MAX_SIZE;
            fota_encryption_stream_reset(ctx->enc_ctx);
            fota_encryption_iv_increment(ctx->enc_ctx); // compensate for parse_header
        }
#endif
        FOTA_TRACE_INFO("Image is valid.");
    }

    // Start iteration phase
    memset(&cb_info, 0, sizeof(cb_info));

    cb_info.status = FOTA_CANDIDATE_ITERATE_START;
    cb_info.header_info = &ctx->header_info;
    cb_info.salt = ctx->salt;
    ret = handler(&cb_info);
    if (ret) {
        FOTA_TRACE_ERROR("Candidate user handler failed on start, ret %d", ret);
        goto fail;
    }

    do {
        ret = fota_candidate_extract_fragment(&buf, &actual_size);
        if (ret) {
            goto fail;
        }
        cb_info.status = FOTA_CANDIDATE_ITERATE_FRAGMENT;
        cb_info.frag_size = actual_size;
        cb_info.frag_pos = ctx->bytes_completed - actual_size;
        cb_info.frag_buf = buf;
        ret = handler(&cb_info);
        if (ret) {
            FOTA_TRACE_ERROR("Candidate user handler failed on fragment, ret %d", ret);
            goto fail;
        }
    } while (actual_size);

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    if (ctx->is_encrypted) {
        fota_encrypt_finalize(&ctx->enc_ctx);
    }
#endif

    cb_info.status = FOTA_CANDIDATE_ITERATE_FINISH;
    ret = handler(&cb_info);
    if (ret) {
        FOTA_TRACE_ERROR("Candidate user handler failed on finish, ret %d", ret);
        goto fail;
    }

fail:
    if (hash_ctx) {
        fota_hash_finish(&hash_ctx);
    }
    cleanup();
    return ret;
}

int fota_candidate_erase(void)
{
    int ret = fota_bd_erase(fota_candidate_get_config()->storage_start_addr, fota_bd_get_erase_size(fota_candidate_get_config()->storage_start_addr));
    return ret;
}

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
