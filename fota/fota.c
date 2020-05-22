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

#include "fota/fota.h"
#include "fota/fota_status.h"
#include "fota/fota_internal.h"
#include "fota/fota_manifest.h"
#include "fota/fota_source.h"
#include "fota/fota_delta.h"
#include "fota/fota_app_ifs.h"
#include "fota/fota_platform.h"
#include "fota/fota_nvm.h"
#include "fota/fota_block_device.h"
#include "fota/fota_crypto.h"
#include "fota/fota_header_info.h"
#include "fota/fota_curr_fw.h"
#include "fota/fota_event_handler.h"
#include "fota/fota_candidate.h"
#include "fota/fota_component.h"
#include "fota/fota_component_internal.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509.h"
#include <stdlib.h>
#include <inttypes.h>

#ifdef __MBED__
#include "mbed_power_mgmt.h"
#endif

#define MAIN_COMP_NUM 0

static fota_context_t *fota_ctx = NULL;

static int handle_fw_fragment(uint8_t *buf, size_t size, bool last);
static void handle_manifest(uint8_t *manifest_buf, size_t manifest_size, bool is_resume);
static void on_reboot(void);

static bool initialized = false;

static void free_context_buffers(void)
{
    if (!fota_ctx) {
        return;
    }
    free(fota_ctx->fw_info);
    fota_ctx->fw_info = NULL;
    free(fota_ctx->page_buf);
    fota_ctx->page_buf = NULL;
    free(fota_ctx->metadata_start_buf);
    fota_ctx->metadata_start_buf = NULL;
    free(fota_ctx->metadata_buf);
    fota_ctx->metadata_buf = NULL;

#if !defined(FOTA_DISABLE_DELTA)
    free(fota_ctx->delta_buf);
    fota_ctx->delta_buf = NULL;
    if (fota_ctx->delta_ctx) {
        fota_delta_finalize(&fota_ctx->delta_ctx);
    }
#endif  // !defined(FOTA_DISABLE_DELTA)

    if (fota_ctx->enc_ctx) {
        fota_encrypt_finalize(&fota_ctx->enc_ctx);
    }
    if (fota_ctx->curr_fw_hash_ctx) {
        fota_hash_finish(&fota_ctx->curr_fw_hash_ctx);
    }
}

static void update_cleanup(void)
{
    free_context_buffers();
    free(fota_ctx);
    fota_ctx = NULL;
}

#define abort_update(ret, msg) do { \
    FOTA_TRACE_ERROR("Update aborted: %s", msg); \
    abort_update__(ret); \
} while(0)
static void abort_update__(int ret)
{
    int upd_res;
    bool do_terminate_update = true;

    if (!fota_is_active_update()) {
        return;
    }

    if (ret == FOTA_STATUS_FAIL_UPDATE_STATE ||
            ret == FOTA_STATUS_UPDATE_DEFERRED) {
        do_terminate_update = false;  // recoverable error, will trigger resume
    } else {
        upd_res = -1 * ret; // return to cloud
    }

    if (do_terminate_update) {
        fota_source_report_update_result(upd_res);
        fota_source_report_state(FOTA_SOURCE_STATE_IDLE, NULL, NULL);
        fota_nvm_manifest_delete();
    } else {
        fota_source_report_state(FOTA_SOURCE_STATE_PROCESSING_MANIFEST, NULL, NULL);
    }

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    fota_nvm_salt_delete();
#endif
    const fota_component_desc_t *comp_desc;
    fota_component_get_desc(fota_ctx->comp_id, &comp_desc);
    fota_platform_abort_update_hook(comp_desc->name);
    fota_app_on_complete(ret); //notify application
    update_cleanup();
}

static void on_state_set_failure(void)
{
    abort_update(FOTA_STATUS_FAIL_UPDATE_STATE, "Failed to deliver FOTA state");
}

bool fota_is_active_update(void)
{
    return (fota_ctx != NULL);
}

fota_state_e fota_is_ready(uint8_t *data, size_t size)
{
    size_t manifest_size;
    uint8_t *manifest = malloc(FOTA_MANIFEST_MAX_SIZE);
    FOTA_ASSERT(manifest);
    memset(manifest, 0, FOTA_MANIFEST_MAX_SIZE);

    int ret = fota_nvm_manifest_get(manifest, FOTA_MANIFEST_MAX_SIZE, &manifest_size);
    if (ret) { //  cannot find saved manifest - ready to start an update
        free(manifest);
        return FOTA_STATE_IDLE;
    }
    if ((size == manifest_size) && (0 == memcmp(manifest, data, manifest_size))) {
        // notify FOTA already handles same manifest
        free(manifest);
        return FOTA_STATE_DOWNLOADING;
    }
    // fota is busy - different update is active
    free(manifest);
    return FOTA_STATE_INVALID;
}

static inline void fota_dev_init(void)
{
    int ret;

#if defined(MBED_CLOUD_DEV_UPDATE_ID) && !defined(FOTA_USE_EXTERNAL_IDS)
    ret = fota_nvm_update_class_id_set();
    FOTA_ASSERT(!ret);

    ret = fota_nvm_update_vendor_id_set();
    FOTA_ASSERT(!ret);
#endif

#if defined(MBED_CLOUD_DEV_UPDATE_CERT) && !defined(FOTA_USE_EXTERNAL_CERT)
    ret = fota_nvm_update_cert_set();
    FOTA_ASSERT(!ret);
#endif

    (void)ret;  // fix unused variable warning in production
}

static int curr_fw_get_digest(uint8_t *buf)
{
    fota_header_info_t curr_fw_info;
    int ret = fota_curr_fw_read_header(&curr_fw_info);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to read current header");
        return ret;
    }
    memcpy(buf, curr_fw_info.digest, FOTA_CRYPTO_HASH_SIZE);
    return FOTA_STATUS_SUCCESS;
}

int fota_init(endpoint_t *in_endpoint)
{
    uint8_t vendor_id[FOTA_GUID_SIZE];
    uint8_t class_id[FOTA_GUID_SIZE];
    uint8_t *manifest = NULL;
    size_t manifest_size = 0;
    fota_source_state_e source_state = FOTA_SOURCE_STATE_IDLE;
    fota_component_desc_t main_component_desc = {0};

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    uint8_t salt[FOTA_ENCRYPT_METADATA_SALT_LEN];
#endif

    int ret;
    bool after_upgrade = false;

    if (initialized) {
        return FOTA_STATUS_SUCCESS;
    }

    fota_dev_init();

    FOTA_DBG_ASSERT(!fota_ctx);

    FOTA_DBG_ASSERT(in_endpoint);

    FOTA_TRACE_DEBUG("init start");

    ret = fota_random_init(NULL, 0);
    FOTA_ASSERT(!ret);

    ret = fota_nvm_get_vendor_id(vendor_id);
    FOTA_ASSERT(!ret);
    ret = fota_nvm_get_class_id(class_id);
    FOTA_ASSERT(!ret);

    fota_header_info_t header_info;
    ret = fota_curr_fw_read_header(&header_info);
    FOTA_ASSERT(!ret);

    ret = fota_event_handler_init();  // Note: must be done before fota_source
    FOTA_ASSERT(!ret);

    manifest = malloc(FOTA_MANIFEST_MAX_SIZE);
    FOTA_ASSERT(manifest);

    ret = fota_nvm_manifest_get(manifest, FOTA_MANIFEST_MAX_SIZE, &manifest_size);
    if (!ret) {
        source_state = FOTA_SOURCE_STATE_PROCESSING_MANIFEST;
    } else {
#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
        ret = fota_nvm_salt_get(salt);
        after_upgrade = !ret;
        fota_nvm_salt_delete();
#else
        // TODO: check if candidate ready is present (need to take care of read size and bd init sequence)
#endif
    }

    free(manifest);

    if (after_upgrade) {
        FOTA_TRACE_INFO("After upgrade. Cleaning up.");
        // TODO: verify the new FW version was actually installed by bootloader
        fota_app_on_complete(FOTA_STATUS_SUCCESS);
    }

    ret = fota_source_init(
              in_endpoint,
              vendor_id, sizeof(vendor_id),
              class_id, sizeof(class_id),
#if FOTA_SOURCE_COMPONENT_BACKWARD_COMPATIBILITY_MODE
              header_info.digest, sizeof(header_info.digest),
              header_info.version,
#endif
              source_state);
    FOTA_ASSERT(!ret);

    fota_component_init();

    // register main component (should be done before platform init hook, which registers all other components).
    strcpy(main_component_desc.name, FOTA_COMPONENT_MAIN_COMPONENT_NAME);
    // "Factory" version here is what we read from main firmware header, as we don't save it to NVM.
    fota_component_version_int_to_semver(header_info.version, main_component_desc.factory_version);
    main_component_desc.candidate_iterate_cb = NULL;
    main_component_desc.need_reboot = true;
    main_component_desc.support_delta = true;
    main_component_desc.curr_fw_read = fota_curr_fw_read;
    main_component_desc.curr_fw_get_digest = curr_fw_get_digest;
    ret = fota_component_add(&main_component_desc);
    FOTA_DBG_ASSERT(!ret);
#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION >= 3)
    // Don't show that in legacy case
    FOTA_TRACE_INFO("Registered %s component, version %s", main_component_desc.name, main_component_desc.factory_version);
#endif

    fota_component_set_curr_version(MAIN_COMP_NUM, header_info.version);

    ret = fota_source_add_component(MAIN_COMP_NUM, main_component_desc.name, main_component_desc.factory_version);
    FOTA_DBG_ASSERT(!ret);

    ret = fota_platform_init_hook(after_upgrade);
    FOTA_ASSERT(!ret);

    // Code saving - only relevant if we have additional components other than the main one
#if (FOTA_NUM_COMPONENTS > 1)
    // Now we should have all components registered, report them all
    unsigned int num_comps = fota_component_num_components();
    for (unsigned int i = 1; i < num_comps; i++) {
        const fota_component_desc_t *comp_desc;
        char nvm_semver[FOTA_COMPONENT_MAX_SEMVER_STR_SIZE] = {0};
        fota_component_version_t version;
        const char *semver;
        fota_component_get_desc(i, &comp_desc);
        ret = fota_nvm_comp_version_get(comp_desc->name, &version);
        if (!ret) {
            ret = fota_component_version_int_to_semver(version, nvm_semver);
            semver = nvm_semver;
        } else {
            ret = fota_component_version_semver_to_int(comp_desc->factory_version, &version);
            semver = comp_desc->factory_version;
        }

        FOTA_TRACE_INFO("Registered %s component, version %s", comp_desc->name, semver);
        ret = fota_source_add_component(i, comp_desc->name, semver);
        FOTA_DBG_ASSERT(!ret);
        fota_component_set_curr_version(i, version);
    }
#endif // FOTA_NUM_COMPONENTS > 1

    initialized = true;
    FOTA_TRACE_DEBUG("init complete");

    return FOTA_STATUS_SUCCESS;
}

int fota_deinit(void)
{
    if (!initialized) {
        FOTA_TRACE_DEBUG("fota_deinit skipped");
        return FOTA_STATUS_SUCCESS;
    }

    FOTA_TRACE_DEBUG("fota_deinit");

    update_cleanup();
    fota_source_deinit();
    fota_random_deinit();
    fota_event_handler_deinit();
    fota_bd_deinit();
    initialized = false;
    return FOTA_STATUS_SUCCESS;
}

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)

static int init_encryption(size_t prog_size, size_t fw_size_in_storage)
{
    int ret = FOTA_STATUS_INTERNAL_ERROR;

    fota_encrypt_config_t encrypt_config;
    fota_ctx->page_buf_size = MAX(fota_candidate_get_config()->encrypt_block_size, fota_ctx->page_buf_size);

    fota_ctx->metadata_buf_size = MAX(prog_size, fota_align_up(FOTA_ENCRYPT_METADATA_MAX_SIZE, prog_size));
    fota_ctx->metadata_buf = malloc(fota_ctx->metadata_buf_size);
    if (!fota_ctx->metadata_buf) {
        FOTA_TRACE_DEBUG("FOTA encryption metadata - allocation failed");
        return FOTA_STATUS_OUT_OF_MEMORY;
    }

    fota_ctx->metadata_start_buf = malloc(FOTA_ENCRYPT_METADATA_START_SIZE);
    if (!fota_ctx->metadata_start_buf) {
        FOTA_TRACE_DEBUG("FOTA encryption start metadata - allocation failed");
        return FOTA_STATUS_OUT_OF_MEMORY;
    }

    FOTA_ASSERT((fota_candidate_get_config()->encrypt_block_size % fota_ctx->page_buf_size) == 0);

    encrypt_config.encrypt_block_size = fota_candidate_get_config()->encrypt_block_size;

    uint8_t fw_enc_key[FOTA_ENCRYPT_KEY_SIZE];
    uint8_t salt[FOTA_ENCRYPT_METADATA_SALT_LEN];
    uint8_t derived_key[FOTA_ENCRYPT_KEY_SIZE];

    if (fota_gen_random(salt, sizeof(salt))) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    ret = fota_nvm_salt_set(salt);
    if (ret) {
        return ret;
    }

    FOTA_TRACE_DEBUG("FOTA encryption salt saved");

    ret = fota_nvm_fw_encryption_key_get(fw_enc_key);
    if (ret == FOTA_STATUS_NOT_FOUND) {
        ret = fota_gen_random(fw_enc_key, sizeof(fw_enc_key));
        if (ret) {
            return ret;
        }
        ret = fota_nvm_fw_encryption_key_set(fw_enc_key);
    }
    if (ret) {
        return ret;
    }

    ret = fota_get_derived_key(fw_enc_key, sizeof(fw_enc_key), salt, sizeof(salt), derived_key);
    if (ret) {
        return ret;
    }

    FOTA_TRACE_DEBUG("FOTA encryption key generated");

    ret = fota_encrypt_decrypt_start(&fota_ctx->enc_ctx, &encrypt_config, derived_key,
                                     FOTA_ENCRYPT_KEY_SIZE, true);
    if (ret) {
        return ret;
    }

    ret = fota_encryption_metadata_start(fota_ctx->enc_ctx, salt, sizeof(salt), fw_size_in_storage,
                                         fota_ctx->metadata_start_buf, fota_candidate_get_config()->encrypt_block_size,
                                         &fota_ctx->metadata_start_size, &fota_ctx->metadata_tags_size);
    if (ret) {
        return ret;
    }

    FOTA_TRACE_DEBUG("FOTA encryption engine initialized");

    fota_ctx->fw_offset_in_storage += fota_align_up(fota_ctx->metadata_start_size, prog_size) +
                                      fota_align_up(fota_ctx->metadata_tags_size, prog_size);

    return FOTA_STATUS_SUCCESS;
}

static int write_initial_metadata(void)
{
    // Write initial metadata
    if ((fota_ctx->metadata_start_size) && (fota_ctx->metadata_tags_size)) {
        uint32_t metadata_header_size = fota_align_up(fota_ctx->metadata_start_size, fota_bd_get_program_size());
        fota_ctx->metadata_curr_addr = fota_candidate_get_config()->storage_start_addr + fota_ctx->candidate_header_size;
        int ret = fota_bd_program(fota_ctx->metadata_start_buf, fota_ctx->metadata_curr_addr, metadata_header_size);
        if (ret) {
            FOTA_TRACE_ERROR("Metadata write to storage failed");
            return FOTA_STATUS_STORAGE_WRITE_FAILED;
        }
        fota_ctx->metadata_curr_addr += metadata_header_size;
    }

    return FOTA_STATUS_SUCCESS;
}

static int handle_metadata_fragment(uint8_t *buf, size_t size)
{
    uint8_t *source_buf = buf, *prog_buf;
    uint32_t prog_size;
    uint32_t chunk;
    // Only need to flush if we have something in the page buffer
    bool flush = ((size == 0) && (buf == 0));

    while (size || flush) {
        if (fota_ctx->metadata_buf_offset || (size < fota_ctx->metadata_buf_size)) {
            chunk = MIN(fota_ctx->metadata_buf_size - fota_ctx->metadata_buf_offset, size);
            prog_size = fota_ctx->metadata_buf_offset + chunk;
            prog_buf = fota_ctx->metadata_buf;
            memcpy(fota_ctx->metadata_buf + fota_ctx->metadata_buf_offset, source_buf, chunk);
            if (flush) {
                // May have a partial page here, align up to page
                prog_size = fota_align_up(prog_size, fota_ctx->metadata_buf_size);
                memset(prog_buf + fota_ctx->metadata_buf_offset + chunk, 0,
                       fota_ctx->metadata_buf_size - fota_ctx->metadata_buf_offset - chunk);
            }
            fota_ctx->metadata_buf_offset = (fota_ctx->metadata_buf_offset + chunk) % fota_ctx->metadata_buf_size;
        } else {
            chunk = fota_align_down(size, fota_ctx->metadata_buf_size);
            prog_size = chunk;
            prog_buf = source_buf;
            source_buf += chunk;
        }
        if (prog_size >= fota_ctx->metadata_buf_size) {
            int ret = fota_bd_program(prog_buf, fota_ctx->metadata_curr_addr, prog_size);
            if (ret) {
                FOTA_TRACE_ERROR("Write to storage failed, address %" PRIu32 ", size %" PRIu32,
                                 fota_ctx->metadata_curr_addr, prog_size);
                return FOTA_STATUS_STORAGE_WRITE_FAILED;
            }

            fota_ctx->metadata_curr_addr += prog_size;
        }
        size -= chunk;
        flush = false;
    }
    return FOTA_STATUS_SUCCESS;
}

#endif

static int init_header(size_t prog_size)
{
    fota_ctx->fw_header_bd_size = fota_align_up(fota_get_header_size(), prog_size);

    // Reserve space for candidate ready header (if not legacy header version)
#if FOTA_HEADER_HAS_CANDIDATE_READY
    fota_ctx->candidate_header_size = fota_align_up(sizeof(fota_candidate_ready_header_t), prog_size);
#else
    fota_ctx->candidate_header_size = 0;
#endif

    fota_ctx->fw_offset_in_storage = fota_ctx->candidate_header_size + fota_ctx->fw_header_bd_size;
    return FOTA_STATUS_SUCCESS;
}

void request_download_auth(void)
{
    FOTA_TRACE_DEBUG("Download Authorization requested");
    fota_component_version_t curr_ver;

    fota_component_get_curr_version(fota_ctx->comp_id, &curr_ver);
    int ret = fota_app_on_download_authorization(
                  fota_ctx->auth_token,
                  fota_ctx->fw_info,
                  curr_ver
              );
    if (ret) {
        abort_update(ret, "Failed delivering Downloading authorization request");
        return;
    }
}

static void handle_manifest(uint8_t *manifest_buf, size_t manifest_size, bool is_resume)
{
    int ret;
    int manifest_save_ret = FOTA_STATUS_INTERNAL_ERROR;
    uint8_t *update_crt_data = NULL;
    size_t update_crt_size;
    mbedtls_x509_crt crt;
    uint32_t prog_size;
    uint32_t fw_size_in_storage;
    const fota_component_desc_t *comp_desc;
    fota_component_version_t curr_fw_version;
    uint8_t curr_fw_digest[FOTA_CRYPTO_HASH_SIZE] = {0};

    if (fota_ctx) {
        ret = FOTA_STATUS_MANIFEST_ALREADY_IN_PROCESS;
        FOTA_TRACE_ERROR("Manifest already in progress.");
        goto fail;
    }

    fota_ctx = (fota_context_t *)malloc(sizeof(*fota_ctx));
    if (!fota_ctx) {
        ret = FOTA_STATUS_OUT_OF_MEMORY;
        goto fail;
    }
    memset(fota_ctx, 0, sizeof(*fota_ctx));

    fota_ctx->fw_info = (manifest_firmware_info_t *) malloc(sizeof(manifest_firmware_info_t));
    if (!fota_ctx->fw_info) {
        ret = FOTA_STATUS_OUT_OF_MEMORY;
        goto fail;
    }
    memset(fota_ctx->fw_info, 0, sizeof(manifest_firmware_info_t));

    FOTA_TRACE_INFO("Firmware update initiated.");


    if (!is_resume) {
        manifest_save_ret = fota_nvm_manifest_set(manifest_buf, manifest_size);
        if (manifest_save_ret) {
            FOTA_TRACE_ERROR("failed to persist manifest %d", manifest_save_ret);
            // ignore the error as it is not essential for good path update
        }
        fota_source_send_manifest_received_ack(); // acknowledge manifest received
        // MUST be done ONLY after persisting the manifest
    }

    update_crt_data = (uint8_t *)malloc(FOTA_CERT_MAX_SIZE);
    if (!update_crt_data) {
        FOTA_TRACE_ERROR("failed to allocate storage for update certificate");
        ret = FOTA_STATUS_OUT_OF_MEMORY;
        goto fail;
    }

    ret = fota_nvm_get_update_certificate(update_crt_data, FOTA_CERT_MAX_SIZE, &update_crt_size);
    if (ret) {
        FOTA_TRACE_ERROR("failed to get update certificate %d", ret);
        ret = FOTA_STATUS_CERT_NOT_FOUND;
        goto fail;
    }

    mbedtls_x509_crt_init(&crt);

    ret = mbedtls_x509_crt_parse_der_nocopy(&crt, update_crt_data, update_crt_size);
    if (ret) {
        FOTA_TRACE_ERROR("failed to parse update certificate %d", ret);
        if (ret == MBEDTLS_ERR_X509_ALLOC_FAILED) {
            ret = FOTA_STATUS_OUT_OF_MEMORY;
        } else {
            ret = FOTA_STATUS_INVALID_CERTIFICATE;
        }
        mbedtls_x509_crt_free(&crt);
        free(update_crt_data);
        goto fail;
    }
    FOTA_TRACE_DEBUG("Update certificate loaded successfully");
    ret = fota_manifest_parse(
              manifest_buf, manifest_size,
              fota_ctx->fw_info,
              &crt);

    mbedtls_x509_crt_free(&crt);
    free(update_crt_data);

    if (ret) {
        FOTA_TRACE_DEBUG("Pelion FOTA manifest rejected %d", ret);
        goto fail;
    }
    FOTA_TRACE_DEBUG("Pelion FOTA manifest is valid");

    // Reset manifest data, no need to keep it anymore
    memset(manifest_buf, 0, manifest_size);

    // TODO: Extract component id from name in manifest. Currently fix it to main component.
    strcpy(fota_ctx->fw_info->component_name, FOTA_COMPONENT_MAIN_COMPONENT_NAME);

    ret = fota_component_name_to_id(fota_ctx->fw_info->component_name, &fota_ctx->comp_id);
    if (ret) {
        ret = FOTA_STATUS_MANIFEST_UNKNOWN_COMPONENT;
        goto fail;
    }
    fota_component_get_desc(fota_ctx->comp_id, &comp_desc);

    ret = fota_platform_start_update_hook(comp_desc->name);
    if (ret) {
        FOTA_TRACE_ERROR("Platform start update hook failed");
        goto fail;
    }

    if (comp_desc->curr_fw_get_digest) {
        comp_desc->curr_fw_get_digest(curr_fw_digest);
    }

    fota_component_get_curr_version(fota_ctx->comp_id, &curr_fw_version);
    FOTA_FI_SAFE_COND(fota_ctx->fw_info->version > curr_fw_version,
                      FOTA_STATUS_MANIFEST_VERSION_REJECTED, "Manifest payload-version rejected - too old");

    prog_size = fota_bd_get_program_size();
    FOTA_ASSERT(prog_size);

    ret = init_header(prog_size);
    if (ret) {
        goto fail;
    }

    // Calculate space for FW image + header
    fw_size_in_storage = fota_align_up(fota_ctx->fw_info->installed_size, prog_size);

    fota_ctx->page_buf_size = prog_size;

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    init_encryption(prog_size, fw_size_in_storage);
#endif

    ret = fota_hash_start(&fota_ctx->curr_fw_hash_ctx);
    if (ret) {
        goto fail;
    }

    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
        if (!comp_desc->support_delta) {
            ret = FOTA_STATUS_MANIFEST_PAYLOAD_UNSUPPORTED;
            goto fail;
        }

        FOTA_FI_SAFE_MEMCMP(curr_fw_digest, fota_ctx->fw_info->precursor_digest, FOTA_CRYPTO_HASH_SIZE,
                            FOTA_STATUS_MANIFEST_PRECURSOR_MISMATCH,
                            "Precursor digest mismatch");

#if !defined(FOTA_DISABLE_DELTA)
        fota_ctx->delta_buf = malloc(MBED_CLOUD_CLIENT_FOTA_DELTA_BLOCK_SIZE);
        if (!fota_ctx->delta_buf) {
            FOTA_TRACE_DEBUG("FOTA delta buffer - allocation failed");
            ret = FOTA_STATUS_OUT_OF_MEMORY;
            goto fail;
        }

        ret = fota_delta_start(&fota_ctx->delta_ctx, comp_desc->curr_fw_read);
        if (ret) {
            goto fail;
        }
        FOTA_TRACE_DEBUG("FOTA delta engine initialized");
#else
        ret = FOTA_STATUS_MANIFEST_PAYLOAD_UNSUPPORTED;
        goto fail;
#endif
    } else {
        // If we have the current fw digest, place it in precursor for the case the installer needs it
        memcpy(fota_ctx->fw_info->precursor_digest, curr_fw_digest, FOTA_CRYPTO_HASH_SIZE);
    }

    ret = fota_bd_init();
    if (ret) {
        FOTA_TRACE_ERROR("Unable to initialize storage");
        ret = FOTA_STATUS_INSUFFICIENT_STORAGE;
        goto fail;
    }
    FOTA_TRACE_DEBUG("FOTA BlockDevice initialized");

    fota_ctx->storage_end_addr = fota_candidate_get_config()->storage_start_addr + fota_ctx->fw_offset_in_storage + fw_size_in_storage;
    fota_ctx->storage_end_addr = fota_align_up(fota_ctx->storage_end_addr, fota_bd_get_erase_size(fota_ctx->storage_end_addr));

    if ((fota_ctx->storage_end_addr - fota_candidate_get_config()->storage_start_addr) > fota_candidate_get_config()->storage_size) {
        FOTA_TRACE_ERROR("Insufficient storage for firmware");
        ret = FOTA_STATUS_INSUFFICIENT_STORAGE;
        goto fail;
    }

    ret = fota_gen_random((uint8_t *) &fota_ctx->auth_token, sizeof(fota_ctx->auth_token));
    if (ret) {
        ret = FOTA_STATUS_INTERNAL_ERROR;
        goto fail;
    }
    fota_ctx->state = FOTA_STATE_AWAIT_DOWNLOAD_AUTHORIZATION;

    fota_source_report_state(FOTA_SOURCE_STATE_AWAITING_DOWNLOAD_APPROVAL, request_download_auth, on_state_set_failure);

    return;

fail:
    if (manifest_save_ret == FOTA_STATUS_SUCCESS) {
        fota_nvm_manifest_delete();
    }
    // Reset buffer received from network and failed authorization/verification
    memset(manifest_buf, 0, manifest_size);
    abort_update(ret, "on manifest event failed");
}

void fota_on_manifest(uint8_t *data, size_t size)
{
    handle_manifest(data, size, /*is_resume*/ false);
}

void fota_on_reject(uint32_t token, int32_t status)
{
    FOTA_ASSERT(fota_ctx);

    FOTA_ASSERT(fota_ctx->auth_token == token);
    FOTA_DBG_ASSERT(
        (fota_ctx->state == FOTA_STATE_AWAIT_DOWNLOAD_AUTHORIZATION) ||
        (fota_ctx->state == FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION)
    );
    fota_ctx->auth_token = 0;
    FOTA_TRACE_ERROR("Application rejected update - reason %" PRId32, status);

    if (fota_ctx->state == FOTA_STATE_AWAIT_DOWNLOAD_AUTHORIZATION) {
        abort_update(FOTA_STATUS_DOWNLOAD_AUTH_NOT_GRANTED, "Download Authorization not granted");
    } else {
        abort_update(FOTA_STATUS_INSTALL_AUTH_NOT_GRANTED, "Install Authorization not granted");
    }
}

void fota_on_defer(uint32_t token, int32_t status)
{
    (void)status;

    if (!fota_ctx) {
        return;  // gracefully ignore this call if update is not running
    }

    FOTA_ASSERT(fota_ctx->auth_token == token);
    fota_ctx->auth_token = 0;
    abort_update(FOTA_STATUS_UPDATE_DEFERRED, "Update deferred by application");
}

static void on_reboot(void)
{
    FOTA_TRACE_INFO("Rebooting.");

    const fota_component_desc_t *comp_desc;
    fota_component_get_desc(fota_ctx->comp_id, &comp_desc);

    // Reason this is here is that platform hook may cut communication with service,
    // so due to reliable report policy, this hook may not be reached.
    fota_platform_finish_update_hook(comp_desc->name);

    update_cleanup();
#ifdef __MBED__
    system_reset();
#endif
}

static int write_candidate_ready(const char *comp_name)
{
    uint8_t *header_buf = malloc(fota_ctx->candidate_header_size);

    memset(header_buf, 0, fota_ctx->candidate_header_size);
    fota_candidate_ready_header_t *header = (fota_candidate_ready_header_t *) header_buf;

    header->magic = FOTA_CANDIDATE_READY_MAGIC;
    strcpy(header->comp_name, comp_name);

    int ret = fota_bd_program(header_buf, fota_candidate_get_config()->storage_start_addr, fota_ctx->candidate_header_size);
    if (ret) {
        ret = FOTA_STATUS_STORAGE_WRITE_FAILED;
        FOTA_TRACE_ERROR("candidate_ready write to storage failed");
    }

    free(header_buf);
    return ret;
}

static void install_component()
{
    unsigned int comp_id = fota_ctx->comp_id;
    const fota_component_desc_t *comp_desc;

#if (FOTA_NUM_COMPONENTS > 1)
    fota_component_version_t new_ver;
    new_ver = fota_ctx->fw_info->version;
#endif

    // At this point we don't need our fota context buffers any more.
    // Free them before installer starts working (to flatten memory allocation curve).
    free_context_buffers();

    fota_component_get_desc(comp_id, &comp_desc);
    FOTA_TRACE_INFO("Installing new version for component %s", comp_desc->name);

    // Code saving - only relevant if we have additional components other than the main one
#if (FOTA_NUM_COMPONENTS > 1)
    // Installer and successful finish actions apply to all components but the main one
    if (comp_id != MAIN_COMP_NUM) {
        // Run the installer using the candidate iterate service
        int ret = fota_candidate_iterate_image(true, (bool) MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT,
                                               comp_desc->name, comp_desc->candidate_iterate_cb);
        if (ret) {
            abort_update(ret, "Failed on component update");
            return;
        }

        // Successful finish actions
        fota_component_set_curr_version(comp_id, new_ver);
        fota_nvm_comp_version_set(comp_desc->name, new_ver);
#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
        fota_nvm_salt_delete();
#endif
        fota_app_on_complete(FOTA_STATUS_SUCCESS); // notify application
    }
#endif // FOTA_NUM_COMPONENTS > 1

    if (comp_desc->need_reboot) {
        fota_source_report_state(FOTA_SOURCE_STATE_REBOOTING, on_reboot, on_reboot);
        return;
    }

    fota_platform_finish_update_hook(comp_desc->name);
    fota_source_report_update_result(FOTA_STATUS_FW_UPDATE_OK);
    fota_source_report_state(FOTA_SOURCE_STATE_IDLE, NULL, NULL);
    update_cleanup();
}

static int prepare_and_program_header()
{
    int ret;
    fota_header_info_t header_info = { 0 };

    uint8_t *header_buf = (uint8_t *) malloc(fota_ctx->fw_header_bd_size);

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    uint32_t metadata_buf_size = 0;
    uint8_t *src_buf = header_buf;
    uint8_t *prog_buf = header_buf;
#endif
    size_t header_buf_actual_size = 0;

    if (!header_buf) {
        ret = FOTA_STATUS_OUT_OF_MEMORY;
        FOTA_TRACE_DEBUG("FOTA scratch buffer - allocation failed");
        goto fail;
    }

    fota_set_header_info_magic(&header_info);
    header_info.fw_size = fota_ctx->fw_info->installed_size;
    header_info.version = fota_ctx->fw_info->version;
    memcpy(header_info.digest, fota_ctx->fw_info->installed_digest, FOTA_CRYPTO_HASH_SIZE);
    memcpy(header_info.precursor, fota_ctx->fw_info->precursor_digest, FOTA_CRYPTO_HASH_SIZE);

    ret = fota_serialize_header(&header_info, header_buf, fota_ctx->fw_header_bd_size, &header_buf_actual_size);
    if (ret) {
        FOTA_TRACE_ERROR("serialize header failed");
        goto fail;
    }

    FOTA_DBG_ASSERT(fota_ctx->fw_header_bd_size >= header_buf_actual_size);

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)

    ret = fota_encrypt_data(fota_ctx->enc_ctx, src_buf, header_buf_actual_size, prog_buf,
                            fota_ctx->metadata_start_buf, FOTA_ENCRYPT_METADATA_MAX_SIZE, &metadata_buf_size);
    if (ret) {
        FOTA_TRACE_ERROR("FW Header encryption failed");
        goto fail;
    }

    ret = handle_metadata_fragment(fota_ctx->metadata_start_buf, metadata_buf_size);
    if (ret) {
        ret = FOTA_STATUS_STORAGE_WRITE_FAILED;
        FOTA_TRACE_ERROR("Metadata write to storage failed");
        goto fail;
    }

    free(fota_ctx->metadata_start_buf);
    fota_ctx->metadata_start_buf = NULL;
#endif

    ret = fota_bd_program(header_buf, fota_ctx->fw_header_offset, fota_ctx->fw_header_bd_size);
    if (ret) {
        ret = FOTA_STATUS_STORAGE_WRITE_FAILED;
        FOTA_TRACE_ERROR("header buf write to storage failed");
    }

fail:
    free(header_buf);
    return ret;
}

void fota_on_authorize(uint32_t token, int32_t status)
{
    int ret;
    (void)status; //unused warning

    FOTA_ASSERT(fota_ctx);

    FOTA_ASSERT(fota_ctx->auth_token == token);
    FOTA_ASSERT(
        (fota_ctx->state == FOTA_STATE_AWAIT_DOWNLOAD_AUTHORIZATION) ||
        (fota_ctx->state == FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION)
    )
    fota_ctx->auth_token = 0;

    if (fota_ctx->state == FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION) {
        const fota_component_desc_t *comp_desc;

        FOTA_TRACE_INFO("Install authorization granted.");

        free(fota_ctx->page_buf);
        fota_ctx->page_buf = NULL;

        fota_component_get_desc(fota_ctx->comp_id, &comp_desc);

#if FOTA_HEADER_HAS_CANDIDATE_READY
        ret = write_candidate_ready(comp_desc->name);
        if (ret) {
            FOTA_TRACE_ERROR("FOTA write_candidate_ready - failed");
            goto fail;
        }
#else
        ret = prepare_and_program_header();
        if (ret) {
            FOTA_TRACE_ERROR("prepare_and_program_header - failed");
            goto fail;
        }
#endif

        fota_nvm_manifest_delete();
        fota_source_report_state(FOTA_SOURCE_STATE_UPDATING, install_component, on_state_set_failure);
        return;
    }

    FOTA_TRACE_INFO("Download authorization granted.");

    // Erase storage
    FOTA_TRACE_DEBUG("Erasing storage at 0x%lx, size %ld",
                     fota_candidate_get_config()->storage_start_addr, fota_ctx->storage_end_addr - fota_candidate_get_config()->storage_start_addr);
    ret = fota_bd_erase(fota_candidate_get_config()->storage_start_addr,
                        fota_ctx->storage_end_addr - fota_candidate_get_config()->storage_start_addr);
    if (ret) {
        FOTA_TRACE_ERROR("Erase storage failed");
        ret = FOTA_STATUS_STORAGE_WRITE_FAILED;
        goto fail;
    }

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    ret = write_initial_metadata();
#endif

    fota_ctx->fw_header_offset = fota_candidate_get_config()->storage_start_addr + fota_ctx->fw_offset_in_storage - fota_ctx->fw_header_bd_size;

    // In non legacy headers we can and should program the FW header already here, as the candidate ready header
    // will be programmed at install phase, telling that the candidate is ready.
#if FOTA_HEADER_HAS_CANDIDATE_READY
    ret = prepare_and_program_header();
    if (ret) {
        goto fail;
    }
#endif

    fota_ctx->page_buf = malloc(fota_ctx->page_buf_size);
    if (!fota_ctx->page_buf) {
        ret = FOTA_STATUS_OUT_OF_MEMORY;
        FOTA_TRACE_DEBUG("FOTA scratch buffer - allocation failed");
        goto fail;
    }

    fota_source_report_state(FOTA_SOURCE_STATE_DOWNLOADING, NULL, NULL);

    ret = fota_source_firmware_request_fragment(fota_ctx->fw_info->uri, fota_ctx->payload_offset);
    if (ret) {
        goto fail;
    }

    return;
fail:
    free(fota_ctx->page_buf);
    fota_ctx->page_buf = NULL;
    FOTA_TRACE_DEBUG("Failed on authorization event. ret code %d", ret);
    abort_update(ret, "Failed on authorization event");
}

static int program_to_storage(uint8_t *buf, uint32_t addr, uint32_t size)
{
    uint32_t prog_size = size;
    uint8_t *src_buf = buf;
    uint8_t *prog_buf = buf;
    int ret;
#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    uint32_t metadata_actual_size;
    uint8_t metadata_buf[FOTA_ENCRYPT_METADATA_MAX_SIZE];

    prog_size = MIN(fota_candidate_get_config()->encrypt_block_size, size);
#endif

    while (size) {

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
        ret = fota_encrypt_data(fota_ctx->enc_ctx, src_buf, prog_size, prog_buf,
                                metadata_buf, FOTA_ENCRYPT_METADATA_MAX_SIZE,
                                &metadata_actual_size);
        if (ret) {
            return FOTA_STATUS_INTERNAL_ERROR;
        }

        ret = handle_metadata_fragment(metadata_buf, metadata_actual_size);
        if (ret) {
            return FOTA_STATUS_INTERNAL_ERROR;
        }
#endif

        ret = fota_bd_program(prog_buf, addr, prog_size);
        if (ret) {
            FOTA_TRACE_ERROR("Write to storage failed, address %" PRIu32 ", size %" PRIu32,
                             addr, size);
            return FOTA_STATUS_STORAGE_WRITE_FAILED;
        }
        src_buf += prog_size;
        addr += prog_size;
        size -= prog_size;
    }
    return FOTA_STATUS_SUCCESS;
}

static int handle_fw_fragment(uint8_t *buf, size_t size, bool last)
{
    uint8_t *source_buf = buf, *prog_buf;
    uint32_t prog_size;
    uint32_t chunk;

    int ret = fota_hash_update(fota_ctx->curr_fw_hash_ctx, buf, size);
    if (ret) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    while (size) {
        if (fota_ctx->page_buf_offset || (size < fota_ctx->page_buf_size)) {
            chunk = MIN(fota_ctx->page_buf_size - fota_ctx->page_buf_offset, size);
            prog_size = fota_ctx->page_buf_offset + chunk;
            prog_buf = fota_ctx->page_buf;
            memcpy(fota_ctx->page_buf + fota_ctx->page_buf_offset, source_buf, chunk);
            fota_ctx->page_buf_offset = (fota_ctx->page_buf_offset + chunk) % fota_ctx->page_buf_size;
            if (last) {
                prog_size = fota_align_up(prog_size, fota_bd_get_program_size());
            }
        } else {
            chunk = fota_align_down(size, fota_ctx->page_buf_size);
            prog_size = chunk;
            prog_buf = source_buf;
        }
        source_buf += chunk;

        if ((prog_size >= fota_ctx->page_buf_size) || last) {
            ret = program_to_storage(prog_buf,
                                     fota_candidate_get_config()->storage_start_addr + fota_ctx->fw_offset_in_storage +
                                     fota_ctx->fw_bytes_written,
                                     prog_size);
            if (ret) {
                return ret;
            }

            fota_ctx->fw_bytes_written += prog_size;
        }
        size -= chunk;
    }
    return FOTA_STATUS_SUCCESS;
}

static void on_approve_state_delivered(void)
{
    FOTA_TRACE_DEBUG("Install Authorization requested");
    int ret = fota_app_on_install_authorization(fota_ctx->auth_token);
    if (ret) {
        abort_update(ret, "Failed to deliver install authorization");
    }
}

static int finalize_update(void)
{
    int ret;
    uint8_t curr_fw_hash_buf[FOTA_CRYPTO_HASH_SIZE];

    ret = fota_hash_result(fota_ctx->curr_fw_hash_ctx, curr_fw_hash_buf);
    if (ret) {
        return ret;
    }

    FOTA_FI_SAFE_MEMCMP(curr_fw_hash_buf, fota_ctx->fw_info->installed_digest, FOTA_CRYPTO_HASH_SIZE,
                        FOTA_STATUS_MANIFEST_PAYLOAD_CORRUPTED,
                        "Downloaded FW hash does not match manifest hash");

#if !defined(FOTA_DISABLE_DELTA)
    ret = fota_delta_finalize(&fota_ctx->delta_ctx);
    if (ret) {
        return ret;
    }
    fota_ctx->delta_ctx = 0;
#endif

    FOTA_TRACE_INFO("Firmware download finished");

    ret = fota_gen_random((uint8_t *) &fota_ctx->auth_token, sizeof(fota_ctx->auth_token));
    if (ret) {
        ret = FOTA_STATUS_INTERNAL_ERROR;
        goto fail;
    }
    fota_ctx->state = FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION;

    fota_source_report_state(FOTA_SOURCE_STATE_AWAITING_APPLICATION_APPROVAL, on_approve_state_delivered, on_state_set_failure);

    return FOTA_STATUS_SUCCESS;

fail:
    abort_update(ret, "Failed on fragment event");
    return ret;

}

void fota_on_fragment_failure(uint32_t token, int32_t status)
{
    FOTA_TRACE_ERROR("Failed to fetch fragment - %" PRId32, status);
    abort_update(FOTA_STATUS_DOWNLOAD_FRAGMENT_FAILED, "Failed to fetch fragment");
}

void fota_on_fragment(uint8_t *buf, size_t size)
{
    int ret = 0;
    bool last_fragment;

    FOTA_ASSERT(fota_ctx);

    uint32_t payload_bytes_left = fota_ctx->fw_info->payload_size - fota_ctx->payload_offset;

    if (size > payload_bytes_left) {
        abort_update(FOTA_STATUS_FW_SIZE_MISMATCH, "Got more bytes than expected");
        return;
    }

    fota_app_on_download_progress(fota_ctx->payload_offset, size, fota_ctx->fw_info->payload_size);

    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
#if !defined(FOTA_DISABLE_DELTA)
        bool finished = false;
        // This loop will have a single iteration in all cases except for the last payload fragment,
        // in which it'll have an additional iteration, where it will draw all firmware fragments
        // that come after the last delta payload fragment.
        do {
            uint32_t actual_frag_size;
            if (payload_bytes_left) {
                ret = fota_delta_new_payload_frag(fota_ctx->delta_ctx, buf, size);
            } else {
                ret = fota_delta_payload_finished(fota_ctx->delta_ctx);
                size = 0;
                finished = true;
            }
            if (ret) {
                goto fail;
            }
            do {
                ret = fota_delta_get_next_fw_frag(fota_ctx->delta_ctx,
                                                  fota_ctx->delta_buf,
                                                  MBED_CLOUD_CLIENT_FOTA_DELTA_BLOCK_SIZE,
                                                  &actual_frag_size);
                if (ret) {
                    goto fail;
                }
                if (actual_frag_size) {
                    last_fragment = ((fota_ctx->fw_bytes_written + fota_ctx->page_buf_offset + actual_frag_size) == fota_ctx->fw_info->installed_size);
                    ret = handle_fw_fragment(fota_ctx->delta_buf, actual_frag_size, last_fragment);
                    if (ret) {
                        goto fail;
                    }
                }
            } while (actual_frag_size);
            payload_bytes_left -= size;
        } while (!payload_bytes_left && !finished);
#else
        // we should not get here. The error is reported from fota_on_manifest
        FOTA_ASSERT(0);
#endif  // #if !defined(FOTA_DISABLE_DELTA)
    } else {
        last_fragment = ((payload_bytes_left - size) == 0);
        ret = handle_fw_fragment(buf, size, last_fragment);
        if (ret) {
            goto fail;
        }
        payload_bytes_left -= size;
    }

    fota_ctx->payload_offset += size;

    if (!payload_bytes_left) {
#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
        ret = handle_metadata_fragment(0, 0);
        if (ret) {
            goto fail;
        }
#endif
        ret = finalize_update();
        if (ret) {
            goto fail;
        }
        return;
    }

    ret = fota_source_firmware_request_fragment(fota_ctx->fw_info->uri, fota_ctx->payload_offset);
    if (ret) {
        goto fail;
    }

    return;

fail:
    abort_update(ret, "Failed on fragment event");
}


void fota_on_resume(uint8_t *data, size_t size)
{
    (void)data;  // unused
    (void)size;  // unused
    if (fota_ctx) {
        return;  // FOTA is already running - ignore
    }

    size_t manifest_size;
    uint8_t *manifest = malloc(FOTA_MANIFEST_MAX_SIZE);
    FOTA_ASSERT(manifest);
    memset(manifest, 0, FOTA_MANIFEST_MAX_SIZE);

    int ret = fota_nvm_manifest_get(manifest, FOTA_MANIFEST_MAX_SIZE, &manifest_size);
    if (!ret) {
        FOTA_TRACE_INFO("Found manifest - resuming update");
        handle_manifest(manifest, manifest_size, /*is_resume*/ true);
    }

    free(manifest);

    if (ret == FOTA_STATUS_NOT_FOUND) {
        // silently ignore - no update to resume
        return;
    }
    if (ret) {
        FOTA_TRACE_ERROR("failed to load manifest from NVM (ret code %d) - update resume aborted.", ret);
    }
}

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
