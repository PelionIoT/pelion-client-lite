// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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

#include "update-client-common/arm_uc_crypto.h"
#if defined(ARM_UC_FEATURE_CERT_STORE_KVSTORE) && (ARM_UC_FEATURE_CERT_STORE_KVSTORE == 1)

#include "update-client-control-center/arm_uc_certificate.h"
#include "update-client-common/arm_uc_config.h"
#include "update-client-metadata-header/arm_uc_buffer_utilities.h"
#include "CloudClientStorage.h"

static arm_uc_error_t cerr2ucerr(int cerr)
{
    arm_uc_error_t err;
    switch (cerr) {
        case CCS_STATUS_SUCCESS:
            err.code = ERR_NONE;
            break;
        case CCS_STATUS_KEY_DOESNT_EXIST:
            err.code = ARM_UC_CM_ERR_NOT_FOUND;
            break;
        case CCS_STATUS_VALIDATION_FAIL:
            err.code = ARM_UC_CM_ERR_INVALID_CERT;
            break;
        case CCS_STATUS_MEMORY_ERROR:
        case CCS_STATUS_ERROR:
        default:
            err.modulecc[0] = 'C';
            err.modulecc[1] = 'C';
            err.error       = cerr;
            break;
    }
    return err;
}

static arm_uc_error_t arm_uc_kvstore_cert_fetcher(arm_uc_buffer_t *certificate,
                                                 const arm_uc_buffer_t *fingerprint,
                                                 const arm_uc_buffer_t *DERCertificateList,
                                                 void (*callback)(arm_uc_error_t, const arm_uc_buffer_t *, const arm_uc_buffer_t *))
{
    // Format the certificate name into the certName buffer
    // ARM_UC_Base64Enc(b64hash, sizeof(b64hash), fingerprint);

    // The arm_uc_buffer_t's size variable is 32bit, but kcm_item_get_data() needs
    // a pointer to size_t, so we need to use a temp variable for it or we would get
    // a corrupted arm_uc_buffer_t structure.
    size_t cert_data_size = 0;

    ccs_status_e ccs_status = get_config_parameter(UPDATE_CERTIFICATE,
                                                   certificate->ptr,
                                                   certificate->size_max,
                                                   &cert_data_size);


    arm_uc_error_t err = cerr2ucerr(ccs_status);
    UC_CONT_TRACE("get_config_parameter ccs_status:%u err:%u", ccs_status, err);
    arm_uc_error_t errFinish = {ARM_UC_CM_ERR_INVALID_PARAMETER};

    // Prepare to calculate the fingerprint of the certificate.
    arm_uc_mdHandle_t h = { 0 };
    uint8_t fingerprintLocal[MBED_CLOUD_SHA256_BYTES];
    arm_uc_buffer_t fingerprintLocalBuffer = {
        .size_max = sizeof(fingerprintLocal),
        .size = 0,
        .ptr = fingerprintLocal
    };

    // Check for overflow before continuing. This is actually unnecessary
    // belts and suspenders type of code, as the max value given to kcm_item_get_data()
    // is at most UINT32_MAX, but the Coverity might point this as a error.
    if (cert_data_size <= UINT32_MAX) {
        certificate->size = (uint32_t)cert_data_size;
    } else {
        err.code = ARM_UC_CM_ERR_INVALID_CERT;
    }

    // Calculate the fingerprint of the certificate
    if (err.error == ERR_NONE) {
        err = ARM_UC_cryptoHashSetup(&h, ARM_UC_CU_SHA256);
    }
    if (err.error == ERR_NONE) {
        err = ARM_UC_cryptoHashUpdate(&h, certificate);

        // The cryptoHashFinish needs to be called no matter if the update succeeded or not as
        // it will do memory freeing. But in order to have valid result, the update & finish
        // must both have succeeded.
        errFinish = ARM_UC_cryptoHashFinish(&h, &fingerprintLocalBuffer);

        // Compare the calculated fingerprint to the requested fingerprint.
        if ((err.error == ERR_NONE) && (errFinish.error == ERR_NONE)) {
            uint32_t rc = ARM_UC_BinCompareCT(fingerprint, &fingerprintLocalBuffer);
            if (rc) {
                err.code = ARM_UC_CM_ERR_NOT_FOUND;
            } else {
                UC_CONT_TRACE("Certificate lookup fingerprint matched.");
                err.code = ERR_NONE;
            }

            if (callback && (err.error == ERR_NONE)) {
                callback(err, certificate, fingerprint);
            }
        }
    }

    return err;
}

static arm_uc_error_t arm_uc_kvstore_cert_storer(const arm_uc_buffer_t *cert,
                                                 const arm_uc_buffer_t *fingerprint,
                                                 void(*callback)(arm_uc_error_t, const arm_uc_buffer_t *))
{
    ccs_status_e ccs_status = set_config_parameter(UPDATE_CERTIFICATE,
                                                   cert->ptr,
                                                   cert->size);

    arm_uc_error_t err = cerr2ucerr(ccs_status);

    if (callback && (err.code == ERR_NONE)) {
        callback(err, fingerprint);
    }

    return err;
}

const struct arm_uc_certificate_api arm_uc_certificate_kvstore_api = {
    .fetch = arm_uc_kvstore_cert_fetcher,
    .store = arm_uc_kvstore_cert_storer
};

#endif /* ARM_UC_FEATURE_CERT_STORE_KVSTORE */
