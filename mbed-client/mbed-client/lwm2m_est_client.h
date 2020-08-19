/*
 * Copyright (c) 2020 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LWM2M_EST_CLIENT_H
#define LWM2M_EST_CLIENT_H

#include "est_defs.h"


/*! \file lwm2m_est_client.h
 *  \brief Client Lite internal API for sending Certificate Enrollment request.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MBED_CLIENT_DISABLE_EST_FEATURE

/**
 * \brief Request certificate enrollment from the EST service.
 * \param cert_name, The name of certificate to enroll. Null enrolls a LwM2M certificate.
 * \param csr_length, The length of the certificate signing request within csr buffer.
 * \param csr, A buffer containing the certificate signing request.
 * \param result_cb, The callback function that is called when EST enrollment has completed.
 * \param context, The user context that is passed to the result_cb callback.
 */
est_status_e est_request_enrollment(const char *cert_name,
                                    uint8_t *csr,
                                    const size_t csr_length,
                                    est_enrollment_result_cb result_cb,
                                    void *context);

/**
 * \brief Release memory allocated for the certificate request.
 * \param context Certificate chain context, received by result callback.
 */
void est_free_context(struct cert_chain_context_s *context);

#else // MBED_CLIENT_DISABLE_EST_FEATURE
#define est_request_enrollment(...) EST_STATUS_INVALID_PARAMETERS
#define est_free_context(...) ()
#endif // MBED_CLIENT_DISABLE_EST_FEATURE

#ifdef __cplusplus
}
#endif

#endif // LWM2M_EST_CLIENT_H
