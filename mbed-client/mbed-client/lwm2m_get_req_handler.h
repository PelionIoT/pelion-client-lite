/*
 * Copyright (c) 2017 ARM Limited. All rights reserved.
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
#ifndef LWM2M_GET_REQ_HANDLER_H
#define LWM2M_GET_REQ_HANDLER_H

#include "lwm2m_endpoint.h"
#include "lwm2m_constants.h"
#include "ns_list.h"
#include "sn_coap_header.h"

#include <stdint.h>

/*! \file lwm2m_get_req_handler.h
 *  \brief Client Lite internal API for executing direct CoAP GET requests.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Destroy all the allocated data.
 *
 */
void get_handler_destroy(void);

/**
 * \brief Send the Constrained Application Protocol (CoAP) GET request to the server.
 *
 * \param endpoint Endpoint info.
 * \param type Download type.
 * \param uri URI path to the data.
 * \param offset Data offset.
 * \param async In async mode, the application must call this API again with the updated offset.
 *        If set to false, client will automatically download the whole package.
 * \param data_cb Callback triggered once there is data available.
 * \param error_cb Callback trigged in case of any error.
 * \param context Application context.
 *
*/
void get_handler_send_get_data_request(endpoint_t *endpoint,
                                       DownloadType type,
                                       const char *uri,
                                       const size_t offset,
                                       const bool async,
                                       get_data_cb data_cb,
                                       get_data_error_cb error_cb,
                                       void *context);

/**
 * \brief This function is called by the send queue to send a pending request.
 * \note This function must not be called from any other module than `lwm2m_send_queue`.
 *
 * \param endpoint Endpoint info.
*/

void get_handler_send_message(endpoint_t *endpoint);

/**
 * \brief Handle GET response.
 *
 * \param endpoint Endpoint info.
 * \param coap_header Incoming CoAP data.
 *
 * \return True if response matches with the GET request, otherwise False.
*/
bool get_handler_handle_response(endpoint_t *endpoint, const sn_coap_hdr_s *coap_header);

/**
 * \brief Mark all existing GET requests to be re-sent.
 *
*/
void get_handler_set_resend_status(void);

/**
 * \brief Send all requests that have retry flag set to true.
 *
 * \param endpoint Endpoint info.
*/
void get_handler_send_pending_request(endpoint_t *endpoint);

/**
 * \brief Remove all pending GET requests.
 *
 * \param coap_header Incoming CoAP data or NULL.
 * \param call_error_cb If true, the error callback is called.
 * \param error_code Error code to be passed to the error callback.
*/
void get_handler_free_get_request_list(const sn_coap_hdr_s *coap_header, bool call_error_cb, get_data_req_error_t error_code);

#ifdef __cplusplus
}
#endif

#endif //LWM2M_GET_REQ_HANDLER_H
