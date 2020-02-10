/*
 * Copyright (c) 2017 - 2018 ARM Limited. All rights reserved.
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

#ifndef LWM2M_REGISTRY_HANDLER_H
#define LWM2M_REGISTRY_HANDLER_H

#include "lwm2m_registry.h"
#include "lwm2m_endpoint.h"

#include "ns_list.h"
#include "ns_types.h"
#include "sn_coap_header.h"
#include "sn_coap_protocol.h"
#include "sn_coap_protocol_internal.h"
#include "lwm2m_registry.h"
#include "lwm2m_endpoint.h"

#include <stdint.h>

/** \file lwm2m_registry_handler.h
 *  \brief Client Lite internal API for handling LwM2M Object registry requests.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Handle Constrained Application Protocol (CoAP) request from the server.
 *
 * \param endpoint Pointer to related endpoint.
 * \param received_coap_header Pointer to CoAP data from the CoAP library.
 * \param address Pointer to source address.
 */
void handle_coap_request(endpoint_t *endpoint,
                         sn_coap_hdr_s *received_coap_header,
                         sn_nsdl_addr_s *address);

/**
 * \brief Handle Constrained Application Protocol (CoAP) response from the server.
 *
 * \param endpoint Pointer to related endpoint.
 * \param received_coap_header Pointer to CoAP data from the CoAP library.
 */
bool handle_coap_response(endpoint_t *endpoint, sn_coap_hdr_s *received_coap_header);

/**
 * \brief Send a response to a execute request.
 *
 * \param path Pointer to resource path.
 * \param endpoint Pointer to related endpoint.
 * \param token Token of the request.
 * \param token_length Length of the token.
 * \param msg_code Message code to use in the response.
 * \param notify_result Provide result of sending the response as callback.
 */
void send_final_response(const registry_path_t *path,
                           endpoint_t *endpoint,
                           const uint8_t *token,
                           const uint8_t token_length,
                           const sn_coap_msg_code_e msg_code,
                           const bool notify_result);

/**
 * TODO: Remove this API. Deprecated.
 */
void send_execute_response(const registry_path_t *path,
                           endpoint_t *endpoint,
                           const uint8_t *token,
                           const uint8_t token_length,
                           const sn_coap_msg_code_e msg_code);

/**
 * \brief Event queue calls this function when a time slot is available for sending.
 *
 * \param endpoint Pointer to related endpoint.
 */
void response_message_send(endpoint_t *endpoint);

#ifdef __cplusplus
}
#endif
#endif // LWM2M_REGISTRY_HANDLER_H
