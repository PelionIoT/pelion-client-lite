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

#ifndef PROTOMAN_LAYER_COAP_H
#define PROTOMAN_LAYER_COAP_H

#include "stdlib.h"

#include "mbed-coap/sn_coap_header.h"
#include "mbed-coap/sn_coap_protocol.h"

#include "mbed-protocol-manager/protoman.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define PROTOMAN_IO_COAP 127

struct protoman_io_coap_s {
    struct protoman_io_header_s header; /* Must be first as protoman_io_bytes_s will be casted to protoman_io_header_s */
    sn_coap_hdr_s *coap_header;
};

struct protoman_layer_coap_s {
    struct protoman_layer_s layer; /* must be first element */
    struct coap_s *coap;
    uint32_t coap_time; /* TODO: this timer needs complete overhaul */
    uint8_t coap_time_interval; /* TODO: this timer needs complete overhaul */
    sn_coap_hdr_s *rx_coap_hdr;
    sn_coap_hdr_s *resend_coap_hdr;
    sn_nsdl_addr_s dummy_addr;
};

void protoman_add_layer_coap(struct protoman_s *protoman, struct protoman_layer_s *layer);

sn_coap_options_list_s *protoman_coap_alloc_options(protoman_layer_id_t id, sn_coap_hdr_s *header);
void protoman_coap_free_msg_mem(protoman_layer_id_t id, sn_coap_hdr_s *header);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // PROTOMAN_LAYER_COAP_H
