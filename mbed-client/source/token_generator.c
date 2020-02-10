/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
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
#include <string.h>
#include "randLIB.h"
#include "token_generator.h"
#include "lwm2m_heap.h"
#include "mbed-coap/sn_config.h"
#include "mbed_trace.h"

#define TRACE_GROUP "tokn"

#ifndef MAX_STORED_TOKENS
#define MAX_STORED_TOKENS 2
#endif


static bool is_token_reserved(uint32_t token);

static uint8_t next_token_index = 0;
static uint32_t stored_tokens[MAX_STORED_TOKENS] = {0};

uint32_t generate_token(void)
{
    uint32_t token;

    // Randomize the new token, do until we get unique token
    do {
        token = randLIB_get_32bit();
        if (token == 0) {
            token++;
        }
    } while (is_token_reserved(token));

    stored_tokens[next_token_index] = token;

    if (++next_token_index == MAX_STORED_TOKENS) {
        next_token_index = 0;
    }

    return token;
}

static bool is_token_reserved(uint32_t token)
{
    for (int i = 0; i < MAX_STORED_TOKENS; i++) {
        if (token == stored_tokens[i]) {
            return true;
        }
    }
    return false;
}
