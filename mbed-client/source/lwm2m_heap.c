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

#include "lwm2m_heap.h"

#include <stdlib.h>
#include <string.h> // memcpy

void *lwm2m_alloc(size_t size)
{
    if (!size) {
        return NULL;// CoAP library seems to expect this.
    }
    return malloc(size);
}

void *lwm2m_alloc_copy(const void *source, size_t size)
{
    void *result = lwm2m_alloc(size);

    if (result) {
        memcpy(result, source, size);
    }

    return result;
}

char *lwm2m_alloc_string_copy(const void *source, size_t size)
{
    char *result = lwm2m_alloc(size + 1);

    if (result) {
        memcpy(result, source, size);
        result[size] = 0;
    }
    return result;
}

void lwm2m_free(void *data)
{
    free(data);
}

void *lwm2m_realloc(void *p, size_t size)
{
    return realloc(p, size);
}
