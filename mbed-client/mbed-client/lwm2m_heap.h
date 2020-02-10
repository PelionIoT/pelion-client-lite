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

#ifndef LWM2M_HEAP_H
#define LWM2M_HEAP_H

/*! \file lwm2m_heap.h
 *  \brief Client Lite internal API for abstracting memory management.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/**
 * \brief Allocate memory from heap.
 *
 * \param size Size of memory to be allocated (in bytes).
 *
 * \return Pointer to the allocated memory.
 * \return NULL allocation failed.
 */
void *lwm2m_alloc(size_t size);

/**
 * \brief Allocate `size` amount of memory, copy `size` amount of
 *  bytes from `source` into it.
 *
 * \note The length of the data pointed by source must be at least
 *       `size` bytes.
 *
 * \param source Source data to copy, must not be NULL.
 * \param size Size of memory to be reserved (in bytes).
 *
 * \return Pointer to the allocated memory.
 * \return NULL allocation failed.
 */
void *lwm2m_alloc_copy(const void *source, size_t size);

/**
 * \brief Allocate (`size` + 1) amount of memory, copy `size` bytes into
 * it and add zero termination.
 *
 * \param source Source string to copy, may not be NULL.
 * \param size Size of memory to be reserved (in bytes).
 *
 * \return Pointer to the allocated memory.
 * \return NULL allocation failed.
 */
char *lwm2m_alloc_string_copy(const void* source, size_t size);

/**
 * \brief Free memory allocated from heap.
 *
 * \note The value given to this function MUST originate from
 *       `lwm2m_alloc`, `lwm2m_alloc_copy` or `lwm2m_alloc_string_copy`
 *       unless it is NULL.
 *
 * \param data Heap allocation to be deallocated or NULL.
 */
void lwm2m_free(void * data);

/**
 * \brief Reallocate the given allocation to size.
 *
 * \note The value given to this function must originate from
 *       `lwm2m_alloc`, `lwm2m_alloc_copy` or `lwm2m_alloc_string_copy`
 *       unless it is NULL.
 *
 * \note If NULL is returned nothing has been done and the `p` is
 *       still a valid heap allocation and may need to be
 *       deallocated using `lwm2m_free`.
 *
 * \param p Previous heap allocation or NULL.
 * \param size New size to allocate.
 *
 * \return Pointer to the reallocated memory, pointer `p` is now invalid.
 * \return NULL reallocation failed, pointer `p` still valid.
 */
void *lwm2m_realloc(void *p, size_t size);

#ifdef __cplusplus
}
#endif

#endif //LWM2M_HEAP_H
