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

#ifndef SINGLY_LINKED_LIST_H
#define SINGLY_LINKED_LIST_H

typedef void* sll_t;

#define sll_init(list) list = NULL

#define sll_add(list, entry) \
        do{void *next; next = list; *(void**)entry = next; list = entry;}while(0)

#define sll_foreach(list,i,p) \
        for(p = &list, i = list; i; p = i, i = *(void**)i)

#define sll_get_next(i,p) \
        do{p = i; i = *(void**)i;}while(0)

#define sll_remove_current(list,i,p) \
        do{if(p == &list){list = *(void**)i;i = (void*)&list;} \
        else{*(void**)p = *(void**)i; i = p;}}while(0)

#endif //SINGLY_LINKED_LIST_H

