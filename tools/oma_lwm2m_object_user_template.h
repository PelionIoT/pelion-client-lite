/*
 * Copyright (c) 2019 ARM Limited. All rights reserved.
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
#ifndef OMA_LWM2M_OBJECT_USER_TEMPLATE
#define OMA_LWM2M_OBJECT_USER_TEMPLATE

#include "oma_lwm2m_object_defs.h"
#include "lwm2m_registry_meta.h"
#include <inttypes.h>

%%RESDEFS_LIST%%

#define USER_OMA_OBJECTS %%OBJDEFS%%

#endif  // OMA_LWM2M_OBJECT_USER_TEMPLATE
