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

#ifndef PROTOMAN_LAYER_PRINT_H
#define PROTOMAN_LAYER_PRINT_H

#include "stdlib.h"
#include "mbed-protocol-manager/protoman.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

struct protoman_layer_print_s {
    struct protoman_layer_s layer; /* must be first entry */
};

extern void protoman_add_layer_print(struct protoman_s *protoman, struct protoman_layer_s *layer);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // PROTOMAN_LAYER_PRINT_H
