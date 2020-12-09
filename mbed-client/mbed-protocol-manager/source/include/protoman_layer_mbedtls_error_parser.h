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

#ifndef PROTOMAN_LAYER_MBEDTLS_ERROR_PARSER_H
#define PROTOMAN_LAYER_MBEDTLS_ERROR_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifdef PROTOMAN_ERROR_STRING
extern const char *protoman_strmbedtls_handshake(int state);
extern const char *protoman_strmbedtls(int errcode);
#else
// if the error tracing is not needed, replace the functions with
// inlined versions, which will remove the function call overhead.
static inline const char *protoman_strmbedtls_handshake(int state)
{
    (void)state;
    return "?";
}

static inline const char *protoman_strmbedtls(int errcode)
{
    (void)errcode;
    return "?";
}
#endif

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // PROTOMAN_LAYER_MBEDTLS_ERROR_PARSER_H
