#/*
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

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#ifndef PROTOMAN_TRACE_H
#define PROTOMAN_TRACE_H

#include "mbed-trace/mbed_trace.h"
#include "protoman_config.h"

/* Appending empty string "" as last argument is required to emulate
 * ##__VA_ARGS__ with __VA_ARGS__ in a portable way for printing */
#ifdef PROTOMAN_VERBOSE
    #define protoman_verbose(...) protoman_tracef(TRACE_LEVEL_DEBUG, __VA_ARGS__, "")
#else
    #define protoman_verbose(...)
#endif
#define protoman_debug(...)   protoman_tracef(TRACE_LEVEL_DEBUG, __VA_ARGS__, "")
#define protoman_warn(...)    protoman_tracef(TRACE_LEVEL_WARN, __VA_ARGS__, "")
#define protoman_info(...)    protoman_tracef(TRACE_LEVEL_INFO, __VA_ARGS__, "")
#define protoman_err(...)     protoman_tracef(TRACE_LEVEL_ERROR, __VA_ARGS__, "")

#ifdef PROTOMAN_VERBOSE_POINTERS
    /* Verbose logs */
    #ifdef PROTOMAN_CORE_FILE
        /* ProtocolManager debug, no layer pointer available */
        #define protoman_tracef(TRACE_LEVEL, format, ...) mbed_tracef(TRACE_LEVEL, TRACE_GROUP, "[p=%p, core]: %s(), " format "%s", protoman, __func__, __VA_ARGS__)
    #else
        /* Layer debug with layer pointer available */
        #define protoman_tracef(TRACE_LEVEL, format, ...) mbed_tracef(TRACE_LEVEL, TRACE_GROUP, "[p=%p, l=%p, %s]: %s(), " format "%s", layer->protoman, layer, layer->name, __func__, __VA_ARGS__)
    #endif
#else
    /* Reduced logs */
    #ifdef PROTOMAN_CORE_FILE
        /* ProtocolManager debug, no layer pointer available */
        #define protoman_tracef(TRACE_LEVEL, format, ...) mbed_tracef(TRACE_LEVEL, TRACE_GROUP, "%s() core, " format "%s", __func__, __VA_ARGS__)
    #else
        /* Layer debug with layer pointer available */
        #define protoman_tracef(TRACE_LEVEL, format, ...) mbed_tracef(TRACE_LEVEL, TRACE_GROUP, "%s(), %s, " format "%s", __func__, layer->name, __VA_ARGS__)
    #endif
#endif

#ifdef __linux__
    #define PROTOMAN_DEBUG_PRINT_ALLOC(LAYER_NAME, LEN, PTR) protoman_verbose("%s(), %s layer, allocated %zd bytes to \"%s\" in %p", __FUNCTION__, LAYER_NAME, LEN, #PTR, PTR)
    #define PROTOMAN_DEBUG_PRINT_FREE(LAYER_NAME, PTR) protoman_verbose("%s(), %s layer, freed %p that was in \"%s\"", __FUNCTION__, LAYER_NAME, PTR, #PTR)
#else
    #define PROTOMAN_DEBUG_PRINT_ALLOC(LAYER_NAME, LEN, PTR)
    #define PROTOMAN_DEBUG_PRINT_FREE(LAYER_NAME, PTR)
#endif

#endif //PROTOMAN_TRACE_H
#ifdef __cplusplus
}
#endif //__cplusplus
