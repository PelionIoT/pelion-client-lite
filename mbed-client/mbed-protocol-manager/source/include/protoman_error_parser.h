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

#ifndef PROTOMAN_ERROR_PARSER_H
#define PROTOMAN_ERROR_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @brief      Converts given state_id to string representation
 *
 * @param[in]  state_id  The state identifier. For example,
 *                       PROTOMAN_STATE_CONNECTED.
 *
 * @return     Pointer to string representation
 */
extern const char *protoman_strstate(int state_id);

/**
 * @brief      Converts given info_id to string representation
 *
 * @param[in]  info_id  The info request identifier. For example,
 *                      PROTOMAN_INFO_HOSTNAME.
 *
 * @return     Pointer to string representation
 */
extern const char *protoman_strinfo(int info_id);

/**
 * @brief      Converts given state_retval to string representation
 *
 * @param[in]  state_retval  The predefined state function return value. For
 *                           example, PROTOMAN_STATE_RETVAL_AGAIN
 *
 * @return     Pointer to string representation
 */
extern const char *protoman_strstateretval(int state_retval);

/**
 * @brief      Converts given error code to string representation
 *
 * @param[in]  err_code  The error code. For example, PROTOMAN_ERR_NOMEM
 *
 * @return     Pointer to string representation
 */
extern const char *protoman_strerror(int err_code);

/**
 * @brief      Converts given event_id to string representation
 *
 * @param[in]  event_id  The event identifier. For example,
 *                       PROTOMAN_EVENT_CONNECTED.
 *
 * @return     Pointer to string representation
 */
extern const char *protoman_strevent(uint8_t event_id);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // PROTOMAN_ERROR_PARSER_H
