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

#include "mbed-protocol-manager/protoman.h"
#include "mbed-protocol-manager/protoman_config.h"

const char *protoman_strstate(int state_id)
{
#ifndef PROTOMAN_ERROR_STRING
    return "?";
#else
    switch (state_id) {
        case PROTOMAN_STATE_INITIALIZING:
            return "PROTOMAN_STATE_INITIALIZING";
        case PROTOMAN_STATE_INITIALIZED:
            return "PROTOMAN_STATE_INITIALIZED";
        case PROTOMAN_STATE_CONNECTING:
            return "PROTOMAN_STATE_CONNECTING";
        case PROTOMAN_STATE_CONNECTED:
            return "PROTOMAN_STATE_CONNECTED";
        case PROTOMAN_STATE_DISCONNECTING:
            return "PROTOMAN_STATE_DISCONNECTING";
        case PROTOMAN_STATE_DISCONNECTED:
            return "PROTOMAN_STATE_DISCONNECTED";
        case PROTOMAN_STATE_ERRORING:
            return "PROTOMAN_STATE_ERRORING";
        case PROTOMAN_STATE_ERRORED:
            return "PROTOMAN_STATE_ERRORED";
        case PROTOMAN_STATE_PAUSING:
            return "PROTOMAN_STATE_PAUSING";
        case PROTOMAN_STATE_PAUSED:
            return "PROTOMAN_STATE_PAUSED";
        case PROTOMAN_STATE_RESUMING:
            return "PROTOMAN_STATE_RESUMING";
        case PROTOMAN_STATE_RESUMED:
            return "PROTOMAN_STATE_RESUMED";
        default:
            return "UNKNOWN";
    }
#endif // PROTOMAN_ERROR_STRING
}

const char *protoman_strinfo(int info_id)
{
#ifndef PROTOMAN_ERROR_STRING
    return "?";
#else
    switch (info_id) {
        case PROTOMAN_INFO_IP_STR:
            return "PROTOMAN_INFO_IP_STR";
        case PROTOMAN_INFO_IP_BYTES:
            return "PROTOMAN_INFO_IP_BYTES";
        case PROTOMAN_INFO_IP_LEN:
            return "PROTOMAN_INFO_IP_LEN";
        case PROTOMAN_INFO_HOSTNAME:
            return "PROTOMAN_INFO_HOSTNAME";
        case PROTOMAN_INFO_PORT:
            return "PROTOMAN_INFO_PORT";
        case PROTOMAN_INFO_BAUDRATE:
            return "PROTOMAN_INFO_BAUDRATE";
        default:
            return "UNKNOWN";
    }
#endif // PROTOMAN_ERROR_STRING
}

const char *protoman_strstateretval(int state_retval)
{
#ifndef PROTOMAN_ERROR_STRING
    return "?";
#else
    switch (state_retval) {
        case PROTOMAN_STATE_RETVAL_FINISHED:
            return "PROTOMAN_STATE_RETVAL_FINISHED";
        case PROTOMAN_STATE_RETVAL_AGAIN:
            return "PROTOMAN_STATE_RETVAL_AGAIN";
        case PROTOMAN_STATE_RETVAL_WAIT:
            return "PROTOMAN_STATE_RETVAL_WAIT";
        case PROTOMAN_STATE_RETVAL_ERROR:
            return "PROTOMAN_STATE_RETVAL_ERROR";
        default:
            return "UNKNOWN";
    }
#endif // PROTOMAN_ERROR_STRING
}

const char *protoman_strerror(int err_code)
{
#ifndef PROTOMAN_ERROR_STRING
    return "?";
#else
    switch (err_code) {
        case PROTOMAN_ERR_NOMEM:
            return "PROTOMAN_ERR_NOMEM";
        case PROTOMAN_ERR_WOULDBLOCK:
            return "PROTOMAN_ERR_WOULDBLOCK";
        case PROTOMAN_ERR_WRONG_IO_TYPE:
            return "PROTOMAN_ERR_WRONG_IO_TYPE";
        case PROTOMAN_ERR_POST_CONF:
            return "PROTOMAN_ERR_POST_CONF";
        case PROTOMAN_ERR_INVALID_INPUT:
            return "PROTOMAN_ERR_INVALID_INPUT";
        case PROTOMAN_ERR_CONNECTION_CLOSED:
            return "PROTOMAN_ERR_CONNECTION_CLOSED";
        case PROTOMAN_ERR_CONNECTION_REFUSED:
            return "PROTOMAN_ERR_CONNECTION_REFUSED";
        case PROTOMAN_ERR_DNS_RESOLVING_FAILED:
            return "PROTOMAN_ERR_DNS_RESOLVING_FAILED";
        case PROTOMAN_ERR_SECURE_CONNECTION_FAILED:
            return "PROTOMAN_ERR_SECURE_CONNECTION_FAILED";
        case PROTOMAN_ERR_NETWORK_ERROR:
            return "PROTOMAN_ERR_NETWORK_ERROR";
        case PROTOMAN_ERR_TOO_BIG_PACKET:
            return "PROTOMAN_ERR_TOO_BIG_PACKET";
        case PROTOMAN_ERR_NOSOCKET:
            return "PROTOMAN_ERR_NOSOCKET";
        case PROTOMAN_ERR_NOT_IMPLEMENTED:
            return "PROTOMAN_ERR_NOT_IMPLEMENTED";
        default:
            return "UNKNOWN";
    }
#endif // PROTOMAN_ERROR_STRING
}

const char *protoman_strevent(uint8_t event_id)
{
#ifndef PROTOMAN_ERROR_STRING
    return "?";
#else
    switch (event_id) {
        case PROTOMAN_EVENT_INITIALIZED:
            return "PROTOMAN_EVENT_INITIALIZED";
        case PROTOMAN_EVENT_RUN:
            return "PROTOMAN_EVENT_RUN";
        case PROTOMAN_EVENT_DATA_AVAIL:
            return "PROTOMAN_EVENT_DATA_AVAIL";
        case PROTOMAN_EVENT_DATA_WRITTEN:
            return "PROTOMAN_EVENT_DATA_WRITTEN";
        case PROTOMAN_EVENT_CONNECTED:
            return "PROTOMAN_EVENT_CONNECTED";
        case PROTOMAN_EVENT_DISCONNECTED:
            return "PROTOMAN_EVENT_DISCONNECTED";
        case PROTOMAN_EVENT_ERROR:
            return "PROTOMAN_EVENT_ERROR";
        case PROTOMAN_EVENT_PAUSED:
            return "PROTOMAN_EVENT_PAUSED";
        case PROTOMAN_EVENT_RESUMED:
            return "PROTOMAN_EVENT_RESUMED";
        default:
            return "UNKNOWN";
    }
#endif // PROTOMAN_ERROR_STRING
}
