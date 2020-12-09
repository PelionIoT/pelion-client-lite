/*
 * Copyright (c) 2018 ARM Limited. All rights reserved.
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

#ifndef LWM2M_SEND_QUEUE_H
#define LWM2M_SEND_QUEUE_H

/** \file lwm2m_send_queue.h
 *  \brief Client Lite internal API for managing the internal LwM2M message queue.
 */

#ifdef __cplusplus
extern "C" {
#endif
#include "ns_types.h"
#include "eventOS_event.h"
#include "eventOS_event_timer.h"

/**
 * \brief Used for mapping requests to different components.
 *
 * \note Values do matter in `send_queue_sender_t`, do not make unplanned changes.
 *
 */
typedef enum send_queue_sender_e {

    SEND_QUEUE_NONE = 0, ///< No active sender.
    SEND_QUEUE_NOTIFIER = (1 << 0), ///< `lwm2m_notifier`
    SEND_QUEUE_REQUEST = (1 << 1), ///< `lwm2m_get_req_handler`
    SEND_QUEUE_RESPONSE = (1 << 2), ///< `lwm2m_registry_handler`
    SEND_QUEUE_ENDPOINT = (1 << 3), ///< `lwm2m_endpoint`, registration messages.
    SEND_QUEUE_COAP_PING = (1 << 4), ///< `lwm2m_endpoint`, CoAP ping message.

} send_queue_sender_t;

/**
 *
 *  \brief Client Lite internal structure for maintaining the outgoing message queue.
 */
typedef struct send_queue_s {

    timeout_t *timeout; ///< Used for adding delay to scheduling.

    send_queue_sender_t pending; ///< This field tracks what message types are currently pending for sending.
    uint8_t last_sender; ///< Type of the last message sent, used for scheduling different types in turns.
                            ///< Does not include `SEND_QUEUE_ENDPOINT` as it always gets sent first if requested.
                            ///< `unsigned` instead of `send_queue_sender_t` as we are not using the `SEND_QUEUE_ENDPOINT` with this field.
    bool sending_in_progress; ///< True if message sending is in progress.

} send_queue_t;

/**
 * \brief Initialize send queue module.
 *
 * \note This function must be called before calling other send queue functions.
 *
 * \param send_queue Pointer to the send queue structure to initialize.
 *
 */
void send_queue_init(send_queue_t *send_queue);

/**
 * \brief Stop the send queue module.
 *
 *        The module may be started again by making a new request.
 *
 * \note This function must be called before calling other send queue functions.
 *
 * \param endpoint Pointer to the related endpoint.
 */
void send_queue_stop(struct endpoint_s *endpoint);

/**
 * \brief Request message sending slot from the send queue.
 *
 *        The send queue will later call the predefined function of the module
 *        when the message can be sent.
 *
 * \note When the request is done in the module, it must call `send_queue_sent`.
 * \note `send_queue_sent` must be called even if the request fails.
 *
 * \param endpoint Pointer to the related endpoint.
 * \param sender Identifies the module that is making the request.
 */
void send_queue_request(struct endpoint_s *endpoint, const send_queue_sender_t sender);

/**
 * \brief This function must be called after the sending operation requested from
 *        the send queue is done.
 *
 * \param endpoint Pointer to the related endpoint.
 * \param confirmable `true` if the sent message has been acknowledged.
 */
void send_queue_sent(struct endpoint_s *endpoint, const bool confirmable);


#ifdef __cplusplus
}
#endif

#endif //LWM2M_SEND_QUEUE_H
