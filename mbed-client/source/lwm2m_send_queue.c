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

#include "lwm2m_endpoint.h"
#include "lwm2m_notifier.h"
#include "lwm2m_registry_handler.h"
#include "lwm2m_req_handler.h"
#include "lwm2m_send_queue.h"
#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP "lwSQ"

#define SEND_QUEUE_DELAY_MS 20
#define SEND_QUEUE_DELAY_NON_CONFIRMABLE_MS 500

static void send_queue_send_next(struct endpoint_s *endpoint);

void send_queue_init(send_queue_t *send_queue)
{
    *send_queue = (send_queue_t){NULL, SEND_QUEUE_NONE, SEND_QUEUE_NOTIFIER, false};
}

void send_queue_stop(struct endpoint_s *endpoint)
{
    send_queue_t *send_queue = &endpoint->send_queue;

    if (send_queue->timeout) {
        eventOS_timeout_cancel(send_queue->timeout);
    }
    *send_queue = (send_queue_t){NULL, SEND_QUEUE_NONE, SEND_QUEUE_NOTIFIER, false};
}

void send_queue_request(struct endpoint_s *endpoint, const send_queue_sender_t sender)
{

    send_queue_t *send_queue = &endpoint->send_queue;

    tr_debug("send_queue_request() %d", sender);

    send_queue->pending |= sender;

    if (!send_queue->sending_in_progress) {
        send_queue_send_next(endpoint);
    }

}

static void timed_send_next(void *endpoint)
{
    ((struct endpoint_s *)endpoint)->send_queue.timeout = NULL;
    send_queue_send_next(endpoint);
}

void send_queue_sent(struct endpoint_s *endpoint, const bool confirmable)
{

    int delay = SEND_QUEUE_DELAY_MS;

    if (!confirmable) {
        delay = SEND_QUEUE_DELAY_NON_CONFIRMABLE_MS;
    }

    endpoint->send_queue.timeout = eventOS_timeout_ms(&timed_send_next, delay, endpoint);

    if (endpoint->send_queue.timeout) {
        tr_debug("send_queue_sent() use %d ms delay", delay);
        return;
    }
    tr_warn("send_queue_sent() eventOS_timeout_ms() failed, calling send_queue_send_next()");

    send_queue_send_next(endpoint);
}

static send_queue_sender_t send_queue_next_sender(struct endpoint_s *endpoint)
{
    send_queue_t *send_queue = &endpoint->send_queue;
    send_queue_sender_t next_sender;

    // Send endpoint messages first as they are highest priority.

    if (send_queue->pending & SEND_QUEUE_ENDPOINT) {
        return SEND_QUEUE_ENDPOINT;
    }

    if (!endpoint->registered) {
        // Do not send other messages when not registered.
        tr_debug("Skip message sending until registered.");
        return SEND_QUEUE_NONE;
    }

    // Schedule other types is turns.

    next_sender = send_queue->last_sender;

    do {

        next_sender <<= 1;

        if (next_sender == SEND_QUEUE_ENDPOINT) {
            next_sender = SEND_QUEUE_NOTIFIER;
        }

        if (send_queue->pending & next_sender) {
            send_queue->last_sender = next_sender;
            return next_sender;
        }


    } while (next_sender != send_queue->last_sender);

    if (send_queue->pending & SEND_QUEUE_COAP_PING) {
        return SEND_QUEUE_COAP_PING;
    }

    return SEND_QUEUE_NONE;

}

void send_queue_send_next(struct endpoint_s *endpoint)
{
    send_queue_sender_t next_sender;
    send_queue_t *send_queue = &endpoint->send_queue;

    send_queue->sending_in_progress = true;

    next_sender = send_queue_next_sender(endpoint);

    send_queue->pending &= ~next_sender;

    switch (next_sender) {

        case SEND_QUEUE_ENDPOINT:
            tr_debug("send_queue_send_next() endpoint");
            endpoint_send_message(endpoint);
            break;

        case SEND_QUEUE_RESPONSE:
            tr_debug("send_queue_send_next() response");
            response_message_send(endpoint);
            break;

        case SEND_QUEUE_NOTIFIER:
            tr_debug("send_queue_send_next() notifier");
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
            notifier_send_now(&endpoint->notifier);
#endif
            break;

        case SEND_QUEUE_REQUEST:
            tr_debug("send_queue_send_next() get");
            req_handler_send_message(endpoint);
            break;

        case SEND_QUEUE_COAP_PING:
#if defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP) || defined(MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE)
            tr_debug("send_queue_send_next() CoAP Ping");
            endpoint_send_coap_ping(endpoint);
#endif
            break;

        case SEND_QUEUE_NONE:
            tr_debug("send_queue_send_next() nothing to send.");
            send_queue->sending_in_progress = false;
            break;

    }

}
