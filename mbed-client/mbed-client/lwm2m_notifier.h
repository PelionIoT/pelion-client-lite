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

#ifndef LWM2M_NOTIFIER_H
#define LWM2M_NOTIFIER_H

/*! \file lwm2m_notifier.h
 *  \brief Client Lite internal LwM2M Object registry notifier API.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "lwm2m_registry.h"
#include "ns_types.h"
#include "eventOS_event.h"

#define NOTIFIER_TIME_INFINITE UINT32_MAX

/**
 *  \brief Client Lite LwM2M Object registry notifier main data structure.
 */
typedef struct notifier_s {
    uint16_t message_id; ///< Message ID of the last notification or 0.
    registry_path_t last_notified; ///< Path of the last Resource notified if `message_id` is not 0.

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    // Note: following bools were stored in a bitfields, but it wasted ~64B of ROM while saving only <2 bytes of RAM.
    bool block_notify; ///< Flag set if notification sent using block transfer.
    bool running; ///< Flag set if running.
    bool notify_next; ///< Flag set if notification is requested for next Resource.
#endif
    bool notifying; ///< Flag set when currently notifying.

    struct endpoint_s *endpoint; ///< Pointer to associated endpoint.
    uint32_t notify_option_number; ///< Notification number, 24-bit counter.
#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY
    uint32_t current_time; ///< Counting seconds.
    uint32_t next_event_time; ///< Time of next event, relative to `current_time`.
    uint32_t last_ticks; ///< Number of system ticks from last call.
#endif
} notifier_t;

#ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY

/**
 * \brief Initialize the notifier.
 * \note This is just intializing the structure. You still need to call `notifier_setup()`. In practice. this function is supposed to
 * be called from a constructor. After this, calling `notifier_stop()` is safe.
 *
 * \param notifier Pointer to the notifier.
 * \param endpoint Pointer to the registry to be used with the notifier.
 *
 */
void notifier_init(notifier_t *notifier, struct endpoint_s *endpoint);

/**
 * \brief Complete the setup of the notifier. This will do Resource allocation, so it
 * can fail.
 *
 * \param notifier Pointer to the notifier structure, initialized with `notifier_init()`.
 */
bool notifier_setup(notifier_t *notifier);

/**
 * \brief Start observation to get notifications on Resource changes.
 *
 * \param notifier Pointer to the notifier.
 * \param path Pointer to the registry registry path that will be observed.
 * \param token Pointer to the token of the resource.
 * \param token_len Length of the token.
 * \param content_type Content type to use in response, use `COAP_CT_NONE` to use the default type.
 *
 * \return >= 0, return value is `notify_option_number` for the response.
 * \return < 0, error occurred when trying to set the observation for the Resource.
 */

int32_t notifier_start_observation(notifier_t *notifier, const registry_path_t *path, const uint8_t *token, const uint8_t token_len, const sn_coap_content_format_e content_type);

/**
 * \brief Stop observation and related notifications.
 *
 * \param notifier Pointer to the notifier.
 * \param path Pointer to the registry path that will no longer be observed.
 */
void notifier_stop_observation(notifier_t *notifier, const registry_path_t *path);

/**
 * \brief Tell notifier that notification has been sent.
 * \note This function MUST be called when the notification has been sent or sending has timed out.
 *
 * \param notifier Pointer to the notifier.
 * \param success True if the notification sending was successful, otherwise false.
 * \param path Pointer to the registry path that has been notified.
 */
void notifier_notification_sent(notifier_t *notifier, bool success, const registry_path_t *path);

/**
 * \brief Stop all notifications. After this call, the notifier needs to be initialized before it can be used again.
 * \note Does not remove observations or other data.
 *
 * \param notifier Pointer to the notifier.
 */
void notifier_stop(notifier_t *notifier);

/**
 * \brief Stop sending new notifications. Use `notifier_continue()` to continue notifications.
 *
 * \param notifier Pointer to the notifier.
 */
void notifier_pause(notifier_t *notifier);

/**
 * \brief Clear internal states and continue to send notifications.
 *
 * \param notifier Pointer to the notifier.
 */
void notifier_continue(notifier_t *notifier);

/**
 * \brief Set dirty parameters related to the changed resources.
 *
 * \param registry Pointer to the registry to be used.
 * \param path Pointer to the registry path with the changed value.
 */
void notifier_set_dirty(registry_t *registry, const registry_path_t *path);

/**
 * \brief Inform the notifier that observation parameters have been changed.
 *
 * \param notifier Pointer to the notifier.
 * \param path Pointer to the registry path with the changed parameters.
 */
void notifier_parameters_changed(notifier_t *notifier, const registry_path_t *path);

/**
 * \brief Message queue calls this function when it is ready to send next notification.
 *
 * \param notifier Pointer to the notifier.
 */
void notifier_send_now(notifier_t *notifier);

/**
 * \brief Cancel all notifications, clear observation tokens. This does not change other flags or options.
 *
 * \param notifier Pointer to the notifier.
 */
void notifier_clear_notifications(notifier_t *notifier);

#else // #ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY

int notifier_send_observation_notification(struct endpoint_s *endpoint, uint32_t max_age, uint8_t *token_ptr, uint8_t token_len,
                                            uint8_t *payload_ptr, uint16_t payload_len, sn_coap_content_format_e content_format);

#endif // #ifndef MBED_CLOUD_CLIENT_DISABLE_REGISTRY

#ifdef __cplusplus
}
#endif

#endif //LWM2M_NOTIFIER_H
