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

#ifndef PROTOMAN_H
#define PROTOMAN_H

/** \defgroup protoman A Protocol Manager.
 * Protocol Manager is a software library written in C that is used to stack protocol layers on top of each other to create a connection.
 *
 * Layer stacking is done in a modular way where the only limitation is that the IO operation types must match between layers.
 * \image html ProtocolManager.png
 *
 * <h3>Application Usage</h3>
 * First you must create a Protocol Manager instance by calling either protoman_create() or protoman_open(), where former allows you to
 * use statically allocated space for Protocol Manager instance, and first one would use the heap for allocation.
 *
 * Next, you should add your protocol layers with protoman_add_layer(). First layer to add, is naturally the platform
 * specific socket layer.
 *
 * To start, you would call protoman_connect(), which would run all layers to connected state, starting from the bottom.
 *
 * Once connected, protoman_read() and protoman_write() are used to push data through protocol layers.
 *
 * @startuml
 *
 * Init: - protoman_create()
 * Init: - protoman_add_predefined()
 * Config: hostname, port,\ncertificates...
 * Connect: protoman_connect()
 * Connected: protoman_write()
 * Connected: protoman_read()
 * Disconnect: protoman_disconnect()
 * Free: protoman_free()
 *
 * note right of Connect
 *   Until connected,
 *   PROTOMAN_WOULDBLOCK
 *   is returned on read/write.
 * end note
 *
 * [*] --> Init
 * Init --> Config
 * Config --> Connect
 * Connect --> Connected
 * Connected --> Disconnect
 * Disconnect --> Disconnected
 * Disconnected --> Connect
 * Disconnected --> Free
 * Free --> [*]
 *
 * @enduml
 *
 * <h3>Protoman Layers</h3>
 *
 * Layer structure is the functional part of Protoman that are effectively appended together to form a complete
 * stack of protocols. Layers are stacked from bottom to top, where layer that is added first with protoman_add_layer() is
 * the bottom one. Bottom layer is usually the platform specific socket layer. Each layer added, will operate on a payload
 * of previously added layer. One the API the term *next layer* refers towards the bottom.
 *
 * Protoman Layer API is also the porting API where you can extend the functionality, or provide platform
 * specific Socket implementations.
 * Eventually the data will flow out to a platform specific network socket.
 * Mbed OS specific Socket layer is given, but protoman allows writing the socket layer for any operating system that
 * provides socket like interface.
 *
 * See \ref protoman_layer.h For further details.
 *
 * <h3>Examples</h3>
 * <h4>Writing data to the stack</h4>
 * Data is written and read from the mbed-protocol-manager with the help of protoman_io_header_s struct.
 * The header defines the type of data is being sent and after recognizing the data type in the layer,
 * the data can be casted to correct type inside the layer.
 *
 * Bytes are written by filling a predefined protoman_io_bytes_s structure:
 * \code
 * struct protoman_io_bytes_s bytes_msg;
 * bytes_msg.header.type = PROTOMAN_IO_BYTES;
 * bytes_msg.buf = "example data";
 * bytes_msg.len = 13;
 *
 * protoman_write(stack1, (struct protoman_io_header_s*)&bytes_msg);
 * \endcode
 *
 * To send CoAP you need to fill a CoAP header struct and for that you need to include the protoman_layer_coap.h:
 * \code
 * #include <protoman_layer_coap.h>
 *
 * struct protoman_io_coap_s coap_msg;
 * sn_coap_hdr_s coap_hdr;
 * // fill coap_hdr with application data
 * coap_msg.header.type = PROTOMAN_IO_COAP;
 * coap_msg.coap_header = &coap_hdr;
 *
 * protoman_write(stack1, (struct protoman_io_header_s*)&coap_msg);
 * \endcode
 *
 * <h4>Reading data from the stack</h4>
 * Reading data is similar to writing data and is done by sending an IO message struct to the mbed-protocol-manager
 *
 * \code
 * struct protoman_io_bytes_s bytes_msg;
 * bytes_msg.header.type = PROTOMAN_IO_BYTES;
 * bytes_msg.len = 13;
 * bytes_msg.buf = malloc(coap_msg.len);
 *
 * protoman_read(stack1, (struct protoman_io_header_s*)&bytes_msg);
 *
 * printf("First byte of read data is 0x%x\n", bytes_msg.buf[0]);
 * \endcode
 *
 */

/** \file protoman.h
 * \brief Protocol manager header file.
 * \ingroup protoman
 * \sa protoman
 */

#include "mbed-protocol-manager/protoman_config.h"

#include "lwm2m_heap.h"
#include "mbed-protocol-manager/protoman_layer.h"
#include "mbed-protocol-manager/protoman_layer_null.h"
#include "mbed-protocol-manager/protoman_layer_drop.h"
#include "mbed-protocol-manager/protoman_layer_print.h"
#include "mbed-protocol-manager/protoman_layer_buffer.h"
#include "mbed-protocol-manager/protoman_layer_counter.h"
#include "mbed-protocol-manager/protoman_layer_frame_lv.h"
#include "mbed-protocol-manager/protoman_layer_packet_split.h"

#include "source/include/protoman_internal.h"
#include "source/include/protoman_error_parser.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/** @name Protoman error codes
 * @{ */
#define PROTOMAN_ERR_NOMEM                     -1
#define PROTOMAN_ERR_WOULDBLOCK                -2
#define PROTOMAN_ERR_WRONG_IO_TYPE             -3
#define PROTOMAN_ERR_POST_CONF                 -4
#define PROTOMAN_ERR_INVALID_INPUT             -5
#define PROTOMAN_ERR_CONNECTION_CLOSED         -6
#define PROTOMAN_ERR_CONNECTION_REFUSED        -7
#define PROTOMAN_ERR_DNS_RESOLVING_FAILED      -8
#define PROTOMAN_ERR_SECURE_CONNECTION_FAILED  -9
#define PROTOMAN_ERR_CERTIFICATE_CHECK_FAILED -10
#define PROTOMAN_ERR_PLATFORM_FAULT           -11
#define PROTOMAN_ERR_INTERNAL_ERROR           -12
#define PROTOMAN_ERR_NETWORK_ERROR            -13
#define PROTOMAN_ERR_TOO_BIG_PACKET           -14
#define PROTOMAN_ERR_NOSOCKET                 -15
#define PROTOMAN_ERR_NOT_IMPLEMENTED          -16
#ifdef PROTOMAN_SANITY
#define PROTOMAN_ERR_SANITY                   -17 /* Used for sanity checks in development phase */
#endif // PROTOMAN_SANITY
/** @} */

/** @name Protoman states.
 *  @{ */
#define PROTOMAN_STATE_INITIALIZING     0 /* must be zero to guarantee initial state after calloc() */
#define PROTOMAN_STATE_INITIALIZED      1
#define PROTOMAN_STATE_CONNECTING       2
#define PROTOMAN_STATE_CONNECTED        3
#define PROTOMAN_STATE_DISCONNECTING    4
#define PROTOMAN_STATE_DISCONNECTED     5
#define PROTOMAN_STATE_ERRORING         6
#define PROTOMAN_STATE_ERRORED          7
#define PROTOMAN_STATE_PAUSING          8
#define PROTOMAN_STATE_PAUSED           9
#define PROTOMAN_STATE_RESUMING        10
#define PROTOMAN_STATE_RESUMED         11
/** @} */


#define PROTOMAN_EVENT_PRIORITY_LOW  0
#define PROTOMAN_EVENT_PRIORITY_MED  1
#define PROTOMAN_EVENT_PRIORITY_HIGH 2

#define PROTOMAN_APPEVENT_DATA_AVAIL   1
#define PROTOMAN_APPEVENT_STATE_CHANGE 2

#define PROTOMAN_MALLOC lwm2m_alloc
#define PROTOMAN_FREE lwm2m_free

#define PROTOMAN_CALLOC(SIZE) (protoman_internal_calloc(1, SIZE))

#ifndef PROTOMAN_MTU
#define PROTOMAN_MTU 1280
#endif

typedef struct protoman_s*       protoman_id_t;
typedef struct protoman_layer_s* protoman_layer_id_t;

typedef void (*protoman_event_cb_t)(protoman_id_t protoman_id, protoman_layer_id_t layer_id, uint8_t event_id, void *event_ctx);

struct protoman_config_s {
    bool is_dgram;
    bool is_client;
    size_t mtu;
};

/** protoman instance */
struct protoman_s {
    int current_state;
    int target_state;
    int8_t tasklet_id;                      /**< Protoman's event handler ID */

    struct protoman_config_s config;
    struct protoman_layer_s *first_error;

    struct protoman_event_storage_s protoman_event_storage;

    NS_LIST_HEAD(struct protoman_layer_s, link) layers; /**< linked list of registered layers */

    protoman_event_cb_t event_cb;
    void *event_ctx;
};

/**
 * Allocates array of memory elements and sets it to 0
 *
 * @param nmemb Amount of elements.
 * @param size Size of the elementi.
 */
void *protoman_internal_calloc(size_t nmemb, size_t size);

/**
 * Creates a new empty Protocol Manager instance.
 *
 * @param event_cb Function pointer to application event handler.
 * @param event_ctx Context pointer that is passed to the event handler.
 * @return Protocol Manager ID if successful or PROTOMAN_ERR_NOMEM if out of memory.
 */
extern protoman_id_t protoman_create(protoman_event_cb_t event_cb, void *event_ctx);

/**
 * Opens a new Protocol Manager instance.
 *
 * @param protoman_id Pointer to protoman_s structure.
 * @param event_cb Function pointer to application event handler.
 * @param event_ctx Context pointer that is passed to the event handler.
 * @return Protocol Manager ID if successful or PROTOMAN_ERR_NOMEM if out of memory.
 */
extern protoman_id_t protoman_open(protoman_id_t protoman_id, protoman_event_cb_t event_cb, void *event_ctx);

/**
 * Retrieves Protocol Manager error code for given layer.
 * @param layer_id The protoman ID.
 * @return 0 if no error or predefined PROTOMAN_ERR_* code.
 */
extern int protoman_get_layer_error(protoman_id_t protoman_id);

/**
 * Retrieves layer component internal error code for given layer.
 * @note As the error code is very specific to the layer implementation,
 *       this error code should not be used for application logic but just
 *       for debugging.
 * @param layer_id The protoman ID.
 * @return 0 if no error or a component specific error code.
 */
extern int protoman_get_layer_error_specific(protoman_id_t protoman_id);

/**
 * Retrieves error string related to the error code.
 * @note This functionality is only enabled when PROTOMAN_VERBOSE flag is defined.
 * @param layer_id The protoman ID.
 * @return Pointer to NULL terminated string describing the error.
 */
extern const char* protoman_get_layer_error_str(protoman_id_t protoman_id);

/**
 * Loops through all Protocol Manager layers to find info with given info_id.
 * @param protoman_id Protocol Manager ID.
 * @param layer_id Specific Layer ID to search the data from. Set to NULL to search from all layers.
 * @param info_id ID identifying searched information.
 * @return Pointer to info data.
 * @return NULL if no matching data is found.
 */
extern void *protoman_get_info(protoman_id_t protoman_id, protoman_layer_id_t layer_id, int info_id);

/**
 * Retrieves a pointer to a configuration struct specific to a given layer and Protocol Manager instance. Protocol Manager configuration struct can be retrieved by setting layer_id to NULL.
 *
 * @param protoman_id Protocol Manager ID.
 * @param layer_id Layer ID.
 * @return A pointer to the configuration struct.
 */
extern void *protoman_get_config(protoman_id_t protoman_id, protoman_layer_id_t layer_id);

/**
 * Reads data from the top-most layer. The application must prepare an IO operation header matching the top-most layer.
 *
 * @param protoman_id Protocol Manager ID.
 * @param operation Pointer to IO operation.l
 * @return Bytes read if successful
 * @return PROTOMAN_ERR_NOMEM in case of not enough memory,
 * @return PROTOMAN_ERR_WOULDBLOCK in case there is no data available
 * @return PROTOMAN_ERR_WRONG_IO if the IO operation type is wrong
 * @return PROTOMAN_ERR_INVALID_INPUT if the input data was badly constructed
 */
extern int protoman_read(protoman_id_t protoman_id, struct protoman_io_header_s *operation);

/**
 * Writes data from the top-most layer. The application must prepare an IO operation header matching the top-most layer.
 *
 * @param protoman_id Protocol Manager ID.
 * @param operation Pointer to IO operation.
 * @return Bytes written
 * @return PROTOMAN_ERR_NOMEM in case of not enough memory
 * @return PROTOMAN_ERR_WOULDBLOCK in case there is no data available
 * @return PROTOMAN_ERR_WRONG_IO if the IO operation type is wrong
 * @return PROTOMAN_ERR_INVALID_INPUT if the input data was badly constructed
 */
extern int protoman_write(protoman_id_t protoman_id, struct protoman_io_header_s *operation);

/**
 * Makes mbed-protocol-manager drive towards connected state.
 *
 * @param protoman_id Protocol Manager ID.
 */
extern void protoman_connect(protoman_id_t protoman_id);

/**
 * Makes mbed-protocol-manager drive towards disconnected state.
 *
 * @param protoman_id Protocol Manager ID.
 */
extern void protoman_disconnect(protoman_id_t protoman_id);

extern void protoman_pause(protoman_id_t protoman_id);
extern void protoman_resume(protoman_id_t protoman_id);


/**
 * Closes Protocol Manager resources and all layers.
 *
 * @param protoman Protocol Manager ID
 */
extern void protoman_close(protoman_id_t protoman_id);

/**
 * Frees Protocol Manager resources and all layers.
 *
 * @param protoman Protocol Manager ID
 */
extern void protoman_free(protoman_id_t protoman_id);

/**
 * Retrieves the state of the given Protocol Manager ID.
 *
 * @param protoman_id Protocol Manager ID.
 * @return State of the Protocol Manager.
 */
extern uint8_t protoman_get_state(protoman_id_t protoman_id);

/**
 * Add layer to the Protocol Manager stack. Maximum of 255 layers are allowed.
 *
 * @param protoman_id Protocol Manager ID.
 * @param layer Pointer to filled layer structure.
 */
extern void protoman_add_layer(protoman_id_t protoman_id, struct protoman_layer_s *layer);

/** @name Protocol manager events
 *  @{ */
#define PROTOMAN_EVENT_BELONGS_TO_CORE 100 /* This can be freely increased if more space is needed, it is added to the original event */
#define PROTOMAN_EVENT_INITIALIZED       0
#define PROTOMAN_EVENT_RUN               1
#define PROTOMAN_EVENT_DATA_AVAIL        6
#define PROTOMAN_EVENT_DATA_WRITTEN      7
#define PROTOMAN_EVENT_CONNECTED         8
#define PROTOMAN_EVENT_DISCONNECTED      9
#define PROTOMAN_EVENT_ERROR            10
#define PROTOMAN_EVENT_PAUSED           11
#define PROTOMAN_EVENT_RESUMED          12

/**
 * Schedules an event to the stack. If layer is set to NULL, the event is pointed to mbed-protocol-manager.
 * @note Scheduling PROTOMAN_EVENT_RUN twice reschedules the event to the earlier time given.
 * \sa Protocol manager event types
 * @param protoman Pointer to Protocol Manager
 * @param layer Pointer to current layer
 * @param event_type Event type
 * @param priority Event priority. Can be one of the following PROTOMAN_EVENT_PRIORITY_HIGH, PROTOMAN_EVENT_PRIORITY_MED or PROTOMAN_EVENT_PRIORITY_LOW.
 * @param after_ms Delay in milliseconds before event is executed. Maximum value is "int32_max / EVENTOS_EVENT_TIMER_HZ - 512".
 */
void protoman_event(struct protoman_s *protoman, struct protoman_layer_s *layer, uint8_t event_type, int priority, uint32_t after_ms);
/** @} */

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // PROTOMAN_H
