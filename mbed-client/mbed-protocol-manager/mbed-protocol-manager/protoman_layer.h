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

#ifndef PROTOMAN_LAYER_H
#define PROTOMAN_LAYER_H

/**
 * \file protoman_layer.h
 * \ingroup protoman
 * \brief Protocol Manager layer API.
 *
 * In Protocol Manager, you can dynamically append layers on top of each other to
 * create protocol stacks for different purposes. Each layer will operate on
 * the data that the layer below it provides. Usually each layer will either
 * handle one header on a specific protol, or encryption, and provide the payload
 * for upstream layer to process. Each layer is independant and requires no knowledge
 * of layers below, or above them.
 *
 * Layer API is where the Protocol Manager is extended, so it is consideres as a porting API as well.
 * You may provide your own implementation of platform specific socket layer, or provide another protocol
 *
 * Layers are defined by creating \ref protoman_layer_s structure, and registered to Protocol Manager with a call to
 * protoman_add_layer().
 * Each layer implementation is internally an event driven state machine. State transitions and data flow are
 * all a result of Protocol Manager calling one of the defined callback functions from \ref protoman_layer_callbacks_s which
 * is part of the \ref protoman_layer_s structure.
 *
 * <h3>Protocol layer state flow</h3>
 *
 * Each layer added to Protocol Manager instance, will have the same state flow. When you call protoman_connect(), it initiates the
 * state transitions that run all layers to `PROTOMAN_STATE_CONNECTED` state which will allow the data to be pushed through the
 * stack.
 *
 * @startuml
 *      PROTOMAN_STATE_INIT: - All layers are initialzied
 *      PROTOMAN_STATE_INIT: - Starts immediately after layer creation
 *      PROTOMAN_STATE_INIT: - No data is moving
 *      PROTOMAN_STATE_DISCONNECTED: - Layers are initialized but not connected
 *      PROTOMAN_STATE_DISCONNECTED: - No data is moving
 *      PROTOMAN_STATE_CONNECTING: - Layers are connected from bottom to up
 *      PROTOMAN_STATE_CONNECTING: - Data is moving
 *      PROTOMAN_STATE_CONNECTED: - Data is moving
 *      PROTOMAN_STATE_DISCONNECTING: - Layers are disconnected from top to bottom
 *      PROTOMAN_STATE_DISCONNECTING: - Data is moving
 *      PROTOMAN_STATE_ERROR: - A layer is in unrecoverable state
 *      PROTOMAN_STATE_ERROR: - The stack is in unrecoverable state
 *
 *      [*] --> PROTOMAN_STATE_INIT
 *      PROTOMAN_STATE_INIT --> PROTOMAN_STATE_DISCONNECTED: All layers initialized
 *      PROTOMAN_STATE_DISCONNECTED --> PROTOMAN_STATE_CONNECTING: protoman_connect();
 *      PROTOMAN_STATE_CONNECTING --> PROTOMAN_STATE_CONNECTED
 *      PROTOMAN_STATE_CONNECTED --> PROTOMAN_STATE_CONNECTING: re-connection
 *      PROTOMAN_STATE_CONNECTED --> PROTOMAN_STATE_DISCONNECTING: protoman_disconnect();
 *      PROTOMAN_STATE_DISCONNECTING --> PROTOMAN_STATE_DISCONNECTED
 *
 *      PROTOMAN_STATE_INIT          --> PROTOMAN_STATE_ERROR
 *      PROTOMAN_STATE_CONNECTING    --> PROTOMAN_STATE_ERROR
 *      PROTOMAN_STATE_CONNECTED     --> PROTOMAN_STATE_ERROR
 *      PROTOMAN_STATE_DISCONNECTING --> PROTOMAN_STATE_ERROR
 *      PROTOMAN_STATE_DISCONNECTED  --> PROTOMAN_STATE_ERROR
 * @enduml
 *
 * Protocol Manager has defined set of callbacks, one per each state, that it calls when it requires the layer to take any actions.
 * Protocol Manager is event based, so when someting is happening, it is usually a result of calling
 * protoman_add_layer() when layer is added, protoman_connect() when application initiates the connection phase, or some
 * layer requests processing time by calling protoman_event() with PROTOMAN_EVENT_RUN as a event type.
 *
 * Callbacks defined in protoman_layer_callbacks_s are as follows:
 *  Current state  | callback that Protocol manager uses
 * ------------- | -------------
 * PROTOMAN_STATE_INIT | protoman_layer_callbacks_s::state_do_init
 * PROTOMAN_STATE_DISCONNECTED or \n PROTOMAN_STATE_CONNECTING | protoman_layer_callbacks_s::state_do_connect
 * PROTOMAN_STATE_CONNECTED | protoman_layer_callbacks_s::state_do_read
 * PROTOMAN_STATE_CONNECTED | protoman_layer_callbacks_s::state_do_write
 * PROTOMAN_STATE_CONNECTED | protoman_layer_callbacks_s::state_do_disconnect
 * PROTOMAN_STATE_CONNECTED | protoman_layer_callbacks_s::state_do_pause
 * - | protoman_layer_callbacks_s::state_do_resume
 *
 * State transition may happen as a result of the callback, and defined by its return value.
 * Each callback funtion follows \ref protoman_layer_state_do_cb_t prototype. As defined in the prototype, each state function
 * may transition the layer state to next one, stay in the current state, or mark errors. See \ref protoman_layer_state_do_cb_t for
 * exact return values.
 *
 * <h3>Data flow</h3>
 *
 * When connected, data can be read of written from the layer. Four callbacks are defined in protoman_layer_callbacks_s for the purpose.
 * * protoman_layer_callbacks_s::state_do_read
 * * protoman_layer_callbacks_s::state_do_write
 * * protoman_layer_callbacks_s::layer_read
 * * protoman_layer_callbacks_s::layer_write
 *
 * These four functions allow defining two distinct ways of delivering the data.
 * Data flows either by result of events where bottom layer fetches the data and creates PROTOMAN_EVENT_DATA_AVAIL event for the layer above.
 * Or the second option is that layer does generate PROTOMAN_EVENT_DATA_AVAIL but only fetches the data when protoman_layer_callbacks_s::layer_read is
 * called.
 *
 * When layer implementation wants to use the model where it pre-fetches the data, two helper functions
 * are provided protoman_generic_bytes_layer_read() and protoman_generic_bytes_layer_write() that can be used in the callback structure.
 * They internally handle buffering for the layer. Then layer as a result of callback or timer from the actual platform
 * may request processing time by calling protoman_event() with PROTOMAN_EVENT_RUN as a type. That eventually goes into state_do_read() function
 * and when the data is finally available, protoman_event() with PROTOMAN_EVENT_DATA_AVAIL is issued. In this model, you only need to implement
 * protoman_layer_callbacks_s::state_do_read and protoman_layer_callbacks_s::state_do_write.
 *
 * If you choose to implement a layer without pre-fetching the data, you may leave protoman_layer_callbacks_s::state_do_read and protoman_layer_callbacks_s::state_do_write()
 * NULL, and implement all data handling into protoman_layer_callbacks_s::layer_read protoman_layer_callbacks_s::layer_write.
 *
 * \sa protoman
 */

#include <stdint.h>

// Slightly ugly way to get ssize_t, but as the Mbed OS already has it we better use it from there.
#if defined(TARGET_LIKE_MBED) && defined(__ARMCC_VERSION) || defined(__ICCARM__)
#include "platform/mbed_retarget.h"
#else
#include <sys/types.h>
#endif

#include "ns_list.h"
#include "mbed-protocol-manager/protoman_config.h"
#include "source/include/protoman_internal.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus


/* These state retval return values are used with the protoman_generic_layer_run(). They
    are used to determine if the call succeeded and does it need to be called again. */
#define PROTOMAN_STATE_RETVAL_FINISHED    2 /* state done, move to next state */
#define PROTOMAN_STATE_RETVAL_AGAIN       1 /* state ok but needs to be called again */
#define PROTOMAN_STATE_RETVAL_WAIT        0 /* state ok, do nothing */
#define PROTOMAN_STATE_RETVAL_DISCONNECT -2 /* state failed, disconnect */
#define PROTOMAN_STATE_RETVAL_ERROR      -3 /* state failed, cannot recover */

#define PROTOMAN_IO_BYTES         0
#define PROTOMAN_IO_CERTFILE      1 /* len is ignored, TODO rename to PROTOMAN_IO_PATH */
#define PROTOMAN_IO_CERTBUF       2
#define PROTOMAN_IO_KEYFILE       3 /* len is ignored */
#define PROTOMAN_IO_KEYBUF        4
#define PROTOMAN_IO_PSKBUF        5
#define PROTOMAN_IO_ZEROCOPY      6 /* On read: Buffer ownership is transferred to caller. After no-longer needed,
                                     *          it MUST be freed by the caller using the lwm2m_free.
                                     *
                                     * On write: The ownership of the buffer is transferred to protoman after a successful call, and the buffer
                                     *           is freed automatically after sending data. The data buffer MUST be allocated using lwm2m_alloc. */

#define PROTOMAN_INFO_IP_STR   1 /* null terminated cstring */
#define PROTOMAN_INFO_IP_BYTES 2 /* uint8_t* network byteorder */
#define PROTOMAN_INFO_IP_LEN   3 /* size_t for PROTOMAN_INFO_IP_BYTES */
#define PROTOMAN_INFO_HOSTNAME 4 /* null terminated cstring */
#define PROTOMAN_INFO_PORT     5 /* uint16_t */
#define PROTOMAN_INFO_BAUDRATE 6 /* unsigned int */

#define PROTOMAN_SECURITY_MODE_CERTIFICATE              0
#define PROTOMAN_SECURITY_MODE_CERTIFICATE_VERIFY_NONE  1
#define PROTOMAN_SECURITY_MODE_PSK                      2

/* Throughout the protoman these alloc macros are used for the data buffer allocations.
   The initial idea was to use these to create a shared data buffers between layers but I
   couldn't really get any memory savings from there. The implementation had
   2 shared RX buffers and 2 shared TX buffers. 2 buffers were needed to allow data transitions.
   Usually there however was only one packet in the pipe and I couldn't get any memory savings */
#define protoman_tx_alloc(protoman, size) PROTOMAN_MALLOC(size)
#define protoman_rx_alloc(protoman, size) PROTOMAN_MALLOC(size)
#define protoman_tx_free(protoman, ptr) PROTOMAN_FREE(ptr)
#define protoman_rx_free(protoman, ptr) PROTOMAN_FREE(ptr)

struct protoman_io_header_s {
    uint8_t type;
};

struct protoman_io_bytes_s {
    struct protoman_io_header_s header; /* Must be first as protoman_io_bytes_s will be casted to protoman_io_header_s */
    uint8_t *buf;
    size_t len;
};

/** Delay configuration structure */
struct protoman_layer_run_delays_s {
    uint32_t do_init;         /* Delay to wait if do_init()       returns PROTOMAN_STATE_RETVAL_AGAIN */
    uint32_t do_connect;      /* Delay to wait if do_connect())   returns PROTOMAN_STATE_RETVAL_AGAIN */
    uint32_t do_write;        /* Delay to wait if do_write()      returns PROTOMAN_STATE_RETVAL_AGAIN */
    uint32_t do_read;         /* Delay to wait if do_read()       returns PROTOMAN_STATE_RETVAL_AGAIN */
    uint32_t do_disconnect;   /* Delay to wait if do_disconnect() returns PROTOMAN_STATE_RETVAL_AGAIN */
    uint32_t do_pause;        /* Delay to wait if do_pause()      returns PROTOMAN_STATE_RETVAL_AGAIN */
    uint32_t do_resume;       /* Delay to wait if do_pause()      returns PROTOMAN_STATE_RETVAL_AGAIN */
};

/**
 * Protocol layer configuration structure.
 * \sa protoman_layer.h
 */
struct protoman_layer_s {
    void *ctx;            /**< Optional implementation specific context handle, not used by Protocol Manager internally. */
    const char *name;     /**< Layer name for debugging purposes */
    int current_state;    /**< This is internal state for the layer */
    int target_state;     /**< This is a state the layer drives towards */
    int perceived_state;  /**< This is a state how ProtocolManager perceives the layer (layer does not edit) */
    bool no_statemachine; /**< not all layers have state machines */

    int protoman_error;   /**< protoman translated error */
    int specific_error;   /**< implementation specific error */
#ifdef PROTOMAN_ERROR_STRING
    const char *specific_error_str; /**< implementation specific verbal error */
#endif // PROTOMAN_ERROR_STRING

    void *config;        /**< Can be requested with protoman_get_config() */

    uint8_t *rx_buf;    /**< Payload buffer, to be requested by upper layer. */
    ssize_t rx_len;     /**< Length of data currently in buffer */
    size_t rx_offset;   /**< offset of payload in rx_buf */

    uint8_t *tx_buf;    /**< holds current layer output data */
    ssize_t tx_len;
    size_t tx_offset;

    const struct protoman_layer_callbacks_s *callbacks; /**< Layer callbacks */
    const struct protoman_layer_run_delays_s *delays;   /**< Delay configurations */

    void *timer_event;

    struct protoman_event_storage_s protoman_event_storage;

    struct protoman_s *protoman; /**< Pointer to Protocol Manager instance */
    ns_list_link_t link;         /**< Linked list pointer */
};

struct protoman_config_tls_common_s {
    uint8_t security_mode; /* PROTOMAN_LAYER_SECURITY_MODE_CERTIFICATE or PROTOMAN_LAYER_SECURITY_MODE_PSK */
};

struct protoman_config_tls_certificate_s {
    struct protoman_config_tls_common_s common; /* must be first item */
    struct protoman_io_bytes_s cacert;
    struct protoman_io_bytes_s owncert;
    struct protoman_io_bytes_s ownkey;
    const char *ownpass;
#ifdef PROTOMAN_USE_SSL_SESSION_RESUME
    bool bootstrap;
#endif
};

struct protoman_config_tls_psk_s {
    struct protoman_config_tls_common_s common;  /* must be first item */
    struct protoman_io_bytes_s psk;
    struct protoman_io_bytes_s psk_identity;
};

struct protoman_config_socket_s {
    char *hostname;
    uint16_t port;
    bool force_ipv4;
#ifdef PROTOMAN_OFFLOAD_TLS
    bool bootstrap;
#endif
};

struct protoman_config_pal_socket_s {
    uint32_t pal_interface_num;
    struct protoman_config_socket_s socket;
};

struct protoman_config_mbedos_socket_s {
    struct protoman_config_socket_s socket; /* must be first item */
    void* interface;
#ifdef PROTOMAN_OFFLOAD_TLS
    bool bootstrap;
#endif
};

struct protoman_config_paltls_certificate_s {
    struct protoman_config_tls_certificate_s certificate; /* must be first item */
    uint32_t pal_interface_num;
    struct protoman_config_socket_s socket;
};

struct protoman_config_paltls_psk_s {
    struct protoman_config_tls_psk_s psk; /* must be first item */
    uint32_t pal_interface_num;
    struct protoman_config_socket_s socket;
};

struct protoman_config_counter_unit_s {
    uint32_t count;
    uint32_t bytes;
    uint32_t nomem;
    uint32_t wouldblock;
};

struct protoman_config_counter_s {
    struct protoman_config_counter_unit_s tx;
    struct protoman_config_counter_unit_s rx;
};

/*  Config - drop
 * --------------- */
struct protoman_drop_entry_s {
    uint8_t *match_buf;     /* Match pattern */
    size_t match_len;       /* Length for match_buf */
    size_t match_offset;    /* Byte offset for the compared data in the match */
    size_t packet_len;      /* Length of the packet to match. 0 matches all lengths*/
    size_t packet_skips;    /* Amount of matching packets to skip before dropping */
    ssize_t packet_drops;   /* Amount of packets to be dropped. 0=all packets, n>0=n packets and n<0=none */
};

struct protoman_drop_entries_s {
    struct protoman_drop_entry_s *list; /* Table of entries */
    size_t count;
};

struct protoman_config_drop_s {
    struct protoman_drop_entries_s tx;
    struct protoman_drop_entries_s rx;
};

/*  Config - pcap
 * --------------- */
struct protoman_config_pcap_s {
    const char *pcap_file_path;
    int pcap_linktype;
};

struct protoman_config_frame_lv_s {
    size_t length_field_width;  /* length field width in bytes */
    size_t length_field_offset; /* Add offset to the length. For example, the length must be include the length field width */
    bool little_endian;          /* defaults to big endian as that is most common with networking */
};

struct protoman_config_packet_split_s {
    size_t read_max_bytes;
};

#ifdef PROTOMAN_ERROR_STRING
#define protoman_layer_record_error(layer, err, serr, estr) _protoman_layer_record_error(layer, err, serr, estr)
#else
#define protoman_layer_record_error(layer, err, serr, estr) _protoman_layer_record_error(layer, err, serr, (const char*)NULL)
#endif // PROTOMAN_ERROR_STRING

#if !defined CPPUTEST_COMPILATION
#define PROTOMAN_INLINE inline
#else
#define PROTOMAN_INLINE
#endif

/**
 * Stores an error state to the given layer.
 * @param layer Pointer to the layer.
 * @param protoman_error Error translated to protoman error.
 * @param specific_error Component specific error.
 * @param specific_error_str Component specific error string.
 */
PROTOMAN_INLINE void _protoman_layer_record_error(struct protoman_layer_s *layer,
                                  int protoman_error,
                                  int specific_error,
                                  const char *specific_error_str);

#ifdef PROTOMAN_VERBOSE
/**
 * Traces an error state on a given layer
 * @param layer Pointer to the layer.
 * @param protoman_error Error translated to protoman error.
 * @param specific_error Component specific error.
 * @param specific_error_str Component specific error string.
 */
void _protoman_layer_trace_error(struct protoman_layer_s *layer,
                                int protoman_error,
                                int specific_error,
                                const char *specific_error_str);
#endif

/* Provide definitions, either for inlining, or for protoman_layer.c */
#if !defined CPPUTEST_COMPILATION || defined PROTOMAN_FN
#ifndef PROTOMAN_FN
#define PROTOMAN_FN PROTOMAN_INLINE
#endif

PROTOMAN_FN void _protoman_layer_record_error(struct protoman_layer_s *layer,
                                                int protoman_error,
                                                int specific_error,
                                                const char *specific_error_str)
{
#ifdef PROTOMAN_ERROR_STRING
    layer->specific_error_str = specific_error_str;
#endif // PROTOMAN_ERROR_STRING
    layer->protoman_error = protoman_error;
    layer->specific_error = specific_error;

#ifdef PROTOMAN_VERBOSE
    _protoman_layer_trace_error(layer, protoman_error, specific_error, specific_error_str);
#endif
}
#endif /* !defined CPPUTEST_COMPILATION || defined PROTOMAN_FN */

/**
 *  Generic layer state change logic which generates events to above layers.
 *  @param layer Pointer to layer;
 *  @param new_state New state to change the layer to.
 */
void protoman_layer_state_change(struct protoman_layer_s *layer, int new_state);

/**
 * Generic layer read function that can be assigned to layer->cb->read for byte operations. The function checks the incoming data and copies it to layer->rx_buf if there is space.
 * @param layer Pointer to layer.
 * @param operation Pointer to the IO operation.
 * @return Bytes read
 * @return PROTOMAN_ERR_NOMEM if out of memory
 * @return PROTOMAN_ERR_WRONG_IO_TYPE if the IO type is wrong
 * @return PROTOMAN_ERR_WOULDBLOCK if the layer is not capable of providing data
 */
int protoman_generic_bytes_layer_read(struct protoman_layer_s *layer, struct protoman_io_header_s *operation);

/**
 * Generic layer write function that can be assigned to layer->cb->write for byte operations. The function checks the incoming data and copies it to layer->tx_buf if there is space.
 * @param layer Pointer to layer.
 * @param operation Pointer to the IO operation.
 * @return Bytes written
 * @return PROTOMAN_ERR_NOMEM if out of memory
 * @return PROTOMAN_ERR_WRONG_IO_TYPE if the IO type is wrong
 * @return PROTOMAN_ERR_WOULDBLOCK if the layer is not capable taking data in
 */
int protoman_generic_bytes_layer_write(struct protoman_layer_s *layer, struct protoman_io_header_s *operation);

/**
 * Generic layer free function that frees both layer->tx_buf and layer->rx_buf.
 * @param layer Pointer to layer.
 */
void protoman_generic_layer_free(struct protoman_layer_s *layer);

/**
 * Calls next layers read
 * @param layer Pointer to current layer
 * @param operation Pointer to IO operation
 * @return Bytes read, PROTOMAN_ERR_NOMEM in case of not enough memory, PROTOMAN_ERR_WOULDBLOCK in case there is no data or PROTOMAN_ERR_WRONG_IO if the IO operation type is wrong.
 */
ssize_t protoman_layer_read_next(struct protoman_layer_s *layer, struct protoman_io_header_s *operation);

/**
 * Calls next layers write
 * @param layer Pointer to current layer
 * @param operation Pointer to IO operation
 * @return Bytes written
 * @return PROTOMAN_ERR_NOMEM if out of memory
 * @return PROTOMAN_ERR_WRONG_IO if the IO type is wrong
 * @return PROTOMAN_ERR_WOULDBLOCK if the layer is not capable taking data in
 */
ssize_t protoman_layer_write_next(struct protoman_layer_s *layer, struct protoman_io_header_s *operation);

/**
 * Generic layer event to be used by layers. This generic layer event handler handles events in a way that
 * allows simple layers to be written. If the usecase requires more fine grained control, the layer can implement
 * it's own layer event handler.
 * @param layer Pointer to the layer.
 * @param event_id The event identifier
 */
void protoman_generic_layer_event(struct protoman_layer_s *layer, int event_id);

/**
 * Generic layer run to be used by layers. This generic run executes through all applicable PROTOMAN_STATEs
 * for the layer and call given _do functions.
 * @param layer Pointer to the layer.
 */
void protoman_generic_layer_run(struct protoman_layer_s *layer);

/**
 * Protocol Manager callback function to pass write operations to the layer
 * @param layer Pointer to the layer.
 * @param operation Pointer to the IO operation for the layer.
 * @return Bytes written
 * @return PROTOMAN_ERR_NOMEM if out of memory
 * @return PROTOMAN_ERR_WRONG_IO_TYPE if the IO type is wrong
 * @return PROTOMAN_ERR_WOULDBLOCK if the layer is not capable taking data in
 */
typedef int (*protoman_layer_write_t)(struct protoman_layer_s *layer, struct protoman_io_header_s *operation);

/**
 * Protocol Manager callback function to pass read operations to the layer
 * @param layer Pointer to the layer.
 * @param operation Pointer to the IO operation for the layer.
 * @return Bytes read
 * @return PROTOMAN_ERR_NOMEM if out of memory
 * @return PROTOMAN_ERR_WRONG_IO_TYPE if the IO type is wrong
 * @return PROTOMAN_ERR_WOULDBLOCK if the layer is not capable of providing data
 */
typedef int (*protoman_layer_read_t)(struct protoman_layer_s *layer, struct protoman_io_header_s *operation);

/**
 * Protocol Manager callback function to progress the layer specific state machine.
 * @param layer Pointer to the layer.
 * @param event_id Event ID.
 */
typedef void (*protoman_layer_event_t)(struct protoman_layer_s *layer, int event_id);

/**
 * Protocol Manager callback function to free the layer specific data.
 * @param layer Pointer to the layer.
 */
typedef void (*protoman_layer_free_t)(struct protoman_layer_s *layer);

/**
 * Protocol Manager callback function to get info from the layer. The returned data format is defined with the PROTOMAN_INFO_*.
 * @param layer Pointer to the layer.
 * @param info_id ID for the requested info. The ID can be one of the PROTOMAN_INFO_* defines.
 * @return Pointer to requested data.
 * @return NULL, if no requested info is found
 */
typedef void* (*protoman_layer_info_t)(struct protoman_layer_s *layer, int info_id);

/**
 * Protocol Manager callback function for generic state machine actions
 * @param layer Pointer to the layer.
 * @return PROTOMAN_STATE_RETVAL_FINISHED if the state action is done and state can be progressed
 * @return PROTOMAN_STATE_RETVAL_AGAIN if the state action needs to be called again without any specific delay
 * @return PROTOMAN_STATE_RETVAL_WAIT if the state action needs to be called at least at layer->delays->do_*
 * @return PROTOMAN_STATE_RETVAL_DISCONNECT if the state action determined that the layer needs to be disconnected
 * @return PROTOMAN_STATE_RETVAL_ERROR if the state action ran into error and cannot operate without outside intervention
 */
typedef int (*protoman_layer_state_do_cb_t)(struct protoman_layer_s *layer);

/**
 * Define layer callbacks.
 * Some members may be left NULL when marked as OPTIONAL.
 * Some helper functions are provided.
 * Usually protoman_generic_layer_run() is used as layer_event. protoman_generic_bytes_layer_write() and protoman_generic_bytes_layer_read() may be used for layer_read and layer_write.
 */
struct protoman_layer_callbacks_s {
    protoman_layer_info_t       layer_info;             /**< OPTIONAL: Get layer information. */
    protoman_layer_read_t       layer_read;             /**< Read data from layer. */
    protoman_layer_write_t      layer_write;            /**< Write data into the layer. */
    protoman_layer_event_t      layer_event;            /**< OPTIONAL: Layer specific event handler. */
    protoman_layer_free_t       layer_free;             /**< OPTIONAL: Free all memory allocated by layer. */
    protoman_layer_state_do_cb_t state_do_init;         /**< OPTIONAL: Called from protoman_generic_layer_run() on Initialization phase. */
    protoman_layer_state_do_cb_t state_do_connect;      /**< OPTIONAL: Called from protoman_generic_layer_run() when connection is requested. */
    protoman_layer_state_do_cb_t state_do_read;         /**< OPTIONAL: Called from protoman_generic_layer_run() when in connected state and PROTOMAN_EVENT_RUN issued. */
    protoman_layer_state_do_cb_t state_do_write;        /**< OPTIONAL: Called from protoman_generic_layer_run() when in connected state and PROTOMAN_EVENT_RUN issued. */
    protoman_layer_state_do_cb_t state_do_disconnect;   /**< OPTIONAL: Called from protoman_generic_layer_run() when disconnection is requested. */
    protoman_layer_state_do_cb_t state_do_pause;        /**< OPTIONAL: Called from protoman_generic_layer_run() when protoman_pause() called. */
    protoman_layer_state_do_cb_t state_do_resume;       /**< OPTIONAL: Called from protoman_generic_layer_run() when protoman_resume() called. */
};

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // PROTOMAN_LAYER_H
