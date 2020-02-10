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

struct protoman_layer_run_delays_s {
    uint32_t do_init;         /* Delay to wait if do_init()       returns PROTOMAN_STATE_RETVAL_AGAIN */
    uint32_t do_connect;      /* Delay to wait if do_connect())   returns PROTOMAN_STATE_RETVAL_AGAIN */
    uint32_t do_write;        /* Delay to wait if do_write()      returns PROTOMAN_STATE_RETVAL_AGAIN */
    uint32_t do_read;         /* Delay to wait if do_read()       returns PROTOMAN_STATE_RETVAL_AGAIN */
    uint32_t do_disconnect;   /* Delay to wait if do_disconnect() returns PROTOMAN_STATE_RETVAL_AGAIN */
};

struct protoman_layer_s {
    void *ctx;
    const char *name;
    int current_state;    /* This is internal state for the layer */
    int target_state;     /* This is a state the layer drives towards */
    int perceived_state;  /* This is a state how ProtocolManager perceives the layer (layer does not edit) */
    bool no_statemachine; /* not all layers have state machines */

    int protoman_error;   /* protoman translated error */
    int specific_error;   /* implementation specific error */
#ifdef PROTOMAN_ERROR_STRING
    const char *specific_error_str; /* implementation specific verbal error */
#endif // PROTOMAN_ERROR_STRING

    void *config;

    uint8_t *rx_buf; /* holds current layer's read data (others ask here) */
    ssize_t rx_len;
    size_t rx_offset;

    uint8_t *tx_buf; /* holds current layer output data */
    ssize_t tx_len;
    size_t tx_offset;

    const struct protoman_layer_callbacks_s *callbacks;
    const struct protoman_layer_run_delays_s *delays;

    void *timer_event;

    struct protoman_event_storage_s protoman_event_storage;

    struct protoman_s *protoman; /* parent */
    ns_list_link_t link;
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
    char *pcap_file_path;
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

/**
 * Stores an error state to the given layer.
 * @param layer Pointer to the layer.
 * @param protoman_error Error translated to protoman error.
 * @param specific_error Component specific error.
 * @param specific_error_str Component specific error string.
 */
void _protoman_layer_record_error(struct protoman_layer_s *layer, int protoman_error, int specific_error, const char *specific_error_str);

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

struct protoman_layer_callbacks_s {
    protoman_layer_info_t       layer_info;
    protoman_layer_read_t       layer_read;
    protoman_layer_write_t      layer_write;
    protoman_layer_event_t      layer_event;
    protoman_layer_free_t       layer_free;
    protoman_layer_state_do_cb_t state_do_init;
    protoman_layer_state_do_cb_t state_do_connect;
    protoman_layer_state_do_cb_t state_do_read;
    protoman_layer_state_do_cb_t state_do_write;
    protoman_layer_state_do_cb_t state_do_disconnect;

};

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // PROTOMAN_LAYER_H
