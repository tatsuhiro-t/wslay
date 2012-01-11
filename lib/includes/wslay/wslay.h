/*
 * Wslay - The WebSocket Library
 *
 * Copyright (c) 2011, 2012 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef WSLAY_H
#define WSLAY_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

enum wslay_error {
  WSLAY_ERR_WANT_READ = -100,
  WSLAY_ERR_WANT_WRITE = -101,
  WSLAY_ERR_PROTO = -200,
  WSLAY_ERR_INVALID_ARGUMENT = -300,
  WSLAY_ERR_INVALID_CALLBACK = -301,
  WSLAY_ERR_NO_MORE_MSG = -302,
  WSLAY_ERR_CALLBACK_FAILURE = -400,
  WSLAY_ERR_WOULDBLOCK = -401,
  WSLAY_ERR_NOMEM = -500
};

/*
 * Status codes defined in RFC6455
 */
enum wslay_status_code {
  WSLAY_CODE_NORMAL_CLOSURE = 1000,
  WSLAY_CODE_GOING_AWAY = 1001,
  WSLAY_CODE_PROTOCOL_ERROR = 1002,
  WSLAY_CODE_UNSUPPORTED_DATA = 1003,
  WSLAY_CODE_NO_STATUS_RCVD = 1005,
  WSLAY_CODE_ABNORMAL_CLOSURE = 1006,
  WSLAY_CODE_INVALID_FRAME_PAYLOAD_DATA = 1007,
  WSLAY_CODE_POLICY_VIOLATION = 1008,
  WSLAY_CODE_MESSAGE_TOO_BIG = 1009,
  WSLAY_CODE_MANDATORY_EXT = 1010,
  WSLAY_CODE_INTERNAL_SERVER_ERROR = 1011,
  WSLAY_CODE_TLS_HANDSHAKE = 1015
};

/*
 * Callback function used by wslay_frame_send function when it needs
 * to send data. The implementation of this function must send at most
 * len bytes of data in buf. user_data is one given in
 * wslay_frame_context_init function. The implementation of this
 * function must return the number of bytes sent. If there is an
 * error, return -1. The return value 0 is also treated an error by
 * the library.
 */
typedef ssize_t (*wslay_frame_send_callback)(const uint8_t *buf, size_t len,
                                             void *user_data);
/*
 * Callback function used by wslay_frame_recv function when it needs
 * more data. The implementation of this function must fill at most
 * len bytes of data into buf. The memory area of buf is allocated by
 * library and not be freed by the application code.  user_data is one
 * given in wslay_frame_context_init function. The implementation of
 * this function must return the number of bytes filled into buf.  If
 * there is an error, return -1. The return value 0 is also treated an
 * error by the library.
 */
typedef ssize_t (*wslay_frame_recv_callback)(uint8_t *buf, size_t len,
                                             void *user_data);
/*
 * Callback function used by wslay_frame_send function when it needs
 * new mask key. The implementation of this function must write len
 * bytes of mask key to buf. user_data is one given in
 * wslay_frame_context_init function. The implementation of this
 * function return the number of bytes written. If the return value is
 * not len, then the library treats it as an error.
 */
typedef ssize_t (*wslay_frame_genmask_callback)(uint8_t *buf, size_t len,
                                                void *user_data);

struct wslay_frame_callbacks {
  wslay_frame_send_callback send_callback;
  wslay_frame_recv_callback recv_callback;
  wslay_frame_genmask_callback genmask_callback;
};

/*
 * The opcode defined in RFC6455. These can be used to specify opcode
 * in wslay_frame_iocb.
 */
enum wslay_opcode {
  WSLAY_CONTINUATION_FRAME = 0x0u,
  WSLAY_TEXT_FRAME = 0x1u,
  WSLAY_BINARY_FRAME = 0x2u,
  WSLAY_CONNECTION_CLOSE = 0x8u,
  WSLAY_PING = 0x9u,
  WSLAY_PONG = 0xau
};

/*
 * Macro that returns 1 if opcode is control frame opcode, otherwise
 * returns 0.
 */
#define wslay_is_ctrl_frame(opcode) ((opcode >> 3) & 1)

/*
 * Macros that returns reserved bits: RSV1, RSV2, RSV3.  These macros
 * assumes that rsv is constructed by ((RSV1 << 2) | (RSV2 << 1) |
 * RSV3)
 */
#define wslay_get_rsv1(rsv) ((rsv >> 2) & 1)
#define wslay_get_rsv2(rsv) ((rsv >> 1) & 1)
#define wslay_get_rsv3(rsv) (rsv & 1)

struct wslay_frame_iocb {
  uint8_t fin; /* 1 for fragmented final frame, 0 for otherwise */
  uint8_t rsv; /* reserved 3 bits. RFC6455 requires 0 unless extensions are
                  negotiated */
  uint8_t opcode; /* 4 bit opcode */
  uint64_t payload_length; /* payload length 0-2**63-1 */
  uint8_t mask; /* 1 for masked frame, 0 for unmasked */
  const uint8_t *data; /* part of payload data */
  size_t data_length; /* bytes of data defined above */
};

struct wslay_frame_context;
typedef struct wslay_frame_context *wslay_frame_context_ptr;

/*
 * Initializes ctx using given callbacks and user_data.  This function
 * allocates memory for struct wslay_frame_context and stores the
 * result to *ctx. The callback functions specified in callbacks are
 * copied to ctx. user_data is stored in ctx and it will be passed to
 * callback functions. When the user code finished using ctx, it must
 * call wslay_frame_context_free to deallocate memory.
 */
int wslay_frame_context_init(wslay_frame_context_ptr *ctx,
                             const struct wslay_frame_callbacks *callbacks,
                             void *user_data);

/*
 * Deallocates memory pointed by ctx.
 */
void wslay_frame_context_free(wslay_frame_context_ptr ctx);

/*
 * Send WebSocket frame specified in iocb. ctx must be initialized
 * using wslay_frame_context_init function.  iocb->fin must be 1 if
 * this is a fin frame, otherwise 0.  iocb->rsv is reserved bits.
 * iocb->opcode must be the opcode of this frame.  iocb->mask must be
 * 1 if this is masked frame, otherwise 0.  iocb->payload_length is
 * the payload_length of this frame.  iocb->data must point to the
 * payload data to be sent. iocb->data_length must be the length of
 * the data.  This function calls recv_callback function if it needs
 * to send bytes.  This function calls gen_mask_callback function if
 * it needs new mask key.  This function returns the number of payload
 * bytes sent. Please note that it does not include any number of
 * header bytes. If it cannot send any single bytes of payload, it
 * returns WSLAY_ERR_WANT_WRITE. If the library detects error in iocb,
 * this function returns WSLAY_ERR_INVALID_ARGUMENT.  If callback
 * functions report a failure, this function returns
 * WSLAY_ERR_INVALID_CALLBACK. This function does not always send all
 * given data in iocb. If there are remaining data to be sent, adjust
 * data and data_length in iocb accordingly and call this function
 * again.
 */
ssize_t wslay_frame_send(wslay_frame_context_ptr ctx,
                         struct wslay_frame_iocb *iocb);

/*
 * Receives WebSocket frame and stores it in iocb.  This function
 * returns the number of payload bytes received.  This does not
 * include header bytes. In this case, iocb will be populated as
 * follows: iocb->fin is 1 if received frame is fin frame, otherwise
 * 0. iocb->rsv is reserved bits of received frame.  iocb->opcode is
 * opcode of received frame.  iocb->mask is 1 if received frame is
 * masked, otherwise 0.  iocb->payload_length is the payload length of
 * received frame.  iocb->data is pointed to the buffer containing
 * received payload data.  This buffer is allocated by the library and
 * must be read-only.  iocb->data_length is the number of payload
 * bytes recieved.  This function calls recv_callback if it needs to
 * receive additional bytes. If it cannot receive any single bytes of
 * payload, it returns WSLAY_ERR_WANT_READ.  If the library detects
 * protocol violation in a received frame, this function returns
 * WSLAY_ERR_PROTO. If callback functions report a failure, this
 * function returns WSLAY_ERR_INVALID_CALLBACK.  This function does
 * not always receive whole frame in a single call. If there are
 * remaining data to be received, call this function again.  This
 * function ensures frame alignment.
 */
ssize_t wslay_frame_recv(wslay_frame_context_ptr ctx,
                         struct wslay_frame_iocb *iocb);

struct wslay_event_context;
typedef struct wslay_event_context *wslay_event_context_ptr;

struct wslay_event_on_msg_recv_arg {
  uint8_t rsv;
  uint8_t opcode;
  const uint8_t *msg;
  size_t msg_length;
  uint16_t status_code; /* Only for opcode == WSLAY_CONNECTION_CLOSE */
};

/*
 * Callback function invoked by wslay_event_recv() when a message is
 * completely received.
 */
typedef void (*wslay_event_on_msg_recv_callback)
(wslay_event_context_ptr ctx,
 const struct wslay_event_on_msg_recv_arg *arg, void *user_data);

struct wslay_event_on_frame_recv_start_arg {
  uint8_t fin;
  uint8_t rsv;
  uint8_t opcode;
  uint64_t payload_length;
};

/*
 * Callback function invoked by wslay_event_recv() when a header of
 * frame is received.
 */
typedef void (*wslay_event_on_frame_recv_start_callback)
(wslay_event_context_ptr ctx,
 const struct wslay_event_on_frame_recv_start_arg *arg, void *user_data);

struct wslay_event_on_frame_recv_chunk_arg {
  const uint8_t *data;
  size_t data_length;
};

/*
 * Callback function invoked by wslay_event_recv() when (part of)
 * payload data of frame is received.
 */
typedef void (*wslay_event_on_frame_recv_chunk_callback)
(wslay_event_context_ptr ctx,
 const struct wslay_event_on_frame_recv_chunk_arg *arg, void *user_data);

/*
 * Callback function invoked by wslay_event_recv() when a frame is
 * completely received.
 */
typedef void (*wslay_event_on_frame_recv_end_callback)
(wslay_event_context_ptr ctx, void *user_data);

/*
 * Callback function invoked by wslay_event_recv() when the library
 * wants to receive more data from peer.
 */
typedef ssize_t (*wslay_event_recv_callback)(wslay_event_context_ptr ctx,
                                             uint8_t *buf, size_t len,
                                             void *user_data);

/*
 * Callback function invoked by wslay_event_send() when the library
 * wants to send data to peer.
 */
typedef ssize_t (*wslay_event_send_callback)(wslay_event_context_ptr ctx,
                                             const uint8_t *data, size_t len,
                                             void *user_data);

/*
 * Callback function invoked by wslay_event_send() when the library
 * wants new mask key.
 */
typedef ssize_t (*wslay_event_genmask_callback)(wslay_event_context_ptr ctx,
                                                uint8_t *buf, size_t len,
                                                void *user_data);

struct wslay_event_callbacks {
  wslay_event_recv_callback recv_callback;
  wslay_event_send_callback send_callback;
  wslay_event_genmask_callback genmask_callback;
  wslay_event_on_frame_recv_start_callback on_frame_recv_start_callback;
  wslay_event_on_frame_recv_chunk_callback on_frame_recv_chunk_callback;
  wslay_event_on_frame_recv_end_callback on_frame_recv_end_callback;
  wslay_event_on_msg_recv_callback on_msg_recv_callback;
};

/*
 * Initializes ctx as WebSocket Server.
 *
 * On success, returns 0. On error, returns one of following negative
 * values:
 *
 * WSLAY_ERR_NOMEM - Not enough memory.
  */
int wslay_event_context_server_init
(wslay_event_context_ptr *ctx,
 const struct wslay_event_callbacks *callbacks, void *user_data);

/*
 * Initializes ctx as WebSocket client.
 *
 * On success, returns 0. On error, returns one of following negative
 * values:
 *
 * WSLAY_ERR_NOMEM - Not enough memory.
  */
int wslay_event_context_client_init
(wslay_event_context_ptr *ctx,
 const struct wslay_event_callbacks *callbacks, void *user_data);

/*
 * Releases allocated resources for ctx.
 */
void wslay_event_context_free(wslay_event_context_ptr ctx);

/*
 * Disable buffering for non-control frames.  If val is zero, enable
 * buffering for non-control frames.  If val is non-zero, disable
 * buffering for non-control frames. If on_msg_recv_callback is
 * invoked when buffering is disabled, msg_length of struct
 * wslay_event_on_msg_recv_arg is set to 0 for non-control frames.
 *
 * This function must not be used after first invocation of
 * wslay_event_recv().
 */
void wslay_event_config_set_no_buffering(wslay_event_context_ptr ctx, int val);

/*
 * Set maximum length of a message that can be received.  If the
 * length of a message is larger than this value, close control frame
 * with WSLAY_CODE_MESSAGE_TOO_BIG is queued.  If buffering for
 * non-control frames is disabled, the library only checks frame
 * payload length and does not check length of entire message.
 *
 * The default value is (1 << 32)-1.
 */
void wslay_event_config_set_max_recv_msg_length(wslay_event_context_ptr ctx,
                                                uint64_t val);

/*
 * Set callbacks to ctx. This function replaces callbacks given in
 * wslay_event_context_server_init() or
 * wslay_event_context_client_init() with given callbacks.  This
 * function is useful if different action is necessary depending on
 * the situation.
 */
void wslay_event_config_set_callbacks
(wslay_event_context_ptr ctx, const struct wslay_event_callbacks *callbacks);

int wslay_event_recv(wslay_event_context_ptr ctx);
int wslay_event_send(wslay_event_context_ptr ctx);

struct wslay_event_msg {
  uint8_t opcode;
  const uint8_t *msg;
  size_t msg_length;
};

/*
 * Queues non-fragmented message. This function supports both control
 * and non-control messages.
 *
 * On success, returns 0. Otherwise returns one of following negative
 * values:
 *
 * WSLAY_ERR_NO_MORE_MSG - Could not queue further message. The one of
 *     possible reason is that close control frame has been
 *     queued/sent.
 *
 * WSLAY_ERR_INVALID_ARGUMENT - arg is not properly crafted.
 *
 * WSLAY_ERR_NOMEM - Not enough memory.
 */
int wslay_event_queue_msg(wslay_event_context_ptr ctx,
                          const struct wslay_event_msg *arg);

union wslay_event_msg_source {
  int fd;
  void *data;
};

typedef ssize_t (*wslay_event_fragmented_msg_callback)
(wslay_event_context_ptr ctx,
 uint8_t *buf, size_t len, const union wslay_event_msg_source *source,
 int *eof, void *user_data);

struct wslay_event_fragmented_msg {
  uint8_t opcode;
  union wslay_event_msg_source source;
  wslay_event_fragmented_msg_callback read_callback;
};

/*
 * Queues fragmented message. This function only supports non-control
 * messages. For control frames, use wslay_event_queue_msg().
 *
 * On success, returns 0. Otherwise returns one of following negative
 * values:
 *
 * WSLAY_ERR_NO_MORE_MSG - Could not queue further message. The one of
 *     possible reason is that close control frame has been
 *     queued/sent.
 *
 * WSLAY_ERR_INVALID_ARGUMENT - arg is not properly crafted.
 *
 * WSLAY_ERR_NOMEM - Not enough memory.
 */
int wslay_event_queue_fragmented_msg
(wslay_event_context_ptr ctx, const struct wslay_event_fragmented_msg *arg);

/*
 * Queue close frame. If status_code is 0, close frame has no body
 * even if reason_length is non-zero. For non-zero status_code value,
 * use one of enum wslay_status_code.
 */
int wslay_event_queue_close(wslay_event_context_ptr ctx,
                            uint16_t status_code,
                            const uint8_t *reason, size_t reason_length);

void wslay_event_set_error(wslay_event_context_ptr ctx, int val);

int wslay_event_want_read(wslay_event_context_ptr ctx);
int wslay_event_want_write(wslay_event_context_ptr ctx);

void wslay_event_shutdown_read(wslay_event_context_ptr ctx);
void wslay_event_shutdown_write(wslay_event_context_ptr ctx);

int wslay_event_get_read_enabled(wslay_event_context_ptr ctx);
int wslay_event_get_write_enabled(wslay_event_context_ptr ctx);

/*
 * Returns 1 if close frame is recived. Otherwise returns 0.
 */
int wslay_event_get_close_received(wslay_event_context_ptr ctx);
/*
 * Returns 1 if close frame is sent. Otherwise returns 0.
 */
int wslay_event_get_close_sent(wslay_event_context_ptr ctx);

/*
 * Returns received status code in close control frame. If no close
 * control frame has not been received, returns
 * WSLAY_CODE_ABNORMAL_CLOSURE.  If received close control frame has
 * no status code, returns WSLAY_CODE_NO_STATUS_RCVD.
 */
uint16_t wslay_event_get_status_code_received(wslay_event_context_ptr ctx);

/*
 * Returns sent status code in close control frame. If no close
 * control frame has not been sent, returns
 * WSLAY_CODE_ABNORMAL_CLOSURE. If sent close control frame has no
 * status code, returns WSLAY_CODE_NO_STATUS_RCVD.
 */
uint16_t wslay_event_get_status_code_sent(wslay_event_context_ptr ctx);

/*
 * Returns the number of queued messages.
 */
size_t wslay_event_get_queued_msg_count(wslay_event_context_ptr ctx);

/*
 * Returns the sum of queued message length. It only counts the
 * message length queued using wslay_event_queue_msg().
 */
size_t wslay_event_get_queued_msg_length(wslay_event_context_ptr ctx);

#ifdef __cplusplus
}
#endif

#endif // WSLAY_H
