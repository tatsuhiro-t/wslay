/*
 * The MIT License
 *
 * Copyright (c) 2011 Tatsuhiro Tsujikawa
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

/*
 * Callback function used by wslay_frame_send function when it needs
 * to send data. The implementation of this function must send at most
 * len bytes of data in buf. user_data is one given in
 * wslay_frame_context_init function. The implementation of this
 * functino must return the number of bytes sent. If there is an
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
 * functino return the number of bytes written. If the return value is
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
#define WSLAY_CONTINUATION_FRAME 0x0u
#define WSLAY_TEXT_FRAME 0x1u
#define WSLAY_BINARY_FRAME 0x2u
#define WSLAY_CONNECTION_CLOSE 0x8u
#define WSLAY_PING 0x9u
#define WSLAY_PONG 0xau

enum wslay_error {
  WSLAY_ERR_WANT_READ = -100,
  WSLAY_ERR_WANT_WRITE = -101,
  WSLAY_ERR_PROTO = -200,
  WSLAY_ERR_INVALID_ARGUMENT = -300,
  WSLAY_ERR_INVALID_CALLBACK = -301
};

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

#ifdef __cplusplus
}
#endif

#endif // WSLAY_H
