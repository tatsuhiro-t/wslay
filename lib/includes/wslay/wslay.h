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

typedef ssize_t (*wslay_send_callback)(const uint8_t *buf, size_t len,
                                       void *user_data);
/*
 * Callback function used by wslay_frame_recv function when it needs
 * more data. The implementation of this function must fill at most
 * len bytes of data into buf. The memory area of buf is allocated by
 * library and not be freed by the application code.  user_data is one
 * given in wslay_session_init function. The implementation of this
 * function must returns the number of bytes filled into buf.  If
 * there is an error, return -1. The return value 0 is also treated an
 * error by the library.
 */
typedef ssize_t (*wslay_recv_callback)(uint8_t *buf, size_t len,
                                       void *user_data);
typedef ssize_t (*wslay_gen_mask_callback)(uint8_t *buf, size_t len,
                                           void *user_data);

struct wslay_callbacks {
  wslay_send_callback send_callback;
  wslay_recv_callback recv_callback;
  wslay_gen_mask_callback gen_mask_callback;
};

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

struct wslay_iocb {
  uint8_t fin; /* 1 for fragmented final frame, 0 for otherwise */
  uint8_t rsv; /* reserved 3 bits. RFC6455 requires 0 unless extensions are
                  negotiated */
  uint8_t opcode; /* 4 bit opcode */
  uint64_t payload_length; /* payload length 0-2**63-1 */
  uint8_t mask; /* 1 for masked frame, 0 for unmasked */
  const uint8_t *data; /* part of payload data */
  size_t data_length; /* bytes of data defined above */
};

struct wslay_session;
typedef struct wslay_session *wslay_session_ptr;

int wslay_session_init(wslay_session_ptr *session,
                       const struct wslay_callbacks *callbacks,
                       void *user_data);

void wslay_session_free(wslay_session_ptr session);

ssize_t wslay_frame_send(wslay_session_ptr session,
                         struct wslay_iocb *iocb);
ssize_t wslay_frame_recv(wslay_session_ptr session,
                         struct wslay_iocb *iocb);

#ifdef __cplusplus
}
#endif

#endif // WSLAY_H
