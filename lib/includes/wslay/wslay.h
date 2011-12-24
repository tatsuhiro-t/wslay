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

#include <stdint.h>
#include <stdlib.h>

struct wslay_session;

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

typedef ssize_t (*wslay_send_callback)(const uint8_t *buf, size_t len,
                                       void *user_data);
typedef ssize_t (*wslay_recv_callback)(uint8_t *buf, size_t len,
                                       void *user_data);
typedef ssize_t (*wslay_gen_mask_callback)(uint8_t *buf, size_t len,
                                           void *user_data);

struct wslay_callbacks {
  wslay_send_callback send_callback;
  wslay_recv_callback recv_callback;
  wslay_gen_mask_callback gen_mask_callback;
};

struct wslay_iocb {
  uint8_t fin; /* 1 */
  uint8_t rsv; /* 3 */
  uint8_t opcode; /* 4 */
  uint64_t payload_length; /* 7/16/64 */
  uint8_t mask; /* 1 */
  const uint8_t *data;
  size_t data_length;
};

int wslay_session_init(struct wslay_session *session,
                       const struct wslay_callbacks *callbacks,
                       void *user_data);

ssize_t wslay_frame_send(struct wslay_session *session,
                         struct wslay_iocb *iocb);
ssize_t wslay_frame_recv(struct wslay_session *session,
                         struct wslay_iocb *iocb);

#endif // WSLAY_H
