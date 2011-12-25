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
typedef ssize_t (*wslay_recv_callback)(uint8_t *buf, size_t len,
                                       void *user_data);
typedef ssize_t (*wslay_gen_mask_callback)(uint8_t *buf, size_t len,
                                           void *user_data);

struct wslay_callbacks {
  wslay_send_callback send_callback;
  wslay_recv_callback recv_callback;
  wslay_gen_mask_callback gen_mask_callback;
};

enum wslay_state {
  PREP_HEADER,
  SEND_HEADER,
  SEND_PAYLOAD,
  RECV_HEADER1,
  RECV_PAYLOADLEN,
  RECV_EXT_PAYLOADLEN,
  RECV_MASKKEY,
  RECV_PAYLOAD
};

struct wslay_opcode_memo {
  uint8_t fin;
  uint8_t opcode;
  uint8_t rsv;
};

struct wslay_session {
  uint8_t ibuf[4096];
  uint8_t *ibufmark;
  uint8_t *ibuflimit;
  struct wslay_opcode_memo iom;
  uint64_t ipayloadlen;
  uint64_t ipayloadoff;
  uint8_t imask;
  uint8_t imaskkey[4];
  enum wslay_state istate;
  size_t ireqread;

  uint8_t oheader[14];
  uint8_t *oheadermark;
  uint8_t *oheaderlimit;
  struct wslay_opcode_memo oom;
  uint64_t opayloadlen;
  uint64_t opayloadoff;
  uint8_t omask;
  uint8_t omaskkey[4];
  enum wslay_state ostate;

  struct wslay_callbacks callbacks;
  void *user_data;
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

#ifdef __cplusplus
}
#endif

#endif // WSLAY_H
