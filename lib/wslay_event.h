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
#ifndef WSLAY_EVENT_H
#define WSLAY_EVENT_H

#include <wslay/wslay.h>

struct wslay_stack;
struct wslay_queue;

struct wslay_byte_chunk {
  uint8_t *data;
  size_t data_length;
};

struct wslay_imsg {
  uint8_t fin;
  uint8_t rsv;
  uint8_t opcode;
  uint32_t utf8state;
  struct wslay_queue *chunks;
  size_t msg_length;
};

enum wslay_msg_type {
  WSLAY_NON_FRAGMENTED,
  WSLAY_FRAGMENTED
};

struct wslay_omsg {
  uint8_t fin;
  uint8_t opcode;
  enum wslay_msg_type type;

  uint8_t *data;
  size_t data_length;

  union wslay_event_msg_source source;
  wslay_event_fragmented_msg_callback read_callback;
  /* TODO To support fragmented send, remember offset where we already
     sent */
};

struct wslay_event_frame_user_data {
  wslay_event_context_ptr ctx;
  void *user_data;
};

enum wslay_event_close_status {
  WSLAY_CLOSE_RECEIVED = 1 << 0,
  WSLAY_CLOSE_QUEUED = 1 << 1,
  WSLAY_CLOSE_SENT = 1 << 2,
};

struct wslay_event_context {
  uint8_t server;
  uint8_t close_status;
  wslay_frame_context_ptr frame_ctx;
  uint8_t read_enabled;
  uint8_t write_enabled;
  struct wslay_imsg imsgs[2];
  struct wslay_imsg *imsg;
  uint64_t ipayloadlen;
  uint64_t ipayloadoff;
  uint8_t imask;
  uint8_t imaskkey[4];
  int error;
  struct wslay_omsg *omsg;
  /* TODO maybe for separete send_queue for ctrl msg */
  struct wslay_queue *send_queue; // <wslay_omsg*>
  struct wslay_queue *send_ctrl_queue; // <wslay_omsg*>, ctrl frame only
  uint8_t obuf[4096];
  uint8_t *obuflimit;
  uint8_t *obufmark;
  uint64_t opayloadlen;
  uint64_t opayloadoff;
  uint8_t omask;
  uint8_t omaskkey[4];
  struct wslay_event_callbacks callbacks;
  struct wslay_event_frame_user_data frame_user_data;
  void *user_data;
};

#endif // WSLAY_EVENT_H
