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
#include "wslay_event_test.h"

#include <assert.h>

#include <CUnit/CUnit.h>

#include "wslay_event.h"

struct scripted_data_feed {
  uint8_t data[8192];
  uint8_t* datamark;
  uint8_t* datalimit;
  size_t feedseq[8192];
  size_t seqidx;
};

struct accumulator {
  uint8_t buf[4096];
  size_t length;
};

struct my_user_data {
  struct scripted_data_feed *df;
  struct accumulator *acc;
};

static void scripted_data_feed_init(struct scripted_data_feed *df,
                                    const uint8_t *data, size_t data_length)
{
  memset(df, 0, sizeof(struct scripted_data_feed));
  memcpy(df->data, data, data_length);
  df->datamark = df->data;
  df->datalimit = df->data+data_length;
  df->feedseq[0] = data_length;
}

static ssize_t scripted_read_callback
(wslay_event_context_ptr ctx,
 uint8_t *data, size_t len, const union wslay_event_msg_source *source,
 int *eof, void *user_data)
{
  struct scripted_data_feed *df = (struct scripted_data_feed*)source->data;
  size_t wlen = df->feedseq[df->seqidx] > len ? len : df->feedseq[df->seqidx];
  memcpy(data, df->datamark, wlen);
  df->datamark += wlen;
  if(wlen <= len) {
    ++df->seqidx;
  } else {
    df->feedseq[df->seqidx] -= wlen;
  }
  if(df->datamark == df->datalimit) {
    *eof = 1;
  }
  return wlen;
}

static ssize_t scripted_recv_callback(wslay_event_context_ptr ctx,
                                      uint8_t* data, size_t len,
                                      void *user_data)
{
  struct scripted_data_feed *df = ((struct my_user_data*)user_data)->df;
  size_t wlen = df->feedseq[df->seqidx] > len ? len : df->feedseq[df->seqidx];
  memcpy(data, df->datamark, wlen);
  df->datamark += wlen;
  if(wlen <= len) {
    ++df->seqidx;
  } else {
    df->feedseq[df->seqidx] -= wlen;
  }
  return wlen;
}

static ssize_t scripted_send_callback(wslay_event_context_ptr ctx,
                                      const uint8_t* data, size_t len,
                                      void *user_data)
{
  struct scripted_data_feed *df = ((struct my_user_data*)user_data)->df;
  size_t wlen = df->feedseq[df->seqidx] > len ? len : df->feedseq[df->seqidx];
  memcpy(df->datamark, data, wlen);
  df->datamark += wlen;
  if(wlen <= len) {
    ++df->seqidx;
  } else {
    df->feedseq[df->seqidx] -= wlen;
  }
  return wlen;
}

static ssize_t accumulator_send_callback(wslay_event_context_ptr ctx,
                                         const uint8_t *buf, size_t len,
                                         void* user_data)
{
  struct accumulator *acc = ((struct my_user_data*)user_data)->acc;
  assert(acc->length+len < sizeof(acc->buf));
  memcpy(acc->buf+acc->length, buf, len);
  acc->length += len;
  return len;
}

static ssize_t one_accumulator_send_callback(wslay_event_context_ptr ctx,
                                             const uint8_t *buf, size_t len,
                                             void* user_data)
{
  struct accumulator *acc = ((struct my_user_data*)user_data)->acc;
  assert(len > 0);
  memcpy(acc->buf+acc->length, buf, 1);
  acc->length += 1;
  return 1;
}

void test_wslay_event_send_fragmented_msg()
{
  wslay_event_context_ptr ctx;
  struct wslay_event_callbacks callbacks;
  struct my_user_data ud;
  struct accumulator acc;
  const char msg[] = "Hello";
  struct scripted_data_feed df;
  struct wslay_event_fragmented_msg arg;
  const uint8_t ans[] = {
    0x01, 0x03, 0x48, 0x65, 0x6c,
    0x80, 0x02, 0x6c, 0x6f
  };
  scripted_data_feed_init(&df, (const uint8_t*)msg, sizeof(msg)-1);
  df.feedseq[0] = 3;
  df.feedseq[1] = 2;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = accumulator_send_callback;
  memset(&acc, 0, sizeof(acc));
  ud.acc = &acc;
  wslay_event_context_server_init(&ctx, &callbacks, &ud);

  memset(&arg, 0, sizeof(arg));
  arg.opcode = WSLAY_TEXT_FRAME;
  arg.source.data = &df;
  arg.read_callback = scripted_read_callback;
  CU_ASSERT(0 == wslay_event_queue_fragmented_msg(ctx, &arg));
  CU_ASSERT(0 == wslay_event_send(ctx));
  CU_ASSERT_EQUAL(9, acc.length);
  CU_ASSERT(0 == memcmp(ans, acc.buf, acc.length));
  wslay_event_context_free(ctx);
}

void test_wslay_event_send_fragmented_msg_with_ctrl()
{
  int i;
  wslay_event_context_ptr ctx;
  struct wslay_event_callbacks callbacks;
  struct my_user_data ud;
  struct accumulator acc;
  const char msg[] = "Hello";
  struct scripted_data_feed df;
  struct wslay_event_fragmented_msg arg;
  struct wslay_event_msg ctrl_arg;
  const uint8_t ans[] = {
    0x01, 0x03, 0x48, 0x65, 0x6c, /* "Hel" */
    0x89, 0x00, /* unmasked ping */
    0x80, 0x02, 0x6c, 0x6f /* "lo" */
  };
  scripted_data_feed_init(&df, (const uint8_t*)msg, sizeof(msg)-1);
  df.feedseq[0] = 3;
  df.feedseq[1] = 2;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = one_accumulator_send_callback;
  memset(&acc, 0, sizeof(acc));
  ud.acc = &acc;
  wslay_event_context_server_init(&ctx, &callbacks, &ud);
  
  memset(&arg, 0, sizeof(arg));
  arg.opcode = WSLAY_TEXT_FRAME;
  arg.source.data = &df;
  arg.read_callback = scripted_read_callback;
  CU_ASSERT(0 == wslay_event_queue_fragmented_msg(ctx, &arg));
  CU_ASSERT(0 == wslay_event_send(ctx));

  memset(&ctrl_arg, 0, sizeof(ctrl_arg));
  ctrl_arg.opcode = WSLAY_PING;
  ctrl_arg.msg_length = 0;
  CU_ASSERT(0 == wslay_event_queue_msg(ctx, &ctrl_arg));
  for(i = 0; i < 10; ++i) {
    CU_ASSERT(0 == wslay_event_send(ctx));
  }
  CU_ASSERT(11 == acc.length);
  CU_ASSERT(0 == memcmp(ans, acc.buf, acc.length));
  wslay_event_context_free(ctx);
}

void test_wslay_event_send_ctrl_msg_first()
{
  wslay_event_context_ptr ctx;
  struct wslay_event_callbacks callbacks;
  struct my_user_data ud;
  struct accumulator acc;
  const char msg[] = "Hello";
  struct wslay_event_msg arg;
  const uint8_t ans[] = {
    0x89, 0x00, /* unmasked ping */
    0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f /* "Hello" */
  };
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = accumulator_send_callback;
  memset(&acc, 0, sizeof(acc));
  ud.acc = &acc;
  wslay_event_context_server_init(&ctx, &callbacks, &ud);
  
  memset(&arg, 0, sizeof(arg));
  arg.opcode = WSLAY_PING;
  arg.msg_length = 0;
  CU_ASSERT(0 == wslay_event_queue_msg(ctx, &arg));
  arg.opcode = WSLAY_TEXT_FRAME;
  arg.msg = (const uint8_t*)msg;
  arg.msg_length = 5;
  CU_ASSERT(0 == wslay_event_queue_msg(ctx, &arg));
  CU_ASSERT(0 == wslay_event_send(ctx));
  CU_ASSERT(9 == acc.length);
  CU_ASSERT(0 == memcmp(ans, acc.buf, acc.length));
  wslay_event_context_free(ctx);
}

void test_wslay_event_queue_close()
{
  wslay_event_context_ptr ctx;
  struct wslay_event_callbacks callbacks;
  struct my_user_data ud;
  struct accumulator acc;
  const char msg[] = "H";
  const uint8_t ans[] = {
    0x88, 0x03, 0x03, 0xf1, 0x48 /* "H" */
  };
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = accumulator_send_callback;
  memset(&acc, 0, sizeof(acc));
  ud.acc = &acc;
  wslay_event_context_server_init(&ctx, &callbacks, &ud);
  CU_ASSERT(0 == wslay_event_queue_close(ctx, WSLAY_CODE_MESSAGE_TOO_BIG,
                                         (const uint8_t*)msg, 1));
  CU_ASSERT(0 == wslay_event_send(ctx));
  CU_ASSERT(5 == acc.length);
  CU_ASSERT(0 == memcmp(ans, acc.buf, acc.length));
  wslay_event_context_free(ctx);
}

void test_wslay_event_queue_close_without_code()
{
  wslay_event_context_ptr ctx;
  struct wslay_event_callbacks callbacks;
  struct my_user_data ud;
  struct accumulator acc;
  const uint8_t ans[] = { 0x88, 0x00 };
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = accumulator_send_callback;
  memset(&acc, 0, sizeof(acc));
  ud.acc = &acc;
  wslay_event_context_server_init(&ctx, &callbacks, &ud);
  CU_ASSERT(0 == wslay_event_queue_close(ctx, 0, NULL, 0));
  CU_ASSERT(0 == wslay_event_send(ctx));
  CU_ASSERT(2 == acc.length);
  CU_ASSERT(0 == memcmp(ans, acc.buf, acc.length));
  wslay_event_context_free(ctx);
}

void test_wslay_event_reply_close()
{
  wslay_event_context_ptr ctx;
  struct wslay_event_callbacks callbacks;
  struct my_user_data ud;
  struct accumulator acc;
  /* Masked close frame with code = 1009, reason = "Hello" */
  const uint8_t msg[] = { 0x88u, 0x87u, 0x00u, 0x00u, 0x00u, 0x00u,
                          0x03, 0xf1, /* 1009 */
                          0x48, 0x65, 0x6c, 0x6c, 0x6f /* "Hello" */
  };
  const uint8_t ans[] = { 0x88u, 0x07u,
                          0x03, 0xf1, /* 1009 */
                          0x48, 0x65, 0x6c, 0x6c, 0x6f /* "Hello" */
  };
  struct scripted_data_feed df;
  scripted_data_feed_init(&df, (const uint8_t*)msg, sizeof(msg));
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.send_callback = accumulator_send_callback;
  callbacks.recv_callback = scripted_recv_callback;
  memset(&acc, 0, sizeof(acc));
  ud.df = &df;
  ud.acc = &acc;
  wslay_event_context_server_init(&ctx, &callbacks, &ud);
  CU_ASSERT(0 == wslay_event_recv(ctx));
  CU_ASSERT(0 == wslay_event_send(ctx));
  CU_ASSERT(9 == acc.length);
  CU_ASSERT(0 == memcmp(ans, acc.buf, acc.length));
  wslay_event_context_free(ctx);
}
