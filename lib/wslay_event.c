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
#include "wslay_event.h"

#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "wslay_stack.h"
#include "wslay_queue.h"

static ssize_t wslay_event_frame_recv_callback(uint8_t *buf, size_t len,
                                               void *user_data)
{
  struct wslay_event_frame_user_data *e =
    (struct wslay_event_frame_user_data*)user_data;
  return e->ctx->callbacks.recv_callback(e->ctx, buf, len, e->user_data);
}

static ssize_t wslay_event_frame_send_callback(const uint8_t *data, size_t len,
                                               void *user_data)
{
  struct wslay_event_frame_user_data *e =
    (struct wslay_event_frame_user_data*)user_data;
  return e->ctx->callbacks.send_callback(e->ctx, data, len, e->user_data);
}

static ssize_t wslay_event_frame_genmask_callback(uint8_t *buf, size_t len,
                                                  void *user_data)
{
  struct wslay_event_frame_user_data *e =
    (struct wslay_event_frame_user_data*)user_data;
  return e->ctx->callbacks.genmask_callback(e->ctx, buf, len, e->user_data);
}

static int wslay_byte_chunk_init(struct wslay_byte_chunk **chunk, size_t len)
{
  *chunk = (struct wslay_byte_chunk*)malloc(sizeof(struct wslay_byte_chunk));
  if(*chunk == NULL) {
    return WSLAY_ERR_NOMEM;
  }
  memset(*chunk, 0, sizeof(struct wslay_byte_chunk));
  if(len) {
    (*chunk)->data = (uint8_t*)malloc(len);
    (*chunk)->data_length = len;
  }
  return 0;
}

static void wslay_byte_chunk_free(struct wslay_byte_chunk *c)
{
  if(!c) {
    return;
  }
  free(c->data);
  free(c);
}

static void wslay_byte_chunk_copy(struct wslay_byte_chunk *c, size_t off,
                                  const uint8_t *data, size_t data_length)
{
  memcpy(c->data+off, data, data_length);
}

static void wslay_imsg_set(struct wslay_imsg *m, uint8_t fin, uint8_t rsv,
                          uint8_t opcode)
{
  m->fin = fin;
  m->rsv = rsv;
  m->opcode = opcode;
  m->msg_length = 0;
}
                           
static void wslay_imsg_chunks_free(struct wslay_imsg *m)
{
  if(!m->chunks) {
    return;
  }
  while(!wslay_queue_empty(m->chunks)) {
    wslay_byte_chunk_free(wslay_queue_top(m->chunks));
    wslay_queue_pop(m->chunks);
  }
}

static int wslay_imsg_append_chunk(struct wslay_imsg *m, size_t len)
{
  if(len == 0) {
    return 0;
  } else {
    int r;
    struct wslay_byte_chunk *chunk;
    if((r = wslay_byte_chunk_init(&chunk, len)) != 0) {
      return r;
    }
    if((r = wslay_queue_push(m->chunks, chunk)) != 0) {
      return r;
    }
    m->msg_length += len;
    return 0;
  }
}

static int wslay_omsg_init(struct wslay_omsg **m, uint8_t opcode,
                           const uint8_t *msg, size_t msg_length)
{
  *m = (struct wslay_omsg*)malloc(sizeof(struct wslay_omsg));
  if(!*m) {
    return WSLAY_ERR_NOMEM;
  }
  memset(*m, 0, sizeof(struct wslay_omsg));
  (*m)->opcode = opcode;
  if(msg_length) {
    (*m)->data = (uint8_t*)malloc(msg_length);
    if(!(*m)->data) {
      free(*m);
      return WSLAY_ERR_NOMEM;
    }
    memcpy((*m)->data, msg, msg_length);
    (*m)->data_length = msg_length;
  }
  return 0;
}

static void wslay_omsg_free(struct wslay_omsg *m)
{
  if(!m) {
    return;
  }
  free(m->data);
  free(m);
}

static uint8_t* wslay_flatten_queue(struct wslay_queue *queue, size_t len)
{
  if(len == 0) {
    return NULL;
  } else {
    size_t off = 0;
    uint8_t *buf = (uint8_t*)malloc(len);
    if(!buf) {
      return NULL;
    }
    while(!wslay_queue_empty(queue)) {
      struct wslay_byte_chunk *chunk = wslay_queue_top(queue);
      memcpy(buf+off, chunk->data, chunk->data_length);
      off += chunk->data_length;
      wslay_byte_chunk_free(chunk);
      wslay_queue_pop(queue);
      assert(off <= len);
    }
    assert(len == off);
    return buf;
  }
}

int wslay_event_queue_close(wslay_event_context_ptr ctx)
{
  struct wslay_event_queue_msg_arg arg = {
    WSLAY_CONNECTION_CLOSE, NULL, 0
  };
  return wslay_event_queue_msg(ctx, &arg);
}

int wslay_event_queue_msg(wslay_event_context_ptr ctx,
                          const struct wslay_event_queue_msg_arg *arg)
{
  int r;
  struct wslay_omsg *omsg;
  if((r = wslay_omsg_init(&omsg, arg->opcode,
                          arg->msg, arg->msg_length)) != 0) {
    return r;
  }
  if((r = wslay_queue_push(ctx->send_queue, omsg)) != 0) {
    return r;
  }
  return 0;
}

int wslay_event_context_init(wslay_event_context_ptr *ctx,
                             const struct wslay_event_callbacks *callbacks,
                             void *user_data)
{
  int i, r;
  struct wslay_frame_callbacks frame_callbacks = {
    wslay_event_frame_send_callback,
    wslay_event_frame_recv_callback,
    wslay_event_frame_genmask_callback
  };
  *ctx = (wslay_event_context_ptr)malloc(sizeof(struct wslay_event_context));
  if(!*ctx) {
    return WSLAY_ERR_NOMEM;
  }
  memset(*ctx, 0, sizeof(struct wslay_event_context));
  (*ctx)->callbacks = *callbacks;
  (*ctx)->user_data = user_data;
  (*ctx)->frame_user_data.ctx = *ctx;
  (*ctx)->frame_user_data.user_data = user_data;
  if((r = wslay_frame_context_init(&(*ctx)->frame_ctx, &frame_callbacks,
                                   &(*ctx)->frame_user_data)) != 0) {
    wslay_event_context_free(*ctx);
    return r;
  }
  (*ctx)->read_enabled = (*ctx)->write_enabled = 1;
  (*ctx)->send_queue = wslay_queue_new();
  if(!(*ctx)->send_queue) {
    wslay_event_context_free(*ctx);
    return WSLAY_ERR_NOMEM;
  }
  (*ctx)->imsgs[0].opcode = 0xffu;
  for(i = 0; i < 2; ++i) {
    (*ctx)->imsgs[i].chunks = wslay_queue_new();
    if(!(*ctx)->imsgs[i].chunks) {
      wslay_event_context_free(*ctx);
      return WSLAY_ERR_NOMEM;
    }
  }
  (*ctx)->imsg = &(*ctx)->imsgs[0];
  return 0;
}

void wslay_event_context_free(wslay_event_context_ptr ctx)
{
  int i;
  if(!ctx) {
    return;
  }
  for(i = 0; i < 2; ++i) {
    wslay_imsg_chunks_free(&ctx->imsgs[i]);
    wslay_queue_free(ctx->imsgs[i].chunks);
  }
  if(ctx->send_queue) {
    while(!wslay_queue_empty(ctx->send_queue)) {
      wslay_omsg_free(wslay_queue_top(ctx->send_queue));
      wslay_queue_pop(ctx->send_queue);
    }
    wslay_queue_free(ctx->send_queue);
  }
  wslay_frame_context_free(ctx->frame_ctx);
  free(ctx);
}

static void wslay_event_call_on_frame_recv_start_callback
(wslay_event_context_ptr ctx, const struct wslay_frame_iocb *iocb)
{
  if(ctx->callbacks.on_frame_recv_start_callback) {
    struct wslay_event_on_frame_recv_start_arg arg;
    arg.fin = iocb->fin;
    arg.rsv = iocb->rsv;
    arg.opcode = iocb->opcode;
    arg.payload_length = iocb->payload_length;
    ctx->callbacks.on_frame_recv_start_callback(ctx, &arg, ctx->user_data);
  }
}

static void wslay_event_call_on_frame_recv_chunk_callback
(wslay_event_context_ptr ctx, const struct wslay_frame_iocb *iocb)
{
  if(ctx->callbacks.on_frame_recv_chunk_callback) {
    struct wslay_event_on_frame_recv_chunk_arg arg = {
      iocb->data, iocb->data_length
    };
    ctx->callbacks.on_frame_recv_chunk_callback(ctx, &arg, ctx->user_data);
  }
};

static void wslay_event_call_on_frame_recv_end_callback
(wslay_event_context_ptr ctx)
{
  if(ctx->callbacks.on_frame_recv_end_callback) {
    ctx->callbacks.on_frame_recv_end_callback(ctx, ctx->user_data);
  }
}

int wslay_event_recv(wslay_event_context_ptr ctx)
{
  struct wslay_frame_iocb iocb;
  ssize_t r;
  while(!ctx->abort_run && ctx->read_enabled) {
    memset(&iocb, 0, sizeof(iocb));
    r = wslay_frame_recv(ctx->frame_ctx, &iocb);
    if(r >= 0) {
      struct wslay_byte_chunk *chunk;
      /* We only allow rsv == 0 ATM. */
      if(iocb.rsv != 0) {
        ctx->read_enabled = 0;
        if((r = wslay_event_queue_close(ctx)) != 0) {
          return r;
        }
        break;
      }
      if(ctx->imsg->opcode == 0xffu) {
        if(iocb.opcode == WSLAY_TEXT_FRAME ||
           iocb.opcode == WSLAY_BINARY_FRAME ||
           iocb.opcode == WSLAY_CONNECTION_CLOSE ||
           iocb.opcode == WSLAY_PING ||
           iocb.opcode == WSLAY_PONG) {
          wslay_imsg_set(ctx->imsg, iocb.fin, iocb.rsv, iocb.opcode);
          ctx->ipayloadlen = iocb.payload_length;
          wslay_event_call_on_frame_recv_start_callback(ctx, &iocb);
          if((r = wslay_imsg_append_chunk(ctx->imsg,
                                          iocb.payload_length)) != 0) {
            return r;
          }
        } else {
          ctx->read_enabled = 0;
          if((r = wslay_event_queue_close(ctx)) != 0) {
            return r;
          }
          break;
        }
      } else if(ctx->ipayloadlen == 0 && ctx->ipayloadoff == 0) {
        if(iocb.opcode == WSLAY_CONTINUATION_FRAME) {
          ctx->imsg->fin = iocb.fin;
        } else if(iocb.opcode == WSLAY_CONNECTION_CLOSE ||
                  iocb.opcode == WSLAY_PING ||
                  iocb.opcode == WSLAY_PONG) {
          ctx->imsg = &ctx->imsgs[1];
          wslay_imsg_set(ctx->imsg, iocb.fin, iocb.rsv, iocb.opcode);
        } else {
          ctx->read_enabled = 0;
          if((r = wslay_event_queue_close(ctx)) != 0) {
            return r;
          }
          break;
        }
        if((r = wslay_imsg_append_chunk(ctx->imsg, iocb.payload_length)) != 0) {
          return r;
        }
        ctx->ipayloadlen = iocb.payload_length;
        wslay_event_call_on_frame_recv_start_callback(ctx, &iocb);
      }
      wslay_event_call_on_frame_recv_chunk_callback(ctx, &iocb);
      if(iocb.data_length > 0) {
        chunk = wslay_queue_tail(ctx->imsg->chunks);
        wslay_byte_chunk_copy(chunk, ctx->ipayloadoff,
                              iocb.data, iocb.data_length);
        ctx->ipayloadoff += iocb.data_length;
      }
      if(ctx->ipayloadoff == ctx->ipayloadlen) {
        wslay_event_call_on_frame_recv_end_callback(ctx);
        if(ctx->imsg->fin) {
          if(ctx->callbacks.on_msg_recv_callback) {
            struct wslay_event_on_msg_recv_arg arg;
            uint8_t *msg = wslay_flatten_queue(ctx->imsg->chunks,
                                               ctx->imsg->msg_length);
            if(ctx->imsg->msg_length && !msg) {
              return WSLAY_ERR_NOMEM;
            }
            arg.rsv = ctx->imsg->rsv;
            arg.opcode = ctx->imsg->opcode;
            arg.msg = msg;
            arg.msg_length = ctx->imsg->msg_length;
            ctx->error = 0;
            ctx->callbacks.on_msg_recv_callback(ctx, &arg, ctx->user_data);
            free(msg);
          }
          ctx->imsg->opcode = 0xffu;
          wslay_imsg_chunks_free(ctx->imsg);
          if(ctx->imsg == &ctx->imsgs[1]) {
            ctx->imsg = &ctx->imsgs[0];
          }
        }
        ctx->ipayloadlen = ctx->ipayloadoff = 0;
      }
    } else {
      if(r == WSLAY_ERR_WANT_READ) {
        if(ctx->error == WSLAY_ERR_IO || ctx->eof) {
          ctx->read_enabled = 0;
          if((r = wslay_event_queue_close(ctx)) != 0) {
            return r;
          }
        }
      } else {
        ctx->read_enabled = 0;
        if((r = wslay_event_queue_close(ctx)) != 0) {
          return r;
        }
      }
      break;
    }
  }
  /* TODO handle malloc failure */
  return 0;
}

int wslay_event_send(wslay_event_context_ptr ctx)
{
  struct wslay_frame_iocb iocb;
  ssize_t r;
  while(!ctx->abort_run && ctx->write_enabled &&
        (!wslay_queue_empty(ctx->send_queue) || ctx->omsg)) {
    if(!ctx->omsg) {
      ctx->omsg = wslay_queue_top(ctx->send_queue);
      wslay_queue_pop(ctx->send_queue);
      ctx->opayloadlen = ctx->omsg->data_length;
      ctx->opayloadoff = 0;
    }
    memset(&iocb, 0, sizeof(iocb));
    /* TODO No fragmentation */
    iocb.fin = 1;
    iocb.opcode = ctx->omsg->opcode;
    /* TODO No mask */
    iocb.mask = 0;
    iocb.data = ctx->omsg->data+ctx->opayloadoff;
    iocb.data_length = ctx->opayloadlen-ctx->opayloadoff;
    iocb.payload_length = ctx->opayloadlen;
    r = wslay_frame_send(ctx->frame_ctx, &iocb);
    if(r >= 0) {
      ctx->opayloadoff += r;
      if(ctx->opayloadoff == ctx->opayloadlen) {
        if(ctx->omsg->opcode == WSLAY_CONNECTION_CLOSE) {
          ctx->write_enabled = 0;
        }
        wslay_omsg_free(ctx->omsg);
        ctx->omsg = NULL;
      }
    } else {
      if(r == WSLAY_ERR_WANT_WRITE) {
        if(ctx->error == WSLAY_ERR_IO) {
          ctx->write_enabled = 0;
          ctx->abort_run = 1;
          /* TODO Return error code, instead of using abort_run? */
        }
      } else {
        ctx->write_enabled = 0;
        ctx->abort_run = 1;
        /* TODO Return error code, instead of using abort_run? */
      }
      break;
    }
  }
  return 0;
}

void wslay_event_set_eof(wslay_event_context_ptr ctx, int val)
{
  ctx->eof = val;
}

void wslay_event_set_error(wslay_event_context_ptr ctx, int val)
{
  ctx->error = val;
}

int wslay_event_want_read(wslay_event_context_ptr ctx)
{
  return ctx->read_enabled;
}

int wslay_event_want_write(wslay_event_context_ptr ctx)
{
  return ctx->write_enabled &&
    (!wslay_queue_empty(ctx->send_queue) || ctx->omsg);
}

void wslay_event_set_read_enabled(wslay_event_context_ptr ctx, int val)
{
  ctx->read_enabled = val;
}

void wslay_event_set_write_enabled(wslay_event_context_ptr ctx, int val)
{
  ctx->write_enabled = val;
}

int wslay_event_get_read_enabled(wslay_event_context_ptr ctx)
{
  return ctx->read_enabled;
}

int wslay_event_get_write_enabled(wslay_event_context_ptr ctx)
{
  return ctx->write_enabled;
}

void wslay_event_set_abort(wslay_event_context_ptr ctx, int val)
{
  ctx->abort_run = val;
}

int wslay_event_get_abort(wslay_event_context_ptr ctx)
{
  return ctx->abort_run;
}
