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
#include "wslay_session.h"

#include <string.h>

static void wslay_opcode_memo_init(struct wslay_opcode_memo *om)
{
  om->opcode = WSLAY_BAD_FLAG;
}

int wslay_session_init(struct wslay_session *session,
                       const struct wslay_callbacks *callbacks,
                       void *user_data)
{
  int i;
  memset(session, 0, sizeof(struct wslay_session));
  for(i = 0; i < 2; ++i) {
    wslay_opcode_memo_init(&session->iom[i]);
  }
  session->iomptr = &session->iom[0];
  session->istate = RECV_HEADER1;
  session->ireqread = 2;
  for(i = 0; i < 2; ++i) {
    wslay_opcode_memo_init(&session->oom[i]);
  }
  session->oomptr = &session->oom[0];
  session->ostate = PREP_HEADER;
  session->user_data = user_data;
  session->ibufmark = session->ibuflimit = session->ibuf;

  session->callbacks = *callbacks;
  return 0;
}
