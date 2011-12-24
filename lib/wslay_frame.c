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
#include "wslay_frame.h"

#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

#include "wslay_session.h"

#ifdef WORDS_BIGENDIAN
uint64_t ntoh64(uint64_t x) { return x; }
uint64_t hton64(uint64_t x) { return x; }
#else // !WORDS_BIGENDIAN
uint64_t byteswap64(uint64_t x) {
  uint64_t v1 = ntohl(x & 0x00000000ffffffffllu);
  uint64_t v2 = ntohl(x >> 32);
  return (v1 << 32)|v2;
}
uint64_t ntoh64(uint64_t x) { return byteswap64(x); }
uint64_t hton64(uint64_t x) { return byteswap64(x); }
#endif // !WORDS_BIGENDIAN

#define wslay_min(A, B) (((A) < (B)) ? (A) : (B))

ssize_t wslay_frame_send(struct wslay_session *session,
                         struct wslay_iocb *iocb)
{
  if(iocb->data_length > iocb->payload_length) {
    return WSLAY_ERR_INVALID_ARGUMENT;
  }
  if(session->ostate == PREP_HEADER) {
    uint8_t *hdptr = session->oheader;
    memset(session->oheader, 0, sizeof(session->oheader));
    *hdptr |= (iocb->fin & 1u) << 7;
    *hdptr |= (iocb->rsv & 7u) << 4;
    *hdptr |= iocb->opcode & 0xfu;
    ++hdptr;
    *hdptr |= (iocb->mask & 1u) << 7;
    if(iocb->payload_length < 126) {
      *hdptr |= iocb->payload_length & 0x7fu;
      ++hdptr;
    } else if(iocb->payload_length < 32768) {
      uint16_t len = htons(iocb->payload_length);
      *hdptr |= 126;
      ++hdptr;
      memcpy(hdptr, &len, 2);
      hdptr += 2;
    } else if(iocb->payload_length < 9223372036854775808llu) {
      uint64_t len = hton64(iocb->payload_length);
      *hdptr |= 127;
      ++hdptr;
      memcpy(hdptr, &len, 8);
      hdptr += 8;
    } else {
      /* Too large payload length */
      return WSLAY_ERR_INVALID_ARGUMENT;
    }
    if(iocb->mask & 1u) {
      if(session->callbacks.gen_mask_callback(session->omaskkey, 4,
                                              session->user_data) != 4) {
        return WSLAY_ERR_INVALID_CALLBACK;
      } else {
        session->omask = 1;
        memcpy(hdptr, session->omaskkey, 4);
        hdptr += 4;
      }
    }
    session->oom.fin = iocb->fin;
    session->oom.opcode = iocb->opcode;
    session->oom.rsv = iocb->rsv;

    session->ostate = SEND_HEADER;
    session->oheadermark = session->oheader;
    session->oheaderlimit = hdptr;
    session->opayloadlen = iocb->payload_length;
    session->opayloadoff = 0;
  }
  if(session->ostate == SEND_HEADER) {
    ptrdiff_t len = session->oheaderlimit-session->oheadermark;
    ssize_t r;
    r = session->callbacks.send_callback(session->oheadermark, len,
                                         session->user_data);
    if(r > 0) {
      if(r > len) {
        return WSLAY_ERR_INVALID_CALLBACK;
      } else {
        session->oheadermark += r;
        if(session->oheadermark == session->oheaderlimit) {
          session->ostate = SEND_PAYLOAD;
        }
      }
    } else {
      return WSLAY_ERR_WANT_WRITE;
    }
  }
  if(session->ostate == SEND_PAYLOAD) {
    size_t totallen = 0;
    if(iocb->data_length > 0) {
      if(session->omask) {
        uint8_t temp[4096];
        const uint8_t *datamark = iocb->data,
          *datalimit = iocb->data+iocb->data_length;
        while(datamark < datalimit) {
          const uint8_t *writelimit = datamark+
            wslay_min(sizeof(temp), datalimit-datamark);
          size_t writelen = writelimit-datamark;
          ssize_t r;
          int i;
          for(i = 0; i < writelen; ++i) {
            temp[i] = datamark[i]^session->omaskkey[(session->opayloadoff+i)%4];
          }
          r = session->callbacks.send_callback(temp, writelen,
                                               session->user_data);
          if(r > 0) {
            if(r > writelen) {
              return WSLAY_ERR_INVALID_CALLBACK;
            } else {
              datamark += r;
              session->opayloadoff += r;
              totallen += r;
            }
          } else {
            if(totallen > 0) {
              break;
            } else {
              return WSLAY_ERR_WANT_WRITE;
            }
          }
        }
      } else {
        ssize_t r;
        r = session->callbacks.send_callback(iocb->data, iocb->data_length,
                                             session->user_data);
        if(r > 0) {
          if(r > iocb->data_length) {
            return WSLAY_ERR_INVALID_CALLBACK;
          } else {
            session->opayloadoff += r;
            totallen = r;
          }
        } else {
          return WSLAY_ERR_WANT_WRITE;
        }
      }
    }
    if(session->opayloadoff == session->opayloadlen) {
      session->ostate = PREP_HEADER;
    }
    return totallen;
  }
  return WSLAY_ERR_INVALID_ARGUMENT;
}

static void wslay_shift_ibuf(struct wslay_session *session)
{
  ptrdiff_t len = session->ibuflimit-session->ibufmark;
  memmove(session->ibuf, session->ibufmark, len);
  session->ibuflimit = session->ibuf+len;
  session->ibufmark = session->ibuf;
}

static ssize_t wslay_recv(struct wslay_session *session)
{
  ssize_t r;
  if(session->ibufmark != session->ibuf) {
    wslay_shift_ibuf(session);
  }
  r = session->callbacks.recv_callback
    (session->ibuflimit,
     session->ibuf+sizeof(session->ibuf)-session->ibuflimit,
     session->user_data);
  if(r > 0) {
    session->ibuflimit += r;
  } else {
    r = WSLAY_ERR_WANT_READ;
  }
  return r;
}

#define WSLAY_AVAIL_IBUF(session) (session->ibuflimit-session->ibufmark)

ssize_t wslay_frame_recv(struct wslay_session *session,
                         struct wslay_iocb *iocb)
{
  ssize_t r;
  if(session->istate == RECV_HEADER1) {
    uint8_t fin, opcode, rsv, payloadlen;
    if(WSLAY_AVAIL_IBUF(session) < session->ireqread) {
      if((r = wslay_recv(session)) <= 0) {
        return r;
      }
    }
    if(WSLAY_AVAIL_IBUF(session) < session->ireqread) {
      return WSLAY_ERR_WANT_READ;
    }
    fin = (session->ibufmark[0] & (1 << 7)) > 0;
    rsv = (session->ibufmark[0] >> 4) & 0x7u;
    opcode = session->ibufmark[0] & 0xfu;
    session->iom.opcode = opcode;
    session->iom.fin = fin;
    session->iom.rsv = rsv;
    ++session->ibufmark;
    session->imask = (session->ibufmark[0] & (1 << 7)) > 0;
    payloadlen = session->ibufmark[0] & 0x7fu;
    ++session->ibufmark;
    if(payloadlen == 126) {
      session->istate = RECV_EXT_PAYLOADLEN;
      session->ireqread = 2;
    } else if(payloadlen == 127) {
      session->istate = RECV_EXT_PAYLOADLEN;
      session->ireqread = 8;
    } else {
      session->ipayloadlen = payloadlen;
      session->ipayloadoff = 0;
      if(session->imask) {
        session->istate = RECV_MASKKEY;
        session->ireqread = 4;
      } else {
        session->istate = RECV_PAYLOAD;
      }
    }
  }
  if(session->istate == RECV_EXT_PAYLOADLEN) {
    if(WSLAY_AVAIL_IBUF(session) < session->ireqread) {
      if((r = wslay_recv(session)) <= 0) {
        return r;
      }
      if(WSLAY_AVAIL_IBUF(session) < session->ireqread) {
        return WSLAY_ERR_WANT_READ;
      }
    }
    session->ipayloadlen = 0;
    session->ipayloadoff = 0;
    memcpy((uint8_t*)&session->ipayloadlen+(8-session->ireqread),
           session->ibufmark, session->ireqread);
    session->ipayloadlen = ntoh64(session->ipayloadlen);
    session->ibufmark += session->ireqread;
    if(session->ipayloadlen & (1LL << (session->ireqread*8-1))) {
      return WSLAY_ERR_PROTO;
    }
    if(session->imask) {
      session->istate = RECV_MASKKEY;
      session->ireqread = 4;
    } else {
      session->istate = RECV_PAYLOAD;
    }
  }
  if(session->istate == RECV_MASKKEY) {
    if(WSLAY_AVAIL_IBUF(session) < session->ireqread) {
      if((r = wslay_recv(session)) <= 0) {
        return r;
      }
      if(WSLAY_AVAIL_IBUF(session) < session->ireqread) {
        return WSLAY_ERR_WANT_READ;
      }
    }
    memcpy(session->imaskkey, session->ibufmark, 4);
    session->ibufmark += 4;
    session->istate = RECV_PAYLOAD;
  }
  if(session->istate == RECV_PAYLOAD) {
    uint8_t *readlimit, *readmark;
    uint64_t rempayloadlen = session->ipayloadlen-session->ipayloadoff;
    if(WSLAY_AVAIL_IBUF(session) == 0 && rempayloadlen > 0) {
      if((r = wslay_recv(session)) <= 0) {
        return r;
      }
    }
    readmark = session->ibufmark;
    readlimit = WSLAY_AVAIL_IBUF(session) < rempayloadlen ?
      session->ibuflimit : session->ibufmark+rempayloadlen;
    if(session->imask) {
      for(; session->ibufmark != readlimit;
          ++session->ibufmark, ++session->ipayloadoff) {
        session->ibufmark[0] ^= session->imaskkey[session->ipayloadoff % 4];
      }
    } else {
      session->ibufmark = readlimit;
      session->ipayloadoff += readlimit-readmark;
    }
    iocb->fin = session->iom.fin;
    iocb->rsv = session->iom.rsv;
    iocb->opcode = session->iom.opcode;
    iocb->payload_length = session->ipayloadlen;
    iocb->mask = session->imask;
    iocb->data = readmark;
    iocb->data_length = session->ibufmark-readmark;
    if(session->ipayloadlen == session->ipayloadoff) {
      session->istate = RECV_HEADER1;
      session->ireqread = 2;
    }
    return iocb->data_length;
  }
  return WSLAY_ERR_INVALID_ARGUMENT;
}
