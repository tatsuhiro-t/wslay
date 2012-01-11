.. highlight:: c

wslay_event_queue_msg
=====================

SYNOPSIS
--------

#include <wslay/wslay.h>

.. c:function:: int wslay_event_queue_msg(wslay_event_context_ptr ctx, const struct wslay_event_msg *arg)

DESCRIPTION
-----------

:c:func:`wslay_event_queue_msg` queues message specified in *arg*.
The *struct wslay_event_msg* is defined as::

  struct wslay_event_msg {
      uint8_t        opcode;
      const uint8_t *msg;
      size_t         msg_length;
  };

The *opcode* member is opcode of the message.
The *msg* member is the pointer to the message data.
The *msg_length* member is the length of message data.

This function supports both control and non-control messages and
the given message is sent without fragmentation.
If fragmentation is needed, use :c:func:`wslay_event_queue_fragmented_msg`
function instead.

This function just queues a message and does not send it.
:c:func:`wslay_event_send` function call sends these queued messages.

RETURN VALUE
------------

:c:func:`wslay_event_queue_msg` returns 0 if it succeeds, or returns
the following negative error codes:

**WSLAY_ERR_NO_MORE_MSG**
  Could not queue given message. The one of
  possible reason is that close control frame has been
  queued/sent and no further queueing message is not allowed.

**WSLAY_ERR_INVALID_ARGUMENT**
  The given message is invalid.

**WSLAY_ERR_NOMEM**
  Out of memory.

SEE ALSO
--------

:c:func:`wslay_event_queue_fragmented_msg`,
:c:func:`wslay_event_queue_close`
