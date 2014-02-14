Wslay - The WebSocket library
=============================

[![Build Status](https://travis-ci.org/jirihnidek/wslay.png?branch=master)](https://travis-ci.org/jirihnidek/wslay)
[![Coverage Status](https://coveralls.io/repos/jirihnidek/wslay/badge.png?branch=master)](https://coveralls.io/r/jirihnidek/wslay?branch=master)

Project Web: http://wslay.sourceforge.net/

Wslay is a WebSocket library written in C.
It implements the protocol version 13 described in
RFC 6455 http://tools.ietf.org/html/rfc6455.
This library offers 2 levels of API:
event-based API and frame-based low-level API. For event-based API, it
is suitable for non-blocking reactor pattern style. You can set
callbacks in various events. For frame-based API, you can send
WebSocket frame directly. Wslay only supports data transfer part of
WebSocket protocol and does not perform opening handshake in HTTP.

Wslay supports:

* Text/Binary messages.
* Automatic ping reply.
* Callback interface.
* External event loop.

Wslay does not perform any I/O operations for its own. Instead, it
offers callbacks for them. This makes Wslay independent on any I/O
frameworks, SSL, sockets, etc.  This makes Wslay protable across
various platforms and the application authors can choose freely I/O
frameworks.

See Autobahn test reports:

* Server: http://wslay.sourceforge.net/autobahn/reports/servers/index.html
* Client: http://wslay.sourceforge.net/autobahn/reports/clients/index.html

Optional Requirements
---------------------

* Sphinx http://sphinx.pocoo.org/ is used to generate man pages.
* CUnit http://cunit.sourceforge.net/ is used to build and run the unit tests
* Nettle http://www.lysator.liu.se/~nisse/nettle/ is used in examples of Wslay
* OpenSSL http://www.openssl.org/ is sed in example of Wslay

Building
--------

Building is easy:

    $ mkdir ./build
    $ cd ./build
    $ cmake ../
    $ make

Testing
-------

To execute all unit tests you have to type:

    $ make test

Documentation
-------------

The documentation is generated during build, when Sphinx is installed. You
can also find documentation including simple tutorial at:
http://wslay.sourceforge.net/
