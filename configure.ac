dnl The MIT License

dnl Copyright (c) 2011 Tatsuhiro Tsujikawa

dnl Permission is hereby granted, free of charge, to any person obtaining
dnl a copy of this software and associated documentation files (the
dnl "Software"), to deal in the Software without restriction, including
dnl without limitation the rights to use, copy, modify, merge, publish,
dnl distribute, sublicense, and/or sell copies of the Software, and to
dnl permit persons to whom the Software is furnished to do so, subject to
dnl the following conditions:

dnl The above copyright notice and this permission notice shall be
dnl included in all copies or substantial portions of the Software.

dnl THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
dnl EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
dnl MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
dnl NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
dnl LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
dnl OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
dnl WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
AC_PREREQ(2.61)
LT_PREREQ([2.4.2])
AC_INIT([wslay], [0.0.1], [t-tujikawa@users.sourceforge.net])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE()
AC_CONFIG_HEADERS([config.h])

dnl Checks for programs
AC_PROG_CC
AM_PROG_LIBTOOL

AC_CONFIG_FILES([
  Makefile
  lib/Makefile
  lib/libwslay.pc
  lib/includes/Makefile
  tests/Makefile
])
AC_OUTPUT