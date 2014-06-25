dnl# $Id: xdt-features.m4 22990 2006-09-02 11:33:28Z benny $
dnl#
dnl# Copyright (c) 2002-2006
dnl#         The Xfce development team. All rights reserved.
dnl#
dnl# Written for Xfce by Benedikt Meurer <benny@xfce.org>.
dnl#
dnl# This program is free software; you can redistribute it and/or modify
dnl# it under the terms of the GNU General Public License as published by
dnl# the Free Software Foundation; either version 2 of the License, or
dnl# (at your option) any later version.
dnl#
dnl# This program is distributed in the hope that it will be useful, but
dnl# WITHOUT ANY WARRANTY; without even the implied warranty of
dnl# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
dnl# General Public License for more details.
dnl#
dnl# You should have received a copy of the GNU General Public License
dnl# along with this program; if not, write to:
dnl#  The Free Software Foundation, Inc.
dnl#  59 Temple Place, Suite 330, Boston, MA
dnl#  02111-1307  USA
dnl#
dnl# xdt-depends
dnl#-----------
dnl#  Contains M4 macros to check for software dependencies.
dnl#  Partly based on prior work of the XDG contributors.
dnl#

dnl# We need a "recent" autoconf version
AC_PREREQ([2.53])



dnl# XDT_FEATURE_DEBUG([])
dnl#
AC_DEFUN([XDT_FEATURE_DEBUG],
[
  AC_ARG_ENABLE([debug],
    AS_HELP_STRING([--enable-debug[=yes|no|full]],
                   [Build with debugging support])
    AS_HELP_STRING([--disable-debug],
                   [Include no debugging support [default]]),
  [],[enable_debug=no])

  AC_MSG_CHECKING([whether to build with debugging support])
  if test x"${enable_debug}" != x"no"; then
    AC_DEFINE([DEBUG],[1],[Define for debugging support])

    if test x"${GCC}" = x"yes"; then
      xdt_cv_additional_CFLAGS="-Wall"
    fi
    xdt_cv_additional_CFLAGS="${xdt_cv_additional_CFLAGS} -DXFCE_DISABLE_DEPRECATED"
    
    if test x"${enable_debug}" = x"full"; then
      AC_DEFINE([DEBUG_TRACE],[1],[Define for tracing support])
      if test x"${GCC}" = x"yes"; then
        xdt_cv_additional_CFLAGS="-g3 -Wextra ${xdt_cv_additional_CFLAGS}"
      fi
      AC_MSG_RESULT([full])
    else
      if test x"${GCC}" = x"yes"; then
        xdt_cv_additional_CFLAGS="-g ${xdt_cv_additional_CFLAGS}"
      fi
      AC_MSG_RESULT([yes])
    fi

    CFLAGS="${CFLAGS} ${xdt_cv_additional_CFLAGS}"
    CXXFLAGS="${CXXFLAGS} ${xdt_cv_additional_CFLAGS}"
  else
    AC_MSG_RESULT([no])
  fi
])

dnl# BM_DEBUG_SUPPORT([])
dnl#
AC_DEFUN([BM_DEBUG_SUPPORT],
[
  dnl# --enable-debug
  AC_REQUIRE([XDT_FEATURE_DEBUG])

  dnl# --enable-profiling
  AC_ARG_ENABLE([profiling],
    AS_HELP_STRING([--enable-profiling],
                   [Generate extra code to write profile information])
    AS_HELP_STRING([--disable-profiling],
                   [No extra code for profiling (default)]),
    [],[enable_profiling=no])

  AC_MSG_CHECKING([whether to build with profiling support])
  if test x"${enable_profiling}" != x"no"; then
    CFLAGS="${CFLAGS} -pg"
    LDFLAGS="${LDFLAGS} -pg"
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
  fi

  dnl# --enable-gcov
  AC_ARG_ENABLE([gcov],
    AS_HELP_STRING([--enable-gcov],
              [compile with coverage profiling instrumentation (gcc only)])
    AS_HELP_STRING([--disable-gcov],
           [do not generate coverage profiling instrumentation (default)]),
    [],[enable_gcov=no])

  AC_MSG_CHECKING([whether to compile with coverage profiling instrumentation])
  if test x"${enable_gcov}" != x"no"; then
    CFLAGS="${CFLAGS} -fprofile-arcs -ftest-coverage"
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
  fi

  dnl# --disable-asserts
  AC_ARG_ENABLE([asserts],
    [AS_HELP_STRING([--disable-asserts],[Disable assertions [DANGEROUS]])],
    [],[enable_asserts=yes])

  AC_MSG_CHECKING([whether to disable assertions])
  if test x"${enable_asserts}" = x"no"; then
    AC_MSG_RESULT([yes])
    CPPFLAGS="${CPPFLAGS} -DG_DISABLE_CHECKS -DG_DISABLE_ASSERT"
    CPPFLAGS="${CPPFLAGS} -DG_DISABLE_CAST_CHECKS -DNDEBUG"
  else
    AC_MSG_RESULT([no])
    if test "x${ac_cv_header_assert_h}" = "x"; then
      test -z "${ac_cv_header_assert_h}"
      AC_CHECK_HEADERS([assert.h])
    fi
  fi

  dnl# --enable-final
  m4_ifdef([LT_PATH_LD],[
    AC_REQUIRE([LT_PATH_LD])
    test ! -z "${with_gnu_ld}"
  ],[
    AC_REQUIRE([AC_PROG_LD])
    test ! -z "${LD}"
  ])
  AC_ARG_ENABLE([final],
    [AS_HELP_STRING([--enable-final],[Build final version])],
    [],[enable_final=yes])

  AC_MSG_CHECKING([whether to build final version])
  if test x"${enable_final}" = x"yes"; then
    AC_MSG_RESULT([yes])
    AC_MSG_CHECKING([whether ${LD} accepts -O1])
    case `${LD} -O1 -v 2>&1 </dev/null` in
    *GNU* | *'with BFD'*)
      LDFLAGS="${LDFLAGS} -Wl,-O1"
      AC_MSG_RESULT([yes])
    	;;
    *)
      AC_MSG_RESULT([no])
    	;;
    esac
  else
    AC_MSG_RESULT([no])
  fi
])
