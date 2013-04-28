## Copyright 2012-2013 Mo McRoberts.
##
##  Licensed under the Apache License, Version 2.0 (the "License");
##  you may not use this file except in compliance with the License.
##  You may obtain a copy of the License at
##
##      http://www.apache.org/licenses/LICENSE-2.0
##
##  Unless required by applicable law or agreed to in writing, software
##  distributed under the License is distributed on an "AS IS" BASIS,
##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
##  See the License for the specific language governing permissions and
##  limitations under the License.

AC_INIT([locksmith],[develop])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])
AM_MAINTAINER_MODE

AC_CONFIG_HEADER([config.h])

BT_PROG_XCODE
AC_PROG_CC([clang gcc c99 cc])
BT_PROG_CC_WARN

developer_CPPFLAGS='-O0 -g'

if test x"$VERSION" = x"develop" ; then
   AC_MSG_RESULT([enabling developer-mode CPPFLAGS: $developer_CPPFLAGS])
   AM_CPPFLAGS="$AM_CPPFLAGS $developer_CPPFLAGS"
fi

PKG_CHECK_MODULES([libcrypto],[libcrypto >= 0.9.8],[
	CPPFLAGS="$CPPFLAGS $libcrypto_CFLAGS"
	LIBS="$LIBS $libcrypto_LIBS"
],[AC_MSG_ERROR([cannot find OpenSSL's libcrypto using pkg-config; please ensure both pkg-config and OpenSSL development files are present, and if necessary set the PKG_CONFIG_PATH environment variable.])])

AC_SUBST([CPPFLAGS])
AC_SUBST([LIBS])

AC_CHECK_HEADERS([unistd.h inttypes.h stdint.h sys/stat.h sys/types.h io.h])
AC_HEADER_TIME
AC_CHECK_FUNCS([strrchr getopt])

AC_CONFIG_FILES([Makefile
m4/Makefile
])

AC_OUTPUT


