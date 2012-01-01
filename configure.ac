AC_INIT([keytool],[0.1.0])
AM_INIT_AUTOMAKE([foreign])
AM_MAINTAINER_MODE

developer_CPPFLAGS='-W -Wall -O0 -g'

if test x"$VERSION" = x"develop" ; then
   AC_MSG_RESULT([enabling developer-mode CPPFLAGS: $developer_CPPFLAGS])
   CPPFLAGS="$CPPFLAGS $developer_CPPFLAGS"
fi

AC_PROG_CC

PKG_CHECK_MODULES([libcrypto],[libcrypto >= 0.9.8],[
	CPPFLAGS="$CPPFLAGS $libcrypto_CFLAGS"
	LIBS="$LIBS $libcrypto_LIBS"
],[AC_MSG_ERROR([cannot find OpenSSL's libcrypto using pkg-config; please ensure both pkg-config and OpenSSL development files are present, and if necessary set the PKG_CONFIG_PATH environment variable.])])

AC_SUBST([CPPFLAGS])
AC_SUBST([LIBS])

AC_CHECK_HEADERS([unistd.h inttypes.h stdint.h sys/stat.h sys/types.h])
AC_HEADER_TIME
AC_CHECK_FUNCS([strrchr])

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT


