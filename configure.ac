AC_PREREQ([2.65])
AC_INIT([pax-utils], [git])
AC_CONFIG_AUX_DIR([autotools])
AM_INIT_AUTOMAKE([1.11 dist-xz no-dist-gzip silent-rules -Wall])
AM_SILENT_RULES([yes]) # AM_INIT_AUTOMAKE([silent-rules]) is broken atm
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([autotools/m4])

AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC_C99
AM_PROG_CC_C_O
AM_PROG_AR
LT_INIT
PKG_PROG_PKG_CONFIG

gl_EARLY
gl_INIT

AC_ARG_WITH([caps], [AS_HELP_STRING([--with-caps], [build with capabilities])])
AS_IF([test "x$with_caps" = "xyes"], [
	PKG_CHECK_MODULES(LIBCAP, libcap)
	CPPFLAGS="$CPPFLAGS $LIBCAP_CFLAGS -DWANT_SYSCAP"
	LIBS="$LIBS $LIBCAP_LIBS"
])

AC_ARG_WITH([debug], [AS_HELP_STRING([--with-debug], [enable debug code])])
AS_IF([test "x$with_debug" = "xyes"], [
	CPPFLAGS="$CPPFLAGS -DEBUG"
])

AC_ARG_WITH([python], [AS_HELP_STRING([--with-python], [use lddtree.py])])
AM_CONDITIONAL([USE_PYTHON], [test "x$with_python" = "xyes"])

AC_ARG_WITH([seccomp], [AS_HELP_STRING([--with-seccomp], [build with seccomp])])
AS_IF([test "x$with_seccomp" = "xyes"], [
	CPPFLAGS="$CPPFLAGS -DWANT_SECCOMP"
])

AX_CFLAGS_WARN_ALL
AC_DEFUN([PT_CHECK_CFLAG],[AX_CHECK_COMPILER_FLAGS([$1],[CFLAGS="$CFLAGS $1"])])
m4_foreach_w([flag], [
	-Wunused
	-Wimplicit
	-Wshadow
	-Wformat=2
	-Wmissing-declarations
	-Wno-missing-prototypes
	-Wwrite-strings
	-Wbad-function-cast
	-Wnested-externs
	-Wcomment
	-Winline
	-Wchar-subscripts
	-Wcast-align
	-Wno-format-nonliteral
	-Wsequence-point
	-Wold-style-definition
	-Wextra
], [
	AX_CHECK_COMPILE_FLAG(flag, AS_VAR_APPEND([CFLAGS], " flag"))
])

AC_CHECK_HEADERS_ONCE(m4_flatten([
	linux/seccomp.h
	linux/securebits.h
]))

AC_CONFIG_FILES([
	Makefile
	autotools/gnulib/Makefile
])
AC_OUTPUT
