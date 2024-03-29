AC_PREREQ([2.69])
AC_INIT([net_check_plugin], [0.1])

AX_CHECK_ENABLE_DEBUG([yes])

AM_INIT_AUTOMAKE([1.15 -Wall -Werror -Wno-portability silent-rules std-options check-news foreign])
AM_SILENT_RULES([yes])
LT_INIT([disable-static])

AC_CONFIG_SRCDIR([src/net_check.c])
AC_CONFIG_MACRO_DIR([m4])

# ---------------------------------------------------------------
# Checks for programs.
# ---------------------------------------------------------------
AC_PROG_CC
AM_PROG_CC_C_O

# Check for Doxygen
DX_DOXYGEN_FEATURE(ON)
DX_DOT_FEATURE(ON)
DX_HTML_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN([net_check], [Doxyfile], [doc])

# Check for pandoc
AC_ARG_VAR([PANDOC],[location of pandoc program])
AC_PATH_PROG([PANDOC], [pandoc])

PKG_PROG_PKG_CONFIG

# ---------------------------------------------------------------

AC_ARG_WITH([libstuncli],
            AS_HELP_STRING([--with-libstuncli],
                           [Use system libstuncli]))
AM_CONDITIONAL([SYSTEMSTUN], [test "x$with_libstuncli" = "xyes"])

# ---------------------------------------------------------------
# Checks for libraries.
# ---------------------------------------------------------------
ELL_VERSION=0.30  dnl Minimum required version of ELL.

# Find mptcpd and ELL
PKG_CHECK_MODULES([MPTCPD], [mptcpd])
PKG_CHECK_MODULES([ELL],
                  [ell >= $ELL_VERSION])
PKG_CHECK_MODULES([LIBMNL], [libmnl])
PKG_CHECK_MODULES([LIBNFTNL], [libnftnl])
PKG_CHECK_MODULES([LIBNETFILTER_QUEUE], [libnetfilter_queue])
AS_IF([test "x$with_libstuncli" = "xyes"], [
        PKG_CHECK_MODULES([LIBSTUNCLI], [libstuncli])
])

PKG_CHECK_VAR([MPTCPD_PLUGINDIR], [mptcpd], [plugindir])

AC_SUBST([ELL_VERSION])

# ---------------------------------------------------------------
# Enable additional C compiler warnings.  We do this after all
# Autoconf tests have been run since not all autoconf macros are
# warning free.
# ---------------------------------------------------------------
AX_CFLAGS_WARN_ALL([CFLAGS])
AX_APPEND_COMPILE_FLAGS([-Wextra -Werror -pedantic])

# ---------------------------------------------------------------
# Generate our build files.
# ---------------------------------------------------------------
AC_CONFIG_FILES([Makefile
                 include/Makefile
                 include/net_check/Makefile
                 include/libstuncli/Makefile
                 lib/Makefile
                 src/Makefile])
AC_OUTPUT
