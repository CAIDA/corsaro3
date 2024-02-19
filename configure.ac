#
# corsaro
#
# Alistair King, CAIDA, UC San Diego
# corsaro-info@caida.org
#
# Copyright (C) 2012 The Regents of the University of California.
#
# This file is part of corsaro.
#
# corsaro is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# corsaro is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with corsaro.  If not, see <http://www.gnu.org/licenses/>.
#

AC_INIT([corsaro], [3.4.1], [corsaro-info@caida.org])
AM_INIT_AUTOMAKE([foreign subdir-objects])

# update before each release according to the rules defined at
# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
CORSARO_LIBTOOL_CURRENT=4
CORSARO_LIBTOOL_REVISION=2
CORSARO_LIBTOOL_AGE=0

AC_DEFINE_UNQUOTED([CORSARO_LIBTOOL_CURRENT],$CORSARO_LIBTOOL_CURRENT,
	[corsaro libtool current])
AC_DEFINE_UNQUOTED([CORSARO_LIBTOOL_REVISION],$CORSARO_LIBTOOL_REVISION,
	[corsaro libtool revision])
AC_DEFINE_UNQUOTED([CORSARO_LIBTOOL_AGE],$CORSARO_LIBTOOL_AGE,
	[corsaro libtool age])

LT_INIT

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_SRCDIR([libcorsaro/libcorsaro_trace.c])
AC_CONFIG_HEADERS([config.h])

# Check for -fvisibility
gl_VISIBILITY

gcc_PACKED
gcc_DEPRECATED
gcc_UNUSED
gcc_PURE
gcc_FORMAT

# Check for gcc style TLS (__thread)
gcc_TLS

# Checks for programs.
AC_PROG_LIBTOOL
AC_PROG_CC_C99

AC_SYS_LARGEFILE

AH_VERBATIM([_GNU_SOURCE],
[/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif])

AC_CHECK_FUNCS([gettimeofday memset strdup strstr strsep strlcpy vasprintf])

# OSX Mavericks has replaced strlcpy with a macro that is not found by
# AC_CHECK_FUNCS
AC_CHECK_DECLS([strlcpy])

# should we dump debug output to stderr and not optmize the build?

AC_MSG_CHECKING([whether to build with debug information])
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
        [enable debug data generation (def=no)])],
    [debugit="$enableval"],
    [debugit=no])
AC_MSG_RESULT([$debugit])

if test x"$debugit" = x"yes"; then
    AC_DEFINE([DEBUG],[],[Debug Mode])
else
    AC_DEFINE([NDEBUG],[],[No-debug Mode])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC


AX_LIB_SOCKET_NSL

# figure out how to get pthreads linked correctly
STASH_CFLAGS="$CFLAGS"
CFLAGS=
AX_PTHREAD(, [AC_MSG_ERROR([pthreads required])])
CFLAGS="$STASH_CFLAGS"
LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"

AC_ARG_ENABLE([tagger], AS_HELP_STRING([--disable-tagger],
        [Disable building the corsarotagger application]))

# Checks for libraries.
AC_CHECK_LIB([trace], [libtrace_message_queue_put], ,[AC_MSG_ERROR(
		      [libtrace >= 4.0.6 required])])

AC_SEARCH_LIBS([yaml_parser_initialize], [yaml], ,[AC_MSG_ERROR(
		 [libyaml required]
		 )])
AC_SEARCH_LIBS([avro_generic_value_new], [avro], ,[AC_MSG_ERROR(
		 [libavro required]
		 )])
AC_SEARCH_LIBS([ipmeta_lookup_addr], [ipmeta], , [AC_MSG_ERROR([libipmeta 3.0.0 required])])
AC_SEARCH_LIBS([zmq_socket], [zmq], , [AC_MSG_ERROR([libzmq required])])
AC_SEARCH_LIBS([rd_kafka_new], [rdkafka], ,[AC_MSG_ERROR([librdkafka required])])

if test "x$enable_tagger" != "xno"; then
    AC_SEARCH_LIBS([ndag_close_multicaster_socket], [ndagserver], ,[AC_MSG_ERROR([libndagserver required])])
fi

AC_SEARCH_LIBS([aio_return], [rt], ,[AC_MSG_ERROR([librt required])])
AC_SEARCH_LIBS([lrint], [m], ,[AC_MSG_ERROR([libm required])])

# TODO libtimeseries is not strictly required, so make this optional
AC_SEARCH_LIBS([timeseries_kp_flush], [timeseries], , [AC_MSG_ERROR([libtimeseries required])])
AC_CHECK_LIB([Judy], [JudyLGet],, [AC_MSG_ERROR([libJudy required])])

AC_SEARCH_LIBS([tc_version], [tcmalloc tcmalloc_minimal],
                havetcmalloc=true, havetcmalloc=false)
if test "x$havetcmalloc" == xtrue; then

        AC_DEFINE_UNQUOTED([HAVE_TCMALLOC], [1],
                        [tcmalloc is used for memory allocations])
        TCMALLOC_FLAGS="-fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free"
else
        TCMALLOC_FLAGS=""
fi

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h inttypes.h limits.h math.h stdlib.h string.h \
			      time.h sys/time.h])
AC_CHECK_HEADERS(uthash.h, [uthash_h=true])

# monitor name
AC_MSG_CHECKING([for the monitor name to use])
AC_ARG_WITH([monitorname],
	[AS_HELP_STRING([--with-monitorname=NAME],
	  [explicitly define the monitor name (defaults to system hostname)])],
	  [if test "x$withval" == xyes || test "x$withval" == ""; then
	  with_monitorname=`hostname`
	  else
	  with_monitorname=$withval
	  fi],
	  [with_monitorname=`hostname`])
AC_MSG_RESULT([$with_monitorname])

AC_DEFINE_UNQUOTED([CORSARO_MONITOR_NAME],[$with_monitorname],[Monitor Name])

################################################################################
# Plugin Configuration Macros                                                  #
# ---------------------------                                                  #
#                                                                              #
# Each ED_WITH_PLUGIN macro defines a plugin which can be compiled into        #
# Corsaro.                                                                     #
#                                                                              #
# The order in which these plugins are listed is the _default_ order in which  #
# they will be run.                                                            #
################################################################################

ED_WITH_PLUGIN([corsaro_flowtuple],[flowtuple],[SIXT],[yes])
ED_WITH_PLUGIN([corsaro_dos],[dos],[DOS],[yes])
ED_WITH_PLUGIN([corsaro_report],[report],[REPORT],[yes])
ED_WITH_PLUGIN([corsaro_null],[null],[NULL],[yes])

# this MUST go after all the ED_WITH_PLUGIN macro calls
AC_DEFINE_UNQUOTED([ED_PLUGIN_INIT_ALL_ENABLED], $ED_PLUGIN_INIT_ALL_ENABLED,
		   [plugins to call the init macro for in corsaro_plugin.c])

#------------------------------------------------------------------------------#
# Extra tests or config needed for plugins should go below here                #
#------------------------------------------------------------------------------#

if test "x$with_plugin_report" == xyes &&
   test "x$uthash_h" != "xtrue"; then
   AC_MSG_ERROR([corsaro_report plugin requires uthash headers])
fi

# the report plugin requires libtimeseries
# TODO: enable this when report plugin actually uses libtimeseries
#if test "x$with_plugin_report" == xyes; then
#   AC_CHECK_LIB([timeseries], [timeseries_init], , [
#			      AC_MSG_ERROR([libtimeseries is required])
#   ])
#fi


################################################################################
# END PLUGIN CONFIGURATION                                                     #
################################################################################

AC_HEADER_ASSERT

AC_SUBST([CORSARO_LIBTOOL_CURRENT])
AC_SUBST([CORSARO_LIBTOOL_REVISION])
AC_SUBST([CORSARO_LIBTOOL_AGE])
AC_SUBST([TCMALLOC_FLAGS])

AC_HEADER_ASSERT

AM_CONDITIONAL([BUILD_TAGGER], [test "x$enable_tagger" != "xno"])

AC_CONFIG_FILES([Makefile
                        libcorsaro/Makefile
                        libcorsaro/plugins/Makefile
                        libcorsaro/libcorsaro.h
                        corsarotrace/Makefile
                        corsarotagger/Makefile
                        corsarowdcap/Makefile
                        corsaroftmerge/Makefile
			common/Makefile
			common/libpatricia/Makefile
                        common/libinterval3/Makefile
                        common/libinterval3/rb_tree/Makefile
                        common/libcsv/Makefile
                        common/libjsmn/Makefile])
AC_OUTPUT
