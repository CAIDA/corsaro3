SUBDIRS = plugins
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/common \
	-I$(top_srcdir)/common/libpatricia \
	-I$(top_srcdir)/libcorsaro/plugins \
        @TCMALLOC_FLAGS@

lib_LTLIBRARIES = libcorsaro.la

include_HEADERS = libcorsaro_log.h libcorsaro.h libcorsaro_avro.h \
    libcorsaro_flowtuple.h

libcorsaro_la_SOURCES = 	\
	libcorsaro_log.c 		\
	libcorsaro_log.h 		\
	libcorsaro_common.c 		\
	libcorsaro_common.h 		\
	libcorsaro_plugin.c 	        \
	libcorsaro_plugin.h            \
        libcorsaro_avro.c              \
        libcorsaro_avro.h              \
        libcorsaro_trace.c             \
        libcorsaro_trace.h             \
        libcorsaro_filtering.c         \
        libcorsaro_filtering.h         \
        libcorsaro_tagging.c           \
        libcorsaro_tagging.h           \
        libcorsaro_memhandler.c        \
        libcorsaro_memhandler.h        \
        libcorsaro_libtimeseries.c     \
        libcorsaro_libtimeseries.h     \
        libcorsaro_flowtuple.c         \
        libcorsaro_flowtuple.h         \
        pqueue.c pqueue.h              \
        libcorsaro.h

libcorsaro_la_LIBADD = $(top_builddir)/common/libcccommon.la \
	$(top_builddir)/libcorsaro/plugins/libcorsaroplugins.la
libcorsaro_la_LDFLAGS = -version-info @CORSARO_LIBTOOL_CURRENT@:@CORSARO_LIBTOOL_REVISION@:@CORSARO_LIBTOOL_AGE@

ACLOCAL_AMFLAGS = -I m4

CLEANFILES = *~
