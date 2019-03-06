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

SUBDIRS = plugins
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/common \
	-I$(top_srcdir)/common/libpatricia \
	-I$(top_srcdir)/libcorsaro/plugins \
        @TCMALLOC_FLAGS@

lib_LTLIBRARIES = libcorsaro.la

include_HEADERS = libcorsaro_log.h libcorsaro.h

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
        pqueue.c pqueue.h               \
        libcorsaro.h

libcorsaro_la_LIBADD = $(top_builddir)/common/libcccommon.la \
	$(top_builddir)/libcorsaro/plugins/libcorsaroplugins.la
libcorsaro_la_LDFLAGS = -version-info @CORSARO_MAJOR_VERSION@:@CORSARO_MINOR_VERSION@:@CORSARO_MID_VERSION@

ACLOCAL_AMFLAGS = -I m4

CLEANFILES = *~
