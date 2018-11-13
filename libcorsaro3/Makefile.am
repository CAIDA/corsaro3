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
	-I$(top_srcdir)/libcorsaro3/plugins

lib_LTLIBRARIES = libcorsaro3.la

include_HEADERS = libcorsaro3_log.h libcorsaro3.h

libcorsaro3_la_SOURCES = 	\
	libcorsaro3_log.c 		\
	libcorsaro3_log.h 		\
	libcorsaro3_plugin.c 	        \
	libcorsaro3_plugin.h            \
        libcorsaro3_avro.c              \
        libcorsaro3_avro.h              \
        libcorsaro3_trace.c             \
        libcorsaro3_trace.h             \
        libcorsaro3_filtering.c         \
        libcorsaro3_filtering.h         \
        libcorsaro3_tagging.c           \
        libcorsaro3_tagging.h           \
        libcorsaro3_memhandler.c        \
        libcorsaro3_memhandler.h        \
        pqueue.c pqueue.h               \
        libcorsaro3.h

libcorsaro3_la_LIBADD = $(top_builddir)/common/libcccommon.la \
	$(top_builddir)/libcorsaro3/plugins/libcorsaro3plugins.la
libcorsaro3_la_LDFLAGS = -version-info @CORSARO_MAJOR_VERSION@:@CORSARO_MINOR_VERSION@:@CORSARO_MID_VERSION@

ACLOCAL_AMFLAGS = -I m4

CLEANFILES = *~
