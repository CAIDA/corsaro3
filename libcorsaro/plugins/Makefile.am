#
# corsaro
#
# Alistair King, CAIDA, UC San Diego
# Shane Alcock, WAND, University of Waikato
#
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

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/common \
        -I$(top_srcdir)/common/libpatricia \
        -I$(top_srcdir)/common/libcsv \
        -I$(top_srcdir)/libcorsaro \
        @TCMALLOC_FLAGS@

noinst_LTLIBRARIES = libcorsaroplugins.la

include_HEADERS =
PLUGIN_SRC=
PLUGIN_LIBS=

if WITH_PLUGIN_SIXT
PLUGIN_SRC+=corsaro_flowtuple.c corsaro_flowtuple.h
include_HEADERS+=corsaro_flowtuple.h
endif

if WITH_PLUGIN_DOS
PLUGIN_SRC+=corsaro_dos.c corsaro_dos.h
include_HEADERS+=corsaro_dos.h
endif

if WITH_PLUGIN_FILTERINGSTATS
PLUGIN_SRC+=corsaro_filteringstats.c corsarofiltering_stats.h
include_HEADERS+=corsaro_filteringstats.h
endif

if WITH_PLUGIN_REPORT
PLUGIN_SRC+=corsaro_report.c corsaro_report.h
include_HEADERS+=corsaro_report.h
endif

libcorsaroplugins_la_SOURCES = \
        $(PLUGIN_SRC)

libcorsaroplugins_la_LIBADD = \
        $(PLUGIN_LIBS)

ACLOCAL_AMFLAGS = -I m4


