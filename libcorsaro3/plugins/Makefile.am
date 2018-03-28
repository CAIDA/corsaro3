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
        -I$(top_srcdir)/libcorsaro3

noinst_LTLIBRARIES = libcorsaro3plugins.la

include_HEADERS =
PLUGIN_SRC=
PLUGIN_LIBS=

if WITH_PLUGIN_SIXT
PLUGIN_SRC+=corsaro_flowtuple.c corsaro_flowtuple.h
include_HEADERS+=corsaro_flowtuple.h
endif

if WITH_PLUGIN_WDCAP
PLUGIN_SRC+=corsaro_wdcap.c corsaro_wdcap.h
include_HEADERS+=corsaro_wdcap.h
endif

libcorsaro3plugins_la_SOURCES = \
        $(PLUGIN_SRC)

libcorsaro3plugins_la_LIBADD = \
        $(PLUGIN_LIBS)

ACLOCAL_AMFLAGS = -I m4


