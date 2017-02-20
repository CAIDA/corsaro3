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

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/common -I$(top_srcdir)/libcorsaro \
	-I$(top_srcdir)/libcorsaro/plugins

dist_bin_SCRIPTS = \
	cors-splitascii.pl \
	cors-ft-timeseries.pl

bin_PROGRAMS = cors-trace2tuple cors2ascii
BUILT_SOURCES =
EXTRA_DIST =

# corsaro2ascii program
cors2ascii_SOURCES = \
	cors2ascii.c
cors2ascii_LDADD = -lcorsaro
cors2ascii_LDFLAGS = -L$(top_builddir)/libcorsaro

# flowtuple2avro converter
if WITH_AVRO
bin_PROGRAMS += cors-flowtuple2avro
cors_flowtuple2avro_SOURCES = cors-flowtuple2avro.c
cors_flowtuple2avro_LDADD = -lcorsaro
cors_flowtuple2avro_LDFLAGS = -L$(top_builddir)/libcorsaro
EXTRA_DIST += flowtuple.avsc.json
BUILT_SOURCES += flowtuple_avsc_json.inc
flowtuple_avsc_json.inc: flowtuple.avsc.json
	xxd -i flowtuple.avsc.json flowtuple_avsc_json.inc
EXTRA_DIST += flowtuple-compact.avsc.json
BUILT_SOURCES += flowtuple_compact_avsc_json.inc
flowtuple_compact_avsc_json.inc: flowtuple-compact.avsc.json
	xxd -i flowtuple-compact.avsc.json flowtuple_compact_avsc_json.inc
endif

# not really a part of corsaro, but lets call corsaro the caida telescope
# toolset :)
cors_trace2tuple_SOURCES = \
	cors-trace2tuple.c
cors_trace2tuple_LDADD = -ltrace

if WITH_PLUGIN_SIXT
bin_PROGRAMS +=  cors-ft-aggregate
cors_ft_aggregate_SOURCES = \
	cors-ft-aggregate.c
cors_ft_aggregate_LDADD = -lcorsaro
cors_ft_aggregate_LDFLAGS = -L$(top_builddir)/libcorsaro
endif

ACLOCAL_AMFLAGS = -I m4

CLEANFILES = *~
