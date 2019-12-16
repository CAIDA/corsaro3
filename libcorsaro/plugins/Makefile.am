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
PLUGIN_SRC+=corsaro_filteringstats.c corsaro_filteringstats.h
include_HEADERS+=corsaro_filteringstats.h
endif

if WITH_PLUGIN_REPORT
PLUGIN_SRC+=report/corsaro_report.c report/corsaro_report.h
PLUGIN_SRC+=report/iptracker_thread.c report/merging_thread.c
PLUGIN_SRC+=report/processing_thread.c report/report_internal.h
include_HEADERS+=report/corsaro_report.h
endif

libcorsaroplugins_la_SOURCES = \
        $(PLUGIN_SRC)

libcorsaroplugins_la_LIBADD = \
        $(PLUGIN_LIBS)

ACLOCAL_AMFLAGS = -I m4


