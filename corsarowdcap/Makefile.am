
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/libcorsaro \
	-I$(top_srcdir)/common @TCMALLOC_FLAGS@

bin_PROGRAMS = corsarowdcap
EXTRA_DIST = README exampleconfig.yaml

# main corsaro program
corsarowdcap_SOURCES = \
	corsarowdcap.c \
        merger_thread.c \
        configparser.c \
        corsarowdcap.h

corsarowdcap_LDADD = -lcorsaro

corsarowdcap_LDFLAGS = -L$(top_builddir)/libcorsaro

ACLOCAL_AMFLAGS = -I m4

CLEANFILES = *~

format:
	find . -type f -name "*.[ch]" -not -path "./common/*" -exec \
		clang-format -style=file -i {} \;

.PHONY: format
