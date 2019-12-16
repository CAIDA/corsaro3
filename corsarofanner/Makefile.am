AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/libcorsaro \
	-I$(top_srcdir)/common @TCMALLOC_FLAGS@

bin_PROGRAMS = corsarofanner

# main corsaro program
corsarofanner_SOURCES = \
	corsarofanner.c \
        configparser.c \
        corsarofanner.h

corsarofanner_LDADD = -lcorsaro

corsarofanner_LDFLAGS = -L$(top_builddir)/libcorsaro

ACLOCAL_AMFLAGS = -I m4

CLEANFILES = *~

format:
	find . -type f -name "*.[ch]" -not -path "./common/*" -exec \
		clang-format -style=file -i {} \;

.PHONY: format
