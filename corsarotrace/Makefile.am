AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/libcorsaro \
	-I$(top_srcdir)/libcorsaro/plugins @TCMALLOC_FLAGS@

bin_PROGRAMS = corsarotrace

# main corsaro program
corsarotrace_SOURCES = \
	corsarotrace.c \
        configparser.c \
        corsarotrace.h

corsarotrace_LDADD = -lcorsaro

corsarotrace_LDFLAGS = -L$(top_builddir)/libcorsaro

ACLOCAL_AMFLAGS = -I m4

CLEANFILES = *~

format:
	find . -type f -name "*.[ch]" -not -path "./common/*" -exec \
		clang-format -style=file -i {} \;

.PHONY: format
