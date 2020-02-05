AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/libcorsaro \
	-I$(top_srcdir)/common @TCMALLOC_FLAGS@

bin_PROGRAMS = corsaroftmerge

# main corsaro program
corsaroftmerge_SOURCES = \
	corsaroftmerge.c

corsaroftmerge_LDADD = -lcorsaro

corsaroftmerge_LDFLAGS = -L$(top_builddir)/libcorsaro

ACLOCAL_AMFLAGS = -I m4

CLEANFILES = *~

format:
	find . -type f -name "*.[ch]" -not -path "./common/*" -exec \
		clang-format -style=file -i {} \;

.PHONY: format
