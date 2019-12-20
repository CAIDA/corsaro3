AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/libcorsaro @TCMALLOC_FLAGS@

bin_PROGRAMS = corsarotagger

# main corsaro program
corsarotagger_SOURCES = \
	corsarotagger.c \
        configparser.c \
        tagger_thread.c \
        packet_thread.c \
        proxy_threads.c \
        corsarotagger.h

corsarotagger_LDADD = -lcorsaro
corsarotagger_LDFLAGS = -L$(top_builddir)/libcorsaro

ACLOCAL_AMFLAGS = -I m4

CLEANFILES = *~

format:
	find . -type f -name "*.[ch]" -not -path "./common/*" -exec \
		clang-format -style=file -i {} \;

.PHONY: format
