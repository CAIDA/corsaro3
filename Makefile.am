SUBDIRS = common libcorsaro corsarotrace corsarowdcap corsaroftmerge

if BUILD_TAGGER
SUBDIRS += corsarotagger
endif
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/common

ACLOCAL_AMFLAGS = -I m4

CLEANFILES = *~

format:
	find . -type f -name "*.[ch]" -not -path "./common/*" -exec \
		clang-format -style=file -i {} \;

.PHONY: format
