SUBDIRS = common libcorsaro corsarotrace corsarotagger corsarowdcap \
        corsaroftmerge
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/common

ACLOCAL_AMFLAGS = -I m4

CLEANFILES = *~

format:
	find . -type f -name "*.[ch]" -not -path "./common/*" -exec \
		clang-format -style=file -i {} \;

.PHONY: format
