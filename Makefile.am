ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src

dist_man_MANS = vmod_varnish4_geoip.3
MAINTAINERCLEANFILES = $(dist_man_MANS)
doc_DATA = README.rst LICENSE

vmod_varnish4_geoip.3: README.rst
if HAVE_RST2MAN
	${RST2MAN} README.rst $@
else
	@echo "========================================"
	@echo "You need rst2man installed to make dist"
	@echo "========================================"
	@false
endif

clean-auto-crap: clean-recursive distclean-recursive clean-libtool mostlyclean-am
	-rm -f Makefile
	-rm -f Makefile.in
	-rm -f aclocal.m4
	-rm -fr autom4te.cache
	-rm -f compile
	-rm -f config.guess
	-rm -f config.h.in
	-rm -f config.log
	-rm -f config.status
	-rm -f config.sub
	-rm -f configure
	-rm -f depcomp
	-rm -f install-sh
	-rm -f ltmain.sh
	-rm -f m4/*.m4
	-rm -f missing
	-rm -f src/Makefile.in
	-rm -f src/vmod_geoip.man.rst
	-rm -f src/vmod_geoip.rst
	-rm -f vmod_varnish4_geoip.3

