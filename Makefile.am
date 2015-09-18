ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src

doc_DATA = README.rst LICENSE

clean-build-crap: clean-recursive distclean-recursive clean-libtool mostlyclean-am
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
	-rm -fr src/.libs
	-rm -f vmod_varnish4_geoip.3
	-rm -f debian/autoreconf.after
	-rm -f debian/autoreconf.before
	-rm -f debian/files
	-rm -f debian/libvmod-varnish4-geoip.debhelper.log
	-rm -f debian/libvmod-varnish4-geoip.substvars
	-rm -fr debian/libvmod-varnish4-geoip
	-rm -fr debian/tmp
