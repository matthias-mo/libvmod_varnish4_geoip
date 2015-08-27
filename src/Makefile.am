AM_CPPFLAGS = @VMOD_INCLUDES@

vmoddir = @VMOD_DIR@
vmodtoolargs = --strict
vmod_LTLIBRARIES = libvmod_geoip.la

libvmod_geoip_la_LDFLAGS = -module -export-dynamic -avoid-version -lGeoIP

libvmod_geoip_la_SOURCES = \
	vcc_if.c \
	vcc_if.h \
	vmod_varnish4_geoip.c

vcc_if.c vcc_if.h: @VMODTOOL@ $(top_srcdir)/src/vmod_varnish4_geoip.vcc
	@VMODTOOL@ $(vmodtoolargs) $(top_srcdir)/src/vmod_varnish4_geoip.vcc

EXTRA_DIST = \
	vmod_varnish4_geoip.vcc

CLEANFILES = $(builddir)/vcc_if.c $(builddir)/vcc_if.h \
	$(builddir)/vmod_varnish4_geoip.man.rst \
	$(builddir)/vmod_varnish4_geoip.rst
