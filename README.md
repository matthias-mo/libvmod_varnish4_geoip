libvmod_geoip
======================

Varnish 4 vmod for adding a header entry inlcluding the GeoIP information

**I have no clue what I'm doing, will most eat puppies.**

Requirement:
============
Packages: build-essential libtool libvarnishapi-dev python-docutils 

Build:
======
You need libgeoip-dev in order to build this.

```
 ./autogen.sh
 ./configure  VMOD_DIR=/usr/lib/varnish/vmods/
 make
 make install
```

Usage:
======
```
import geoip;

sub vcl_recv {
    if (req.restarts == 0 && (req.method == "GET" || req.method == "POST")) {
        geoip.set_country_header();
    }
}

```
