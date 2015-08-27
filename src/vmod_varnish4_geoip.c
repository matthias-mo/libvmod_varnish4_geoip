/*
 * Varnish 4 Geo IP lookup
 *
 * Idea and GeoIP varnish 3 code taken from
 * http://https://github.com/cosimo/varnish-geoip
 *
 */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <GeoIPCity.h>
#include <pthread.h>

#include "vcl.h"
#include "vrt.h"
#include "vrt_obj.h"

#define vcl_string char

/* At Opera, we use the non-existent "A6" country
   code to identify Geo::IP failed lookups */
#define FALLBACK_COUNTRY "A6"

/* HTTP Header will be json-like */
#define HEADER_MAXLEN 255

pthread_mutex_t geoip_mutex;
GeoIP* gi;

/*
 * vmod entrypoint.
 * Initializes the mutex.
 * Initializes the GeoIP DB
 */
int init_function(struct vmod_priv *priv, const struct VCL_conf *cfg) {

    if (pthread_mutex_init(&geoip_mutex, NULL) != 0) {
        printf("\nMutex init failed\n");
        return 1;
    }
    if (!gi) {
        if (GeoIP_db_avail(GEOIP_COUNTRY_EDITION)) {
            gi = GeoIP_open_type(GEOIP_COUNTRY_EDITION, GEOIP_STANDARD);
        }
        if (!gi) {
            printf("\nGeoIP DB initialization failed.\n");
            return 1;
        }
    }
    return 0;
}

static int geoip_lookup_country(char *ip, vcl_string *resolved) {

    pthread_mutex_lock(&geoip_mutex);

    const char * rec = GeoIP_country_code_by_addr(gi, ip);

    snprintf(resolved,
             HEADER_MAXLEN,
             "country:%s",
             rec ? rec : FALLBACK_COUNTRY);

    pthread_mutex_unlock(&geoip_mutex);

    /* Assume always success: we have FALLBACK_COUNTRY */
    return 1;
}

/* Simplified version: sets "X-Geo-IP" header with the country only */
void vmod_set_country_header(const struct vrt_ctx *ctx) {
    vcl_string hval[HEADER_MAXLEN];
    char *ip = VRT_IP_string(ctx, VRT_r_client_ip(ctx));
    geoip_lookup_country(ip, hval);

    static const struct gethdr_s VGC_HDR_REQ_GEO_IP = { HDR_REQ, "\011X-Geo-IP:"};

    /*VRT_SetHdr(ctx, &VGC_HDR_REQ_GEO_IP, "\020X-Request-Start:", hval, vrt_magic_string_end);*/
    VRT_SetHdr(ctx, &VGC_HDR_REQ_GEO_IP, hval, vrt_magic_string_end);
}
/* vim: syn=c ts=4 et sts=4 sw=4 tw=0
*/
