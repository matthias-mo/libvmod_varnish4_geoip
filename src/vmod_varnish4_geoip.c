/*
 * Varnish 4 Geo IP lookup
 *
 * Idea and GeoIP varnish 3 code taken from
 * http://https://github.com/cosimo/varnish-geoip
 *
 */

/* for strcasestr */
#define _GNU_SOURCE 1

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <GeoIPCity.h>
#include <pthread.h>

#include "vrt.h"
#include "vrt_obj.h"
#include "vdef.h"

/* from mgt/mgt.h */
#define REPORT0(pri, fmt)       \
  do {                          \
    fprintf(stderr, fmt "\n");  \
    syslog(pri, fmt);           \
  } while (0)

#define REPORT(pri, fmt, ...)               \
  do {                                      \
    fprintf(stderr, fmt "\n", __VA_ARGS__); \
    syslog(pri, fmt, __VA_ARGS__);          \
  } while (0)

#define vcl_string char

/* Set the non-existent "WORLD" country
   code to identify Geo::IP failed lookups */
#define FALLBACK_COUNTRY "WORLD"

/* HTTP Header will be json-like */
#define HEADER_MAXLEN 255

pthread_mutex_t geoip_mutex;
GeoIP *         gi = NULL;

/*
 * vmod entrypoint.
 * Initializes the mutex.
 * Initializes the GeoIP DB
 */
int init_function(struct vmod_priv *priv, const struct VCL_conf *cfg) {

  if (pthread_mutex_init(&geoip_mutex, NULL) != 0) {
    REPORT0(LOG_ERR, "Mutex initializing failed");
    return 1;
  }

  if (!gi) {
    if (GeoIP_db_avail(GEOIP_COUNTRY_EDITION)) {
      gi = GeoIP_open_type(GEOIP_COUNTRY_EDITION, GEOIP_STANDARD);
    }
    if (!gi) {
      REPORT0(LOG_ERR, "Failed to initialize GeoIP DB");
      return 1;
    }
  }
  return 0;
}

static void geoip_lookup_country(const struct vrt_ctx *ctx, vcl_string *resolved) {

  char *ip = VRT_IP_string(ctx, VRT_r_client_ip(ctx));
  pthread_mutex_lock(&geoip_mutex);

  const char * rec = GeoIP_country_code_by_addr(gi, ip);

  snprintf(resolved,
           HEADER_MAXLEN,
           "country:%s",
           rec ? rec : FALLBACK_COUNTRY);

  pthread_mutex_unlock(&geoip_mutex);
}

/* Simplified version: sets "X-Geo-IP" header with the country only */
VCL_VOID __match_proto__(td_geoip_set_country_header)
vmod_set_country_header(const struct vrt_ctx *ctx) {

  static const struct gethdr_s VGC_HDR_REQ_Referer    = { HDR_REQ, "\010Referer:"};
  static const struct gethdr_s VGC_HDR_REQ_Host       = { HDR_REQ, "\005Host:"};
  static const struct gethdr_s VGC_HDR_REQ_User_Agent = { HDR_REQ, "\013User-Agent:"};
  const char * referer    = VRT_GetHdr(ctx, &VGC_HDR_REQ_Referer);
  const char * host       = VRT_GetHdr(ctx, &VGC_HDR_REQ_Host);
  const char * user_agent = VRT_GetHdr(ctx, &VGC_HDR_REQ_User_Agent);

  if (referer && *referer && host && *host) {
    REPORT(LOG_DEBUG, "Referer: \"%s\"", referer);
    const char from_search[] = "://";
    const int  to_search     = (int)'/';
    const char * ref_from    = strstr(referer, from_search) + 3;
    const char * ref_to      = strchr(ref_from, to_search) ? strchr(ref_from, to_search) : referer + strlen(referer);
    unsigned reflen          = ref_to - ref_from;
    char ref[HEADER_MAXLEN + 1];

    assert(ref_from != NULL);
    assert(reflen <= HEADER_MAXLEN);

    strncpy(ref, ref_from, reflen);
    ref[reflen] = '\0';
    /* do not redirect when the referer is from the same URL */
    if (strncmp(ref, host, strlen(host)) == 0) {
      REPORT(LOG_DEBUG, "Host and Referer are equal: \"%s\"", ref);
      REPORT0(LOG_DEBUG, "Not setting the GeoIP header for redirecting");
      return;
    } else {
      REPORT(LOG_DEBUG, "Host \"%s\" and Referer \"%s\" are not equal", host, ref);
      REPORT0(LOG_DEBUG, "Setting the GeoIP header for redirecting");
    }
  }
  if (user_agent && *user_agent ) {
    REPORT(LOG_DEBUG, "User-Agent: \"%s\"", user_agent);
    const char mozilla[] = "Mozilla";
    if (strstr(user_agent, mozilla)) {
      REPORT0(LOG_DEBUG, "User-Agent claims to be Mozilla");
      const char * const bot_str[] = {"bot", "crawler", "spider"};
      for (size_t i = 0; i < 3; i++) {
        if (strcasestr(user_agent, bot_str[i]) != NULL) {
          /* user agent says its a bot/crawler/spider: we don't redirect */
          REPORT0(LOG_DEBUG, "User-Agent claims to be a Mozilla bot: not setting the GeoIP header for redirecting");
          return;
        }
      }
    } else {
      const char * const engines[] = {"Webkit", "Safari", "Opera", "Dillo",
                                      "Lynx", "Links", "w3m", "Midori", "iCab"};
      unsigned known_agent = 0;

      for (size_t i = 0; i < 9; i++) {
        if (strstr(user_agent, engines[i]) != NULL){
          known_agent = 1;
          break;
        }
      }
      if (known_agent == 0) {
        /* user agent is not one we know -> we don't redirect */
        REPORT0(LOG_DEBUG, "User-Agent is not one of our list: not settting the GeoIP header for redirecting");
        return;
      }
    }
  } else {
    /* do not redirect when the user agent header isn't set */
    REPORT0(LOG_DEBUG, "User-Agent is not set: not setting the GeoIP header for redirecting");
    return;
  }
  vcl_string hval[HEADER_MAXLEN + 1];
  geoip_lookup_country(ctx, hval);
  REPORT(LOG_DEBUG, "Setting the GeoIP header to: \"%s\"", hval);

  static const struct gethdr_s VGC_HDR_REQ_GEO_IP = { HDR_REQ, "\011X-Geo-IP:"};

  VRT_SetHdr(ctx, &VGC_HDR_REQ_GEO_IP, hval, vrt_magic_string_end);
}
