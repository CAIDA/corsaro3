/*
 * corsaro
 *
 * Alistair King, CAIDA, UC San Diego
 * corsaro-info@caida.org
 *
 * Copyright (C) 2012 The Regents of the University of California.
 *
 * This file is part of corsaro.
 *
 * corsaro is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * corsaro is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with corsaro.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "config.h"
#include "corsaro_int.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libipmeta.h>
#include <libtimeseries.h>
#include <libtrace.h>

#include "khash.h"
#include "ksort.h"
#include "utils.h"

#include "corsaro_ipmeta.h"
#include "corsaro_io.h"
#include "corsaro_log.h"
#include "corsaro_plugin.h"

#ifdef WITH_PLUGIN_SIXT
#include "corsaro_flowtuple.h"
#endif

#include "corsaro_report.h"

/** @file
 *
 * @brief Corsaro FlowTuple Reporting plugin
 *
 * @author Alistair King
 *
 */

/** The magic number for this plugin - "REPT" */
#define CORSARO_ANON_MAGIC 0x52455054

/** The name of this plugin */
#define PLUGIN_NAME "report"

/** The length of the buffer used to construct key names */
#define KEY_BUFFER_LEN 1024

/* to count the number of unique src ips per country */
KHASH_INIT(32xx, khint32_t, char, 0, kh_int_hash_func2, kh_int_hash_equal)

/** Structure which holds state about sub-metrics for each metric */
typedef struct metric_package {
  uint32_t id_offset;
  khash_t(32xx) *uniq_src_ip;
  khash_t(32xx) *uniq_dst_ip;
  uint64_t pkt_cnt;
  uint64_t ip_len;
} metric_package_t;


/* ---------- TURN THINGS ON AND OFF ---------- */

#define WITH_MAXMIND_STATS
#define WITH_NETACQ_EDGE_STATS
#define WITH_PFX2AS_STATS
#define WITH_PROTOCOL_STATS
#define WITH_PORT_STATS

/* ---------- GLOBAL METRIC SETTINGS ---------- */

/** The prefix to attach to all metrics */
#define METRIC_PREFIX "darknet.ucsd-nt"

enum metric_type {
  METRIC_TYPE_UNIQ_SRC_IP = 0,
  METRIC_TYPE_UNIQ_DST_IP = 1,
  METRIC_TYPE_PKT_CNT     = 2,
  METRIC_TYPE_IP_LEN      = 3,

  METRIC_TYPE_CNT         = 4
};

const char *metric_type_names[] = {
  "uniq_src_ip",
  "uniq_dst_ip",
  "pkt_cnt",
  "ip_len"
};

/* ---------- MAXMIND METRIC SETTINGS ---------- */
#ifdef WITH_MAXMIND_STATS

#define METRIC_PATH_MAXMIND_COUNTRY    METRIC_PREFIX".geo.maxmind"

/** The max number of values in a 16 bit number (two 8-bit ascii characters) */
#define METRIC_MAXMIND_ASCII_MAX UINT16_MAX

#endif

/* ---------- NETACQ EDGE METRIC SETTINGS ---------- */
#ifdef WITH_NETACQ_EDGE_STATS

#define METRIC_PATH_NETACQ_EDGE_COUNTRY     \
  METRIC_PREFIX".geo.netacuity.edge.country"

/** The max number of values in a 16 bit number (two 8-bit ascii characters) */
#define METRIC_NETACQ_EDGE_COUNTRY_MAX UINT16_MAX

#define METRIC_PATH_NETACQ_EDGE_REGION     \
  METRIC_PREFIX".geo.netacuity.edge.region"

/** The max region code value (currently the actual max is 30,404, but this
 * could easily go higher. be careful) */
#define METRIC_NETACQ_EDGE_REGION_MAX UINT16_MAX

#endif

/* ---------- PFX2AS METRIC SETTINGS ---------- */
#ifdef WITH_PFX2AS_STATS

#define METRIC_PATH_PFX2AS             METRIC_PREFIX".routing.pfx2as.asn"
#define METRIC_PFX2AS_VAL_MAX          3000

/** Sort PFX2AS ASN Records
 *
 * First, sort by ASN count ascending (to put ASN groups at the end)
 * Second, sort by 'size' of AS (number of IPs in it's prefixes)
 * Third, sort by the ASN
 */
#define pfx2as_ip_cnt_lt(alpha, bravo)					\
  (									\
   ((alpha)->asn_cnt < (bravo)->asn_cnt) ||				\
   (									\
    ((alpha)->asn_cnt == (bravo)->asn_cnt) &&				\
    (									\
     ((alpha)->asn_ip_cnt > (bravo)->asn_ip_cnt) ||			\
     (									\
     ((alpha)->asn_ip_cnt == (bravo)->asn_ip_cnt) &&			\
     (									\
     ((alpha)->asn[0] < (bravo)->asn[0])				\
									) \
									) \
									) \
									) \
									)

KSORT_INIT(pfx2as_ip_cnt_desc, ipmeta_record_t*, pfx2as_ip_cnt_lt);

KHASH_INIT(u32metric, uint32_t, metric_package_t *, 1,
	   kh_int_hash_func2, kh_int_hash_equal)

#endif

/* ---------- PROTOCOL METRIC SETTINGS ---------- */
#ifdef WITH_PROTOCOL_STATS

#define METRIC_PATH_PROTOCOL            METRIC_PREFIX".traffic.protocol"
#define METRIC_PROTOCOL_VAL_MAX         256

#endif

/* ---------- PORT METRIC SETTINGS ---------- */

#ifdef WITH_PORT_STATS

/* these need to be METRIC_DIRECTION_MAX apart */
enum {
  METRIC_PORT_PROTOCOL_SKIP  = -1,
  METRIC_PORT_PROTOCOL_TCP   = 0,
  METRIC_PORT_PROTOCOL_UDP   = 1,
  /*  METRIC_PROTOCOL_OTHER = 4,*/

  METRIC_PORT_PROTOCOL_MAX = METRIC_PORT_PROTOCOL_UDP,
};

enum {
  METRIC_PORT_DIRECTION_SRC = 0,
  METRIC_PORT_DIRECTION_DST = 1,

  METRIC_PORT_DIRECTION_MAX = METRIC_PORT_DIRECTION_DST,
};

#define METRIC_PORT_VAL_MAX 6000
/* 65536 is the actual max, but we just want the first 6000 */

#define PORT_PREFIX METRIC_PREFIX".traffic.port"

static char *port_metric_paths[] = {
  PORT_PREFIX".tcp.src_port",
  PORT_PREFIX".tcp.dst_port",
  PORT_PREFIX".udp.src_port",
  PORT_PREFIX".udp.dst_port",
  /*
  PORT_PREFIX".other.src_port",
  PORT_PREFIX".other.dst_port",
  */
};
#endif

/* ---------- END METRIC SETTINGS ---------- */

/** Common plugin information across all instances */
static corsaro_plugin_t corsaro_report_plugin = {
  PLUGIN_NAME,                                 /* name */
  CORSARO_PLUGIN_ID_REPORT,                      /* id */
  CORSARO_ANON_MAGIC,                          /* magic */
#ifdef WITH_PLUGIN_SIXT
  CORSARO_PLUGIN_GENERATE_PTRS_FT(corsaro_report),  /* func ptrs */
#else
  CORSARO_PLUGIN_GENERATE_PTRS(corsaro_report),
#endif
  CORSARO_PLUGIN_GENERATE_TAIL,
};

/** Holds the state for an instance of this plugin */
struct corsaro_report_state_t {

#ifdef WITH_MAXMIND_STATS
  /** Array of countries (converted to integers) that point to metrics.
   *
   * Even though it uses more memory, we create an array that can hold 2^16
   * countries -- this allows us to directly index a country based on the
   * conversion of the ascii characters in each ISO 3166 2 character code.
   */
  metric_package_t *maxmind_country_metrics[METRIC_MAXMIND_ASCII_MAX];
#endif

#ifdef WITH_NETACQ_EDGE_STATS
  /** Array of country codes (specific to netacq) that point to metrics.
   *
   * Even though it uses more memory, we create an array that can hold 2^16
   * countries -- this allows us to directly index a country based on the
   * conversion of the ascii characters in each ISO 3166 2 character code.
   */
  metric_package_t *netacq_country_metrics[METRIC_NETACQ_EDGE_REGION_MAX];

  /** Array of region codes (specific to netacq) that point to metrics.
   *
   * Note that many of these will be NULL
   */
  metric_package_t *netacq_region_metrics[METRIC_NETACQ_EDGE_REGION_MAX];
#endif

#ifdef WITH_PFX2AS_STATS
  /** The minimum number of IPs that an ASN can have before it is considered for
      reporting (based on smallest the top METRIC_PFX2AS_VAL_MAX ASes) */
  int pfx2as_min_ip_cnt;
  /** Hash of asns that point to metrics */
  khash_t(u32metric) *pfx2as_metrics;
#endif

#ifdef WITH_PROTOCOL_STATS
  /** Array of protocols that each contain a metric */
  metric_package_t *protocol_metrics[METRIC_PROTOCOL_VAL_MAX];
#endif

#ifdef WITH_PORT_STATS
  /** Array of port metrics */
  metric_package_t *port_metrics[METRIC_PORT_PROTOCOL_MAX+1]	\
  [METRIC_PORT_DIRECTION_MAX+1][METRIC_PORT_VAL_MAX];
#endif

  /** libtimeseries state */
  timeseries_t *timeseries;

  /** The libtimeseries backend(s) we will write to */
  timeseries_backend_t *enabled_backends[TIMESERIES_BACKEND_ID_LAST];

  /** The number of libtimeseries backends that are enabled */
  int enabled_backends_cnt;

  /** The libtimeseries key package that we are updating */
  timeseries_kp_t *kp;

  /** the 'current' time (i.e. the start of the current interval) */
  uint32_t time;
};

/** Extends the generic plugin state convenience macro in corsaro_plugin.h */
#define STATE(corsaro)						\
  (CORSARO_PLUGIN_STATE(corsaro, report, CORSARO_PLUGIN_ID_REPORT))

/** Extends the generic plugin plugin convenience macro in corsaro_plugin.h */
#define PLUGIN(corsaro)						\
  (CORSARO_PLUGIN_PLUGIN(corsaro, CORSARO_PLUGIN_ID_REPORT))

#if defined(WITH_MAXMIND_STATS) || defined(WITH_PFX2AS_STATS) ||	\
  defined(WITH_PROTOCOL_STATS) || defined(WITH_PORT_STATS)
static metric_package_t *metric_package_new(struct corsaro_report_state_t *state,
					    const char *metric_prefix,
					    uint32_t id_offset)
{
  metric_package_t *mp = NULL;
  int i;
  char key_buffer[KEY_BUFFER_LEN];

  /* allocate memory for the metric package */
  if((mp = malloc(sizeof(metric_package_t))) == NULL)
    {
      /* could not malloc the memory. this is bad */
      return NULL;
    }

  /* create a key in the key package for each sub-metric in the metric
     package */
  for(i=0; i<METRIC_TYPE_CNT; i++)
    {
      /* generate a key for this metric and insert it in the key package */
	  snprintf(key_buffer, KEY_BUFFER_LEN,
		   "%s.%s", metric_prefix, metric_type_names[i]);

	  timeseries_kp_add_key(state->kp, key_buffer);
	}

  /* the id of this metric in the key package */
  mp->id_offset = id_offset;

  /* create a new src ip map */
  mp->uniq_src_ip = kh_init(32xx);
  /* create a new dst ip map */
  mp->uniq_dst_ip = kh_init(32xx);

  /* zero the packet count (better than a memset 0 on all of it?) */
  mp->pkt_cnt = 0;
  /* and the byte count */
  mp->ip_len = 0;

  return mp;
}

static void metric_package_destroy(metric_package_t *mp)
{
  assert(mp != NULL);

  /* free the src ip map */
  kh_destroy(32xx, mp->uniq_src_ip);

  /* free the dst ip map */
  kh_destroy(32xx, mp->uniq_dst_ip);

  /* finally, free the metric package */
  free(mp);

  return;
}

static void metric_package_update(metric_package_t *mp,
				  uint32_t src_ip,
				  uint32_t dst_ip,
				  uint16_t ip_len,
				  uint64_t pkt_cnt)
{
  int khret;
  assert(mp != NULL);

  /* simply add the src ip to the map */
  kh_put(32xx, mp->uniq_src_ip, src_ip, &khret);
  /* and add the dst ip */
  kh_put(32xx, mp->uniq_dst_ip, dst_ip, &khret);
  /* and increment the packet count */
  mp->pkt_cnt+=pkt_cnt;
  /* and increment the byte counter */
  mp->ip_len+=(ip_len*pkt_cnt);

  return;
}

static void metric_package_dump(struct corsaro_report_state_t *state,
				metric_package_t *mp)
{
  timeseries_kp_set(state->kp,
		    mp->id_offset+METRIC_TYPE_UNIQ_SRC_IP,
		    (uint64_t)kh_size(mp->uniq_src_ip));

  timeseries_kp_set(state->kp,
		    mp->id_offset+METRIC_TYPE_UNIQ_DST_IP,
		    (uint64_t)kh_size(mp->uniq_dst_ip));

  timeseries_kp_set(state->kp,
		    mp->id_offset+METRIC_TYPE_PKT_CNT,
		    mp->pkt_cnt);

  timeseries_kp_set(state->kp,
		    mp->id_offset+METRIC_TYPE_IP_LEN,
		    mp->ip_len);

  /* empty the maps for this country */
  kh_clear(32xx, mp->uniq_src_ip);
  kh_clear(32xx, mp->uniq_dst_ip);
  /* reset the counters */
  mp->pkt_cnt = 0;
  mp->ip_len = 0;
}
#endif

static inline uint16_t lookup_convert_cc(corsaro_packet_state_t *state,
					 ipmeta_provider_id_t provider_id)
{
  ipmeta_record_t *record;

  if((record =
      corsaro_ipmeta_get_record(state, provider_id))
     != NULL)
    {
      if(record->country_code != NULL)
	{
	  return (record->country_code[0]<<8) | record->country_code[1];
	}
    }

  return 0x2D2D; /* "--" */
}

static int process_generic(corsaro_t *corsaro, corsaro_packet_state_t *state,
			   uint32_t src_ip, uint32_t dst_ip,
			   uint16_t src_port, uint16_t dst_port,
			   uint16_t ip_len, uint8_t protocol, uint64_t pkt_cnt)
{
  struct corsaro_report_state_t *plugin_state = STATE(corsaro);
  assert(plugin_state != NULL);

#ifdef WITH_PORT_STATS
  int proto;
#endif

#if defined WITH_MAXMIND_STATS || defined WITH_NETACQ_EDGE_STATS
  uint16_t cc;
#endif

#ifdef WITH_NETACQ_EDGE_STATS
  uint16_t rc;
#endif

#ifdef WITH_PFX2AS_STATS
  khiter_t khiter;
  ipmeta_record_t *record;
#endif

  /* ==================== GEOGRAPHIC ==================== */
#ifdef WITH_MAXMIND_STATS
  /* maxmind country code */
  cc = lookup_convert_cc(state, IPMETA_PROVIDER_MAXMIND);

  /* update the appropriate country metric package */
  assert(plugin_state->maxmind_country_metrics[cc] != NULL);
  metric_package_update(plugin_state->maxmind_country_metrics[cc],
			src_ip, dst_ip, ip_len, pkt_cnt);
#endif

#ifdef WITH_NETACQ_EDGE_STATS
  /* netacq edge country code */
  cc = lookup_convert_cc(state, IPMETA_PROVIDER_NETACQ_EDGE);

  /* update the appropriate country metric package */
  assert(plugin_state->netacq_country_metrics[cc] != NULL);
  metric_package_update(plugin_state->netacq_country_metrics[cc],
			src_ip, dst_ip, ip_len, pkt_cnt);

  /* netacq edge region code */
  if((record =
      corsaro_ipmeta_get_record(state, IPMETA_PROVIDER_NETACQ_EDGE))
     != NULL)
    {
      rc = record->region_code;
      assert(plugin_state->netacq_region_metrics[rc] != NULL);
      metric_package_update(plugin_state->netacq_region_metrics[rc],
			    src_ip, dst_ip, ip_len, pkt_cnt);
    }
#endif

  /* ==================== PFX2AS ASNs ==================== */
#ifdef WITH_PFX2AS_STATS
  /* note we are deliberately discarding ASN records that have more than one ASN
     because we consider them an artifact of the measurement */
  /* we are also discarding any AS that is smaller than the smallest AS in our
     top METRIC_PFX2AS_VAL_MAX ASes list. */
  /* note that this means there may *occasionally* be more than
     METRIC_PFX2AS_VAL_MAX ASes dumped. this will only happen when there are
     multiple ASes of size plugin_state->pfx2as_min_ip_cnt */
  /* also note that we are NOT recording stats for packets that we cannot
     compute ans ASN for */
  if((record = corsaro_ipmeta_get_record(state, IPMETA_PROVIDER_PFX2AS))
     != NULL
     && record->asn_cnt == 1
     && record->asn_ip_cnt >= plugin_state->pfx2as_min_ip_cnt)
    {
      khiter = kh_get(u32metric, plugin_state->pfx2as_metrics,
		      record->asn[0]);

      assert(khiter != kh_end(plugin_state->pfx2as_metrics));

      metric_package_update(kh_val(plugin_state->pfx2as_metrics, khiter),
			    src_ip, dst_ip, ip_len, pkt_cnt);
    }
#endif

  /* ==================== PROTOCOL ==================== */
#ifdef WITH_PROTOCOL_STATS
  /* just basic protocol stats */
  metric_package_update(plugin_state->protocol_metrics[protocol],
			src_ip, dst_ip, ip_len, pkt_cnt);
#endif

  /* ==================== PORTS ==================== */
  /* full port stats for tcp and udp and other */
#ifdef WITH_PORT_STATS
  if(protocol == TRACE_IPPROTO_TCP)
    {
      proto = METRIC_PORT_PROTOCOL_TCP;
    }
  else if(protocol == TRACE_IPPROTO_UDP)
    {
      proto = METRIC_PORT_PROTOCOL_UDP;
    }
  else
    {
      proto = METRIC_PORT_PROTOCOL_SKIP;
    }

  if(proto != METRIC_PORT_PROTOCOL_SKIP)
    {
      if(src_port < METRIC_PORT_VAL_MAX)
	{
	  metric_package_update(plugin_state->
				port_metrics
				[proto][METRIC_PORT_DIRECTION_SRC][src_port],
				src_ip, dst_ip, ip_len, pkt_cnt);
	}

      if(dst_port < METRIC_PORT_VAL_MAX)
	{
	  metric_package_update(plugin_state->
				port_metrics
				[proto][METRIC_PORT_DIRECTION_DST][dst_port],
				src_ip, dst_ip, ip_len, pkt_cnt);
	}
    }
#endif

  return 0;
}

static void usage(corsaro_t *corsaro)
{
  assert(STATE(corsaro)->timeseries != NULL);
  timeseries_backend_t **backends = NULL;
  int i;

  fprintf(stderr,
	  "usage: %s -b backend [-b backend]\n"
	  "       -b <backend> enable the given timeseries backend,\n"
	  "                     -b can be used multiple times\n"
	  "                     available backends:\n",
	  PLUGIN(corsaro)->argv[0]);
  /* get the available backends from libtimeseries */
  backends = timeseries_get_all_backends(STATE(corsaro)->timeseries);

  for(i = 0; i < TIMESERIES_BACKEND_ID_LAST; i++)
    {
      /* skip unavailable backends */
      if(backends[i] == NULL)
	{
	  continue;
	}

      assert(timeseries_get_backend_name(backends[i]));
      fprintf(stderr, "                      - %s\n",
	      timeseries_get_backend_name(backends[i]));
    }
}


/** Parse the arguments given to the plugin */
static int parse_args(corsaro_t *corsaro)
{
  corsaro_plugin_t *plugin = PLUGIN(corsaro);
  struct corsaro_report_state_t *state = STATE(corsaro);
  int opt;

  int i;
  char *backends[TIMESERIES_BACKEND_ID_LAST];
  int backends_cnt = 0;
  char *backend_arg_ptr = NULL;
  timeseries_backend_t *backend = NULL;

  if(plugin->argc <= 0)
    {
      return 0;
    }

  /* NB: remember to reset optind to 1 before using getopt! */
  optind = 1;

  while((opt = getopt(plugin->argc, plugin->argv, ":b:?")) >= 0)
    {
      switch(opt)
	{
	case 'b':
	  backends[backends_cnt++] = strdup(optarg);
	  break;

	case '?':
	case ':':
	default:
	  usage(corsaro);
	  return -1;
	}
    }

  /* at least one backend must have been specified */
  if(backends_cnt == 0)
    {
      fprintf(stderr,
	      "ERROR: At least one backend must be specified using -b\n");
      usage(corsaro);
      goto err;
    }

  /* enable the backends that were requested */
  for(i=0; i<backends_cnt; i++)
    {
      /* the string at backends[i] will contain the name of the plugin,
	 optionally followed by a space and then the arguments to pass
	 to the plugin */
      if((backend_arg_ptr = strchr(backends[i], ' ')) != NULL)
	{
	  /* set the space to a nul, which allows backends[i] to be used
	     for the backend name, and then increment plugin_arg_ptr to
	     point to the next character, which will be the start of the
	     arg string (or at worst case, the terminating \0 */
	  *backend_arg_ptr = '\0';
	  backend_arg_ptr++;
	}

      /* lookup the backend using the name given */
      if((backend = timeseries_get_backend_by_name(state->timeseries,
						   backends[i])) == NULL)
	{
	  fprintf(stderr, "ERROR: Invalid backend name (%s)\n",
		  backends[i]);
	  usage(corsaro);
	  goto err;
	}

      if(timeseries_enable_backend(state->timeseries, backend,
				   backend_arg_ptr) != 0)
	{
	  fprintf(stderr, "ERROR: Failed to initialized backend (%s)",
		  backends[i]);
	  usage(corsaro);
	  goto err;
	}

      state->enabled_backends[state->enabled_backends_cnt++] = backend;

      /* free the string we dup'd */
      free(backends[i]);
      backends[i] = NULL;
    }

  return 0;

 err:
  for(i=0; i<backends_cnt; i++)
    {
      if(backends[i] != NULL)
	{
	  free(backends[i]);
	}
    }
  return -1;
}

/* == PUBLIC PLUGIN FUNCS BELOW HERE == */

corsaro_plugin_t *corsaro_report_alloc(corsaro_t *corsaro)
{
  return &corsaro_report_plugin;
}

int corsaro_report_probe_filename(const char *fname)
{
  /* this writes to RRD files, not readable by corsaro */
  return 0;
}

int corsaro_report_probe_magic(corsaro_in_t *corsaro, corsaro_file_in_t *file)
{
  /* this writes RRD files, not readable by corsaro */
  return 0;
}

#define METRIC_PREFIX_INIT(target, prefix, format, instance)		\
  do {									\
    char key_buffer[KEY_BUFFER_LEN];					\
    snprintf(key_buffer, KEY_BUFFER_LEN, "%s."format, prefix, instance); \
    if((target = metric_package_new(state,				\
				    key_buffer,				\
				    key_id)) == NULL)			\
      {									\
	goto err;							\
      }									\
									\
    key_id += METRIC_TYPE_CNT;						\
  } while(0)

int corsaro_report_init_output(corsaro_t *corsaro)
{
  struct corsaro_report_state_t *state;
  corsaro_plugin_t *plugin = PLUGIN(corsaro);

  /* the current key id (used by METRIC_PREFIX_INIT) */
  int key_id = 0;

#if defined(WITH_MAXMIND_STATS) || defined(WITH_NETACQ_EDGE_STATS) \
  || defined(WITH_PFX2AS_STATS) || defined(WITH_PROTOCOL_STATS)
  int i;
#endif

#ifdef WITH_PFX2AS_STATS
  /* Array of ASNs, sorted in descending order by number of IPs each AS owns */
  ipmeta_record_t **pfx2as_records;
  /* Number of records in the pfx2as_records array */
  int pfx2as_records_cnt;

  metric_package_t *tmp_mp;
  khiter_t khiter;
  int khret;
  uint32_t tmp_asn;
#endif

#if defined(WITH_MAXMIND_STATS) || defined(WITH_NETACQ_EDGE_STATS)
  const char **countries;
  int country_cnt;
  const char **continents;
  int continent_cnt;
  uint16_t country_idx;
  char cc_str[6] = "--.--";
#endif

#ifdef WITH_NETACQ_EDGE_STATS
  ipmeta_provider_t *provider;
  ipmeta_provider_netacq_edge_country_t **netacq_countries;
  int netacq_countries_cnt;
  ipmeta_provider_netacq_edge_region_t **regions;
  int regions_cnt;
#endif

#ifdef WITH_PORT_STATS
  int proto, dir, port;
#endif

  assert(plugin != NULL);

  if((state = malloc_zero(sizeof(struct corsaro_report_state_t))) == NULL)
    {
      corsaro_log(__func__, corsaro,
		"could not malloc corsaro_report_state_t");
      goto err;
    }
  corsaro_plugin_register_state(corsaro->plugin_manager, plugin, state);

  /* initialize the timeseries API
   * NOTE: do not call usage() before here
   */
  if((state->timeseries = timeseries_init()) == NULL)
    {
      corsaro_log(__func__, corsaro,
		  "could not initialize libtimeseries");
      goto err;
    }

  /* parse command-line args
     NB: this must be done after timeseries is initialized */
  if(parse_args(corsaro) != 0)
    {
      return -1;
    }

  if((state->kp = timeseries_kp_init(0)) == NULL)
    {
      corsaro_log(__func__, corsaro,
		  "could not create key package");
      goto err;
    }

  /* initialize the providers */
#ifdef WITH_MAXMIND_STATS
  /* we want to add an empty metric for all possible countries */
  country_cnt = ipmeta_provider_maxmind_get_iso2_list(&countries);
  continent_cnt =
    ipmeta_provider_maxmind_get_country_continent_list(&continents);
  assert(country_cnt == continent_cnt);

  for(i=0; i< country_cnt; i++)
    {
      /* what is the index of this country in the maxmind_country_metrics
       * array? */
      country_idx = (countries[i][0] << 8) | countries[i][1];

      /* quickly build a string which contains the continent and country code*/
      memcpy(cc_str, continents[i], 2);
      memcpy(&cc_str[3], countries[i], 2);

      METRIC_PREFIX_INIT(state->maxmind_country_metrics[country_idx],
			 METRIC_PATH_MAXMIND_COUNTRY,
			 "%s", cc_str);
    }
#endif

  /* netacq regions */
#ifdef WITH_NETACQ_EDGE_STATS
  /* get the netacq edge provider */
  if((provider =
      corsaro_ipmeta_get_provider(corsaro, IPMETA_PROVIDER_NETACQ_EDGE))
     == NULL || ipmeta_is_provider_enabled(provider) == 0)
    {
      corsaro_log(__func__, corsaro,
		  "ERROR: Net Acuity Edge provider must be enabled");
      return -1;
    }

  /* netacq countries */
  netacq_countries_cnt =
    ipmeta_provider_netacq_edge_get_countries(provider, &netacq_countries);

  if(countries == NULL || netacq_countries_cnt == 0)
    {
      corsaro_log(__func__, corsaro,
		  "ERROR: Net Acuity Edge provider must be used the -c option "
		  "to load country information");
      return -1;
    }
  for(i=0; i < netacq_countries_cnt; i++)
    {
      assert(netacq_countries[i] != NULL);

      /* convert the ascii country code to a 16bit uint */
      country_idx =
	(netacq_countries[i]->iso2[0] << 8) | netacq_countries[i]->iso2[1];

      /* build a string which contains the continent and country code*/
      /* graphite dislikes metrics with *'s in them, replace with '-' */
      cc_str[0] = (netacq_countries[i]->continent[0] == '*') ?
	'-' : netacq_countries[i]->continent[0];
      cc_str[1] = (netacq_countries[i]->continent[1] == '*') ?
	'-' : netacq_countries[i]->continent[1];

      cc_str[3] = (netacq_countries[i]->iso2[0] == '*') ?
	'-' : netacq_countries[i]->iso2[0];
      cc_str[4] = (netacq_countries[i]->iso2[1] == '*') ?
	'-' : netacq_countries[i]->iso2[1];

      /*
      memcpy(cc_str, netacq_countries[i]->continent, 2);
      memcpy(&cc_str[3], netacq_countries[i]->iso2, 2);
      */

      METRIC_PREFIX_INIT(state->netacq_country_metrics[country_idx],
			 METRIC_PATH_NETACQ_EDGE_COUNTRY,
			 "%s", cc_str);
    }

  /* net acq regions */
  regions_cnt = ipmeta_provider_netacq_edge_get_regions(provider, &regions);
  if(regions == NULL || regions_cnt == 0)
    {
      corsaro_log(__func__, corsaro,
		  "ERROR: Net Acuity Edge provider must be used the -r option "
		  "to load region information");
      return -1;
    }

  for(i=0; i < regions_cnt; i++)
    {
      assert(regions[i] != NULL);
      /* if netacq starts to allocate region codes > 2**16 we probably need to
       * switch to using a hash here. Cannot use an assert because we disable
       * those in production */
      if(regions[i]->code > METRIC_NETACQ_EDGE_REGION_MAX)
	{
	  corsaro_log(__func__, corsaro,
		      "ERROR: Net Acuity Edge region code > 2^16 found");
	  return -1;
	}
      METRIC_PREFIX_INIT(state->netacq_region_metrics[regions[i]->code],
			 METRIC_PATH_NETACQ_EDGE_REGION,
			 "%"PRIu32, regions[i]->code);
    }
#endif

#ifdef WITH_PFX2AS_STATS
  /** @todo add some code to corsaro_ipmeta that allows a plugin to check that a
      given provider is initialized */

  /* initialize the metrics hash (i can't think of a way around having this be a
     hash...) */
  state->pfx2as_metrics = kh_init(u32metric);

  /* initialize the ASNs */

  /* first, get a list of the ASN records from the pfx2as provider */
  if((pfx2as_records_cnt =
      ipmeta_provider_get_all_records(
				      corsaro_ipmeta_get_provider(corsaro,
						      IPMETA_PROVIDER_PFX2AS),
				      &pfx2as_records)) <= 0)
    {
      corsaro_log(__func__, corsaro,
		  "ERROR: could not get array of pfx2as records");
      return -1;
    }

  /* now, sort that array */
  /* note that this is sorted so that the ASNs with >1 ASN are at the
     end */
  ks_introsort(pfx2as_ip_cnt_desc,
	       pfx2as_records_cnt,
	       pfx2as_records);

  /* find out how big the smallest AS is that we are going to track */
  /* but if we want to track more ASes than actually exist, just leave the
     smallest size at it's default of zero - that will track them all */
  if(METRIC_PFX2AS_VAL_MAX < pfx2as_records_cnt)
    {
      /* now, jump to index 2999 and ask it how many IPs are in that ASN */
      assert(pfx2as_records[METRIC_PFX2AS_VAL_MAX-1] != NULL);
      assert(pfx2as_records[METRIC_PFX2AS_VAL_MAX-1]->asn_ip_cnt > 0);
      state->pfx2as_min_ip_cnt =
	pfx2as_records[METRIC_PFX2AS_VAL_MAX-1]->asn_ip_cnt;
    }

  corsaro_log(__func__, corsaro,
	      "there are %d ASNs, the ASN at index %d is %d and has %d IPs",
	      pfx2as_records_cnt,
	      METRIC_PFX2AS_VAL_MAX-1,
	      pfx2as_records[METRIC_PFX2AS_VAL_MAX-1]->asn[0],
	      state->pfx2as_min_ip_cnt);

  /* and an empty metric for each asn that we will track */
  for(i = 0;
      i < pfx2as_records_cnt &&
	pfx2as_records[i]->asn_ip_cnt >= state->pfx2as_min_ip_cnt;
      i++)
    {
      /* we simply refuse to deal with those pesky group ASNs */
      assert(pfx2as_records[i]->asn_cnt == 1);

      tmp_asn = pfx2as_records[i]->asn[0];

      /* create a metric package for this asn */
      METRIC_PREFIX_INIT(tmp_mp, METRIC_PATH_PFX2AS, "%"PRIu32, tmp_asn);

      /* now insert the mp into the hash */
      assert(kh_get(u32metric, state->pfx2as_metrics, tmp_asn)
	     == kh_end(state->pfx2as_metrics)
	     );

      khiter = kh_put(u32metric, state->pfx2as_metrics, tmp_asn, &khret);
      kh_value(state->pfx2as_metrics, khiter) = tmp_mp;
    }

  /* we're done initializing pfx2as metrics, free the pfx2as record array */
  free(pfx2as_records);
#endif

#ifdef WITH_PROTOCOL_STATS
  /* initialize the protocols */
  for(i=0; i < METRIC_PROTOCOL_VAL_MAX; i++)
    {
      /* create an empty metric package for this protocol */
      METRIC_PREFIX_INIT(state->protocol_metrics[i], METRIC_PATH_PROTOCOL,
			 "%"PRIu32, i);
    }
#endif

#ifdef WITH_PORT_STATS
  for(proto = 0; proto <= METRIC_PORT_PROTOCOL_MAX; proto++)
    {
      for(dir = 0; dir <= METRIC_PORT_DIRECTION_MAX; dir++)
	{
	  for(port = 0; port < METRIC_PORT_VAL_MAX; port++)
	    {
	      /* initialize a metric package for this proto/dir/port combo */
	      METRIC_PREFIX_INIT(state->port_metrics[proto][dir][port],
		  port_metric_paths[(proto*(METRIC_PORT_PROTOCOL_MAX+1))+dir],
				 "%"PRIu32, port);
	    }
	}
    }
#endif

  return 0;

 err:
  corsaro_report_close_output(corsaro);
  return -1;
}

int corsaro_report_init_input(corsaro_in_t *corsaro)
{
  assert(0);
  return -1;
}

int corsaro_report_close_input(corsaro_in_t *corsaro)
{
  assert(0);
  return -1;
}

int corsaro_report_close_output(corsaro_t *corsaro)
{
  /* clean up and close RRD stuff */
  struct corsaro_report_state_t *state = STATE(corsaro);

#if defined(WITH_MAXMIND_STATS) || defined(WITH_PFX2AS_STATS) ||	\
  defined(WITH_PROTOCOL_STATS) || defined(WITH_PORT_STATS)
  int i;
#endif

#ifdef WITH_PFX2AS_STATS
  khiter_t khiter;
#endif

#ifdef WITH_PORT_STATS
  int proto, dir, port;
#endif

  if(state != NULL)
    {
#ifdef WITH_MAXMIND_STATS
      for(i = 0; i < METRIC_MAXMIND_ASCII_MAX; i++)
	{
	  if(state->maxmind_country_metrics[i] != NULL)
	    {
	      metric_package_destroy(state->maxmind_country_metrics[i]);
	      state->maxmind_country_metrics[i] = NULL;
	    }
	}
#endif

#ifdef WITH_NETACQ_STATS
      for(i = 0; i < METRIC_NETACQ_EDGE_COUNTRY_MAX; i++)
	{
	  if(state->netacq_country_metrics[i] != NULL)
	    {
	      metric_package_destroy(state->netacq_country_metrics[i]);
	      state->netacq_country_metrics[i] = NULL;
	    }
	}
      for(i = 0; i < METRIC_NETACQ_EDGE_REGION_MAX; i++)
	{
	  if(state->netacq_region_metrics[i] != NULL)
	    {
	      metric_package_destroy(state->netacq_region_metrics[i]);
	      state->netacq_region_metrics[i] = NULL;
	    }
	}
#endif

#ifdef WITH_PFX2AS_STATS
      if(state->pfx2as_metrics != NULL)
	{
	  for(khiter = kh_begin(state->pfx2as_metrics);
	      khiter != kh_end(state->pfx2as_metrics);
	      ++khiter)
	    {
	      if(kh_exist(state->pfx2as_metrics, khiter))
		{
		  metric_package_destroy(kh_val(state->pfx2as_metrics,
						khiter));
		}
	    }
	  kh_destroy(u32metric, state->pfx2as_metrics);
	  state->pfx2as_metrics = NULL;
	}
#endif

#ifdef WITH_PROTOCOL_STATS
      for(i=0; i < METRIC_PROTOCOL_VAL_MAX; i++)
	{
	  if(state->protocol_metrics[i] != NULL)
	    {
	      metric_package_destroy(state->protocol_metrics[i]);
	      state->protocol_metrics[i] = NULL;
	    }
	}
#endif

#ifdef WITH_PORT_STATS
      for(proto = 0; proto <= METRIC_PORT_PROTOCOL_MAX; proto++)
	{
	  for(dir = 0; dir <= METRIC_PORT_DIRECTION_MAX; dir++)
	    {
	      for(port = 0; port < METRIC_PORT_VAL_MAX; port++)
		{
		  if(state->port_metrics[proto][dir][port] != NULL)
		    {
		      metric_package_destroy(
				     state->port_metrics[proto][dir][port]);
		      state->port_metrics[proto][dir][port] = NULL;
		    }
		}
	    }
	}
#endif

      /* free the key package */
      if(state->kp != NULL)
	{
	  timeseries_kp_free(state->kp);
	  state->kp = NULL;
	}

      /* free the timeseries framework */
      if(state->timeseries != NULL)
	{
	  timeseries_free(state->timeseries);
	  state->timeseries = NULL;
	}

      /* the backends themselves should have been free'd by timeseries_free */
      for(i=0; i<state->enabled_backends_cnt; i++)
	{
	  state->enabled_backends[i] = NULL;
	}
      state->enabled_backends_cnt = 0;

      corsaro_plugin_free_state(corsaro->plugin_manager, PLUGIN(corsaro));
    }

  return 0;
}

off_t corsaro_report_read_record(struct corsaro_in *corsaro,
			       corsaro_in_record_type_t *record_type,
			       corsaro_in_record_t *record)
{
  assert(0);
  return -1;
}

off_t corsaro_report_read_global_data_record(struct corsaro_in *corsaro,
			      enum corsaro_in_record_type *record_type,
			      struct corsaro_in_record *record)
{
  /* we write nothing to the global file. someone messed up */
  return -1;
}

int corsaro_report_start_interval(corsaro_t *corsaro,
				corsaro_interval_t *int_start)
{
  STATE(corsaro)->time = int_start->time;
  return 0;
}

int corsaro_report_end_interval(corsaro_t *corsaro,
				corsaro_interval_t *int_end)
{
#if defined(WITH_MAXMIND_STATS) || defined(WITH_NETACQ_EDGE_STATS)	\
  || defined(WITH_PFX2AS_STATS) || defined(WITH_PROTOCOL_STATS)		\
  || defined(WITH_PORT_STATS)
  struct corsaro_report_state_t *state = STATE(corsaro);
  int i;
#endif

#ifdef WITH_PFX2AS_STATS
  khiter_t khiter;
#endif

#ifdef WITH_PORT_STATS
  int proto, dir, port;
#endif

#ifdef WITH_MAXMIND_STATS
  for(i = 0; i < METRIC_MAXMIND_ASCII_MAX; i++)
    {
      /* NOTE: most of these will be NULL! */
      if(state->maxmind_country_metrics[i] != NULL)
	{
	  metric_package_dump(state, state->maxmind_country_metrics[i]);
	}
    }
#endif

#ifdef WITH_NETACQ_EDGE_STATS
  for(i = 0; i < METRIC_NETACQ_EDGE_COUNTRY_MAX; i++)
    {
      /* NOTE: most of these will be NULL! */
      if(state->netacq_country_metrics[i] != NULL)
	{
	  metric_package_dump(state, state->netacq_country_metrics[i]);
	}

      /* NOTE: most of these will be NULL! */
      if(state->netacq_region_metrics[i] != NULL)
	{
	  metric_package_dump(state, state->netacq_region_metrics[i]);
	}
    }
#endif

#ifdef WITH_PFX2AS_STATS
  for(khiter = kh_begin(state->pfx2as_metrics);
      khiter != kh_end(state->pfx2as_metrics);
      ++khiter)
    {
      if(kh_exist(state->pfx2as_metrics, khiter))
	{
	  metric_package_dump(state, kh_val(state->pfx2as_metrics,
					khiter));
	}
    }
#endif

#ifdef WITH_PROTOCOL_STATS
  /* dump the protocol metrics */
  for(i = 0; i < METRIC_PROTOCOL_VAL_MAX; i++)
    {
      metric_package_dump(state, state->protocol_metrics[i]);
    }
#endif

#ifdef WITH_PORT_STATS
  for(proto = 0; proto <= METRIC_PORT_PROTOCOL_MAX; proto++)
    {
      for(dir = 0; dir <= METRIC_PORT_DIRECTION_MAX; dir++)
	{
	  for(port = 0; port < METRIC_PORT_VAL_MAX; port++)
	    {
	      if(state->port_metrics[proto][dir][port] != NULL)
		{
		  metric_package_dump(state,
				      state->port_metrics[proto][dir][port]);
		}
	    }
	}
    }
#endif

#if defined(WITH_MAXMIND_STATS) || defined(WITH_PFX2AS_STATS) ||	\
  defined(WITH_PROTOCOL_STATS) || defined(WITH_PORT_STATS)
  /* now flush to each backend */
  for(i=0; i<state->enabled_backends_cnt; i++)
    {
      timeseries_kp_flush(state->enabled_backends[i], state->kp, state->time);
    }
#endif

  return 0;
}

int corsaro_report_process_packet(corsaro_t *corsaro,
				corsaro_packet_t *packet)
{
  libtrace_packet_t *ltpacket = LT_PKT(packet);
  libtrace_ip_t  *ip_hdr  = NULL;
  libtrace_icmp_t *icmp_hdr = NULL;
  uint16_t src_port;
  uint16_t dst_port;

  /* check for ipv4 */
  if((ip_hdr = trace_get_ip(ltpacket)) == NULL)
    {
      /* not an ip packet */
      return 0;
    }

  if(ip_hdr->ip_p == TRACE_IPPROTO_ICMP &&
     (icmp_hdr = trace_get_icmp(ltpacket)) != NULL)
    {
      src_port = icmp_hdr->type;
      dst_port = icmp_hdr->code;
    }
  else
    {
      src_port = trace_get_source_port(ltpacket);
      dst_port = trace_get_destination_port(ltpacket);
    }

  if(process_generic(corsaro, &packet->state,
		     ip_hdr->ip_src.s_addr,
		     ip_hdr->ip_dst.s_addr,
		     src_port, dst_port,
		     ntohs(ip_hdr->ip_len),
		     ip_hdr->ip_p,
		     1) != 0)
    {
      return -1;
    }

  return 0;
}

#ifdef WITH_PLUGIN_SIXT
int corsaro_report_process_flowtuple(corsaro_t *corsaro,
				     corsaro_flowtuple_t *flowtuple,
				     corsaro_packet_state_t *state)
{
  if(process_generic(corsaro, state,
		     corsaro_flowtuple_get_source_ip(flowtuple),
		     corsaro_flowtuple_get_destination_ip(flowtuple),
		     ntohs(flowtuple->src_port), ntohs(flowtuple->dst_port),
		     ntohs(flowtuple->ip_len), flowtuple->protocol,
		     ntohl(flowtuple->packet_cnt)) != 0)
    {
      return -1;
    }
  return 0;
}

int corsaro_report_process_flowtuple_class_start(corsaro_t *corsaro,
				   corsaro_flowtuple_class_start_t *class)
{
  /* we dont care about these */
  return 0;
}

int corsaro_report_process_flowtuple_class_end(corsaro_t *corsaro,
				   corsaro_flowtuple_class_end_t *class)
{
  /* dont care */
  return 0;
}
#endif
