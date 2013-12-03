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

#include <libtimeseries.h>
#include <libtrace.h>

#include "khash.h"
#include "ksort.h"
#include "utils.h"

#include "corsaro_geo.h"
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

/* ---------- TURN THINGS ON AND OFF ---------- */

#define WITH_MAXMIND_STATS
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

KSORT_INIT(pfx2as_ip_cnt_desc, corsaro_geo_record_t*, pfx2as_ip_cnt_lt);

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
  METRIC_PROTOCOL_SKIP  = -1,
  METRIC_PROTOCOL_TCP   = 0,
  METRIC_PROTOCOL_UDP   = 2,
  /*  METRIC_PROTOCOL_OTHER = 4,*/

  METRIC_PROTOCOL_MAX = METRIC_PROTOCOL_UDP,
};

enum {
  METRIC_DIRECTION_SRC = 0,
  METRIC_DIRECTION_DST = 1,

  METRIC_DIRECTION_MAX = METRIC_DIRECTION_DST,
};

/* number of hashes is the last protocol index, plus the number of directions
   for *that* protocol */
#define METRIC_PORT_HASH_CNT (METRIC_PROTOCOL_MAX+(METRIC_DIRECTION_MAX+1))

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

/* to count the number of unique src ips per country */
KHASH_SET_INIT_INT(32xx)

typedef struct corsaro_report_metrics {
  uint32_t id_offset;
  khash_t(32xx) *uniq_src_ip;
  khash_t(32xx) *uniq_dst_ip;
  uint64_t pkt_cnt;
  uint64_t ip_len;
} corsaro_report_metrics_t;

KHASH_INIT(u32metric, uint32_t, corsaro_report_metrics_t *, 1,
	   kh_int_hash_func, kh_int_hash_equal)

/** Holds the state for an instance of this plugin */
struct corsaro_report_state_t {

#ifdef WITH_MAXMIND_STATS
  /** Hash of countries that point to metrics */
  khash_t(u32metric) *country_hash;
  /** Pointer to the Maxmind Geo Provider */
  corsaro_geo_provider_t *maxmind_provider;
#endif

#ifdef WITH_PFX2AS_STATS
  /** Array of ASNs, sorted in descending order by number of IPs each AS owns */
  corsaro_geo_record_t **pfx2as_records;
  /** Number of records in the pfx2as_records array */
  int pfx2as_records_cnt;
  /** The minimum number of IPs that an ASN can have before it is considered for
      reporting (based on smallest the top METRIC_PFX2AS_VAL_MAX ASes) */
  int pfx2as_min_ip_cnt;
  /** Hash of asns that point to metrics */
  khash_t(u32metric) *asn_hash;
  /** Pointer to the PFX2AS Geo Provider */
  corsaro_geo_provider_t *pfx2as_provider;
#endif

#ifdef WITH_PROTOCOL_STATS
  /** Hash of protocols that point to metrics */
  khash_t(u32metric) *protocol_hash;
#endif

#ifdef WITH_PORT_STATS
  /** Hash of (tcp|udp) (src|dst) ports that point to metrics
   * Indexes are at [METRIC_PROTOCOL_TCP+METRIC_DIRECTION_SRC], etc
   */
  khash_t(u32metric) *port_hash[METRIC_PORT_HASH_CNT];
#endif

  /** libtimeseries state */
  timeseries_t *timeseries;

  /** The libtimeseries backend(s) we will write to */
  timeseries_backend_t *enabled_backends[TIMESERIES_BACKEND_MAX];

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
static int u32metric_hash_new_record(khash_t(u32metric) *hash,
				     uint32_t id_offset,
				     uint32_t key)
{
  corsaro_report_metrics_t *new_metrics = NULL;
  khiter_t khiter;
  int khret;

  /* check if this key is in the hash already */
  if((khiter = kh_get(u32metric, hash, key)) == kh_end(hash))
    {
      /* create a new country struct */
      if((new_metrics = malloc(sizeof(corsaro_report_metrics_t))) == NULL)
	{
	  /* could not malloc the memory. this is bad */
	  return -1;
	}

      /* the id of this metric in the key package */
      new_metrics->id_offset = id_offset;

      /* create a new src ip map */
      new_metrics->uniq_src_ip = kh_init(32xx);
      /* create a new dst ip map */
      new_metrics->uniq_dst_ip = kh_init(32xx);

      /* zero the packet count (better than a memset 0 on all of it?) */
      new_metrics->pkt_cnt = 0;
      /* and the byte count */
      new_metrics->ip_len = 0;

      /* add it to the hash */
      khiter = kh_put(u32metric, hash, key, &khret);
      kh_value(hash, khiter) = new_metrics;
    }
  return 0;
}

static int u32metric_hash_add_record(khash_t(u32metric) *hash,
				     uint32_t key,
				     uint32_t src_ip, uint32_t dst_ip,
				     uint16_t ip_len,
				     uint64_t pkt_cnt)
{
  corsaro_report_metrics_t *new_metrics = NULL;
  khiter_t khiter;
  int khret;

  /* all records must already be in the hash */
  khiter = kh_get(u32metric, hash, key);
  assert(khiter != kh_end(hash));

  new_metrics = kh_value(hash, khiter);

  /* now simply add the src ip to the map */
  kh_put(32xx, new_metrics->uniq_src_ip, src_ip, &khret);
  /* and add the dst ip */
  kh_put(32xx, new_metrics->uniq_dst_ip, dst_ip, &khret);
  /* and increment the packet count */
  new_metrics->pkt_cnt+=pkt_cnt;
  /* and increment the byte counter */
  new_metrics->ip_len+=(ip_len*pkt_cnt);

  return 0;
}

static void u32metric_hash_destroy(khash_t(u32metric) *hash)
{
  khiter_t i;

  /* we need to free all the ip maps */
  for(i = kh_begin(hash); i != kh_end(hash); ++i)
    {
      if(kh_exist(hash, i))
	{
	  /* free the src ip map */
	  kh_destroy(32xx,
		     (kh_val(hash, i))->uniq_src_ip);

	  /* free the dst ip map */
	  kh_destroy(32xx,
		     (kh_val(hash, i))->uniq_dst_ip);

	  /* finally, free the metric struct */
	  free(kh_val(hash, i));
	}
    }

  kh_destroy(u32metric, hash);
}

static void u32metric_hash_dump(struct corsaro_report_state_t *state,
				khash_t(u32metric) *hash)
{
  corsaro_report_metrics_t *metrics = NULL;
  khiter_t i;

  for(i = kh_begin(hash); i != kh_end(hash); ++i)
    {
      if(kh_exist(hash, i))
	{
	  metrics = kh_value(hash, i);

	  timeseries_kp_set(state->kp,
			    metrics->id_offset+METRIC_TYPE_UNIQ_SRC_IP,
			    (uint64_t)kh_size(metrics->uniq_src_ip));

	  timeseries_kp_set(state->kp,
			    metrics->id_offset+METRIC_TYPE_UNIQ_DST_IP,
			    (uint64_t)kh_size(metrics->uniq_dst_ip));

	  timeseries_kp_set(state->kp,
			    metrics->id_offset+METRIC_TYPE_PKT_CNT,
			    metrics->pkt_cnt);

	  timeseries_kp_set(state->kp,
			    metrics->id_offset+METRIC_TYPE_IP_LEN,
			    metrics->ip_len);

	  /* empty the maps for this country */
	  kh_clear(32xx, metrics->uniq_src_ip);
	  kh_clear(32xx, metrics->uniq_dst_ip);
	  /* reset the counters */
	  metrics->pkt_cnt = 0;
	  metrics->ip_len = 0;
	}
    }
}
#endif

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

#ifdef WITH_MAXMIND_STATS
  uint32_t cc = 0x2D2D2D2D; /* "----" */
#endif

#if defined(WITH_MAXMIND_STATS) || defined(WITH_PFX2AS_STATS)
  corsaro_geo_record_t *record;
#endif

  /* ==================== COUNTRY CODES ==================== */
#ifdef WITH_MAXMIND_STATS
  assert(plugin_state->maxmind_provider != NULL);

  /* we will only look at the first record for this packet */
  if((record = corsaro_geo_next_record(plugin_state->maxmind_provider, NULL))
     != NULL)
    {
      if(record->country_code != NULL)
	{
	  cc = (record->country_code[0]<<8) | record->country_code[1];
	}
      if(record->continent_code > 0)
	{
	  cc &= 0x0000FFFF;
	  cc |= (record->continent_code & 0x0000FFFF) << 16;
	}
    }

  /* now store the 'hashed' country code */
  if(u32metric_hash_add_record(plugin_state->country_hash,
			       cc,
			       src_ip, dst_ip,
			       ip_len, pkt_cnt) != 0)
    {
      corsaro_log(__func__, corsaro, "failed to update country hash");
      return -1;
    }
#endif

  /* ==================== PFX2AS ASNs ==================== */
#ifdef WITH_PFX2AS_STATS
  assert(plugin_state->pfx2as_provider != NULL);

  /* we will only look at the first record for this packet */
  /* note we are deliberately discarding ASN records that have more than one ASN
     because we consider them an artifact of the measurement */
  /* we are also discarding any AS that is smaller than the smallest AS in our
     top METRIC_PFX2AS_VAL_MAX ASes list. */
  /* note that this means there may *occasionally* be more than
     METRIC_PFX2AS_VAL_MAX ASes dumped. this will only happen when there are
     multiple ASes of size plugin_state->pfx2as_min_ip_cnt */
  /* also note that we are NOT recording stats for packets that we cannot
     compute ans ASN for */
  if((record = corsaro_geo_next_record(plugin_state->pfx2as_provider, NULL))
     != NULL
     && record->asn_cnt == 1
     && record->asn_ip_cnt >= plugin_state->pfx2as_min_ip_cnt)
    {
      /* now store the 'hashed' asn */
      if(u32metric_hash_add_record(plugin_state->asn_hash,
				   record->asn[0],
				   src_ip, dst_ip,
				   ip_len, pkt_cnt) != 0)
	{
	  corsaro_log(__func__, corsaro, "failed to update asn hash");
	  return -1;
	}
    }
#endif

  /* ==================== PROTOCOL ==================== */
#ifdef WITH_PROTOCOL_STATS
  /* just basic protocol stats */
  if(u32metric_hash_add_record(plugin_state->protocol_hash,
			       protocol,
			       src_ip, dst_ip,
			       ip_len, pkt_cnt) != 0)
    {
      corsaro_log(__func__, corsaro, "failed to update protocol hash");
      return -1;
    }
#endif

  /* ==================== PORTS ==================== */
  /* full port stats for tcp and udp and other */
#ifdef WITH_PORT_STATS
  if(protocol == TRACE_IPPROTO_TCP)
    {
      proto = METRIC_PROTOCOL_TCP;
    }
  else if(protocol == TRACE_IPPROTO_UDP)
    {
      proto = METRIC_PROTOCOL_UDP;
    }
  else
    {
      proto = METRIC_PROTOCOL_SKIP;
      /*proto = METRIC_PROTOCOL_OTHER;*/
    }

  if(proto != METRIC_PROTOCOL_SKIP)
    {
      if(src_port < METRIC_PORT_VAL_MAX &&
	 u32metric_hash_add_record(plugin_state->
				   port_hash[proto+METRIC_DIRECTION_SRC],
				   src_port, src_ip, dst_ip,
				   ip_len, pkt_cnt) != 0)
	{
	  corsaro_log(__func__, corsaro, "failed to update src port hash");
	  return -1;
	}

      if(dst_port < METRIC_PORT_VAL_MAX &&
	 u32metric_hash_add_record(plugin_state->
				   port_hash[proto+METRIC_DIRECTION_DST],
				   dst_port, src_ip, dst_ip,
				   ip_len, pkt_cnt) != 0)
	{
	  corsaro_log(__func__, corsaro, "failed to update src port hash");
	  return -1;
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

  for(i = 0; i < TIMESERIES_BACKEND_MAX; i++)
    {
      assert(backends[i] != NULL);
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
  char *backends[TIMESERIES_BACKEND_MAX];
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

  /* report doesn't take any extra arguments */
  if(optind != plugin->argc)
    {
      usage(corsaro);
      return -1;
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
	  fprintf(stderr, "ERROR: Could not enable backend %s\n",
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

int corsaro_report_init_output(corsaro_t *corsaro)
{
  struct corsaro_report_state_t *state;
  corsaro_plugin_t *plugin = PLUGIN(corsaro);

  /* the current key id */
  int key_id = 0;
  char key_buffer[KEY_BUFFER_LEN];

#if defined(WITH_MAXMIND_STATS) || defined(WITH_PFX2AS_STATS) ||	\
  defined(WITH_PROTOCOL_STATS) || defined(WITH_PORT_STATS)
  int i, j;
#endif

#ifdef WITH_MAXMIND_STATS
  const char **countries;
  int country_cnt;
  const char **continents;
  int continent_cnt;
  uint32_t cc;
#endif

#ifdef WITH_PORT_STATS
  int k, l;
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
  /* first, ask for the maxmind provider */
  if((state->maxmind_provider = corsaro_geo_get_by_id(corsaro,
				       CORSARO_GEO_PROVIDER_MAXMIND)) == NULL)
    {
      /* no provider? this can't be what they want */
      corsaro_log(__func__, corsaro,
		  "ERROR: Maxmind Geolocation Provider is required");
      return -1;
    }

  state->country_hash = kh_init(u32metric);

  /* we want to add an empty metric for all possible countries */
  country_cnt = corsaro_geo_get_maxmind_iso2_list(&countries);
  continent_cnt = corsaro_geo_get_maxmind_country_continent_list(&continents);
  assert(country_cnt == continent_cnt);
  for(i=0; i< country_cnt; i++)
    {
      cc = (continents[i][0] << 24) | (continents[i][1] << 16) |
	(countries[i][0]<<8) | countries[i][1];

      for(j=0; j<METRIC_TYPE_CNT; j++)
	{
	  /* generate a key for this metric and insert it in the key package */
	  snprintf(key_buffer, KEY_BUFFER_LEN,
		   "%s.%s.%s.%s",
		   METRIC_PATH_MAXMIND_COUNTRY,
		   continents[i],
		   countries[i],
		   metric_type_names[j]);

	  timeseries_kp_add_key(state->kp, key_buffer);
	}

      /* create empty metrics for this country */
      u32metric_hash_new_record(state->country_hash,
				key_id,
				cc);

      key_id += METRIC_TYPE_CNT;
    }

#endif

#ifdef WITH_PFX2AS_STATS
  /* now, ask for the pfx2as provider */
  if((state->pfx2as_provider = corsaro_geo_get_by_id(corsaro,
				       CORSARO_GEO_PROVIDER_PFX2AS)) == NULL)
    {
      /* no provider? this can't be what they want */
      corsaro_log(__func__, corsaro,
		  "ERROR: PFX2AS Provider is required");
      return -1;
    }

  state->asn_hash = kh_init(u32metric);

  /* initialize the ASNs */

  /* first, get a list of the ASN records from the pfx2as provider */
  if((state->pfx2as_records_cnt =
      corsaro_geo_get_all_records(state->pfx2as_provider,
				  &state->pfx2as_records)) <= 0)
    {
      corsaro_log(__func__, corsaro,
		  "ERROR: could not get array of pfx2as records");
      return -1;
    }

  /* now, sort that array */
  /* note that this is sorted so that the ASNs with >1 ASN are at the
     end */
  ks_introsort(pfx2as_ip_cnt_desc,
	       state->pfx2as_records_cnt,
	       state->pfx2as_records);

  /* find out how big the smallest AS is that we are going to track */
  /* but if we want to track more ASes than actually exist, just leave the
     smallest size at it's default of zero - that will track them all */
  if(METRIC_PFX2AS_VAL_MAX < state->pfx2as_records_cnt)
    {
      /* now, jump to index 2999 and ask it how many IPs are in that ASN */
      assert(state->pfx2as_records[METRIC_PFX2AS_VAL_MAX-1] != NULL);
      assert(state->pfx2as_records[METRIC_PFX2AS_VAL_MAX-1]->asn_ip_cnt > 0);
      state->pfx2as_min_ip_cnt =
	state->pfx2as_records[METRIC_PFX2AS_VAL_MAX-1]->asn_ip_cnt;
    }

  corsaro_log(__func__, corsaro,
	      "there are %d ASNs, the ASN at index %d is %d and has %d IPs",
	      state->pfx2as_records_cnt,
	      METRIC_PFX2AS_VAL_MAX-1,
	      state->pfx2as_records[METRIC_PFX2AS_VAL_MAX-1]->asn[0],
	      state->pfx2as_min_ip_cnt);

  /* and an empty metric for each asn that we will track */
  for(i=0;
      i<state->pfx2as_records_cnt &&
	state->pfx2as_records[i]->asn_ip_cnt >= state->pfx2as_min_ip_cnt;
      i++)
    {
      /*
      corsaro_log(__func__, corsaro, "pos: %d\tasn: %d\tcnt: %d\tasn_cnt:%d",
		  i, state->pfx2as_records[i]->asn[0],
		  state->pfx2as_records[i]->asn_ip_cnt,
		  state->pfx2as_records[i]->asn_cnt);
      */

      /* we simply refuse to deal with those pesky group ASNs */
      assert(state->pfx2as_records[i]->asn_cnt == 1);

      for(j=0; j<METRIC_TYPE_CNT; j++)
	{
	  /* generate a key for this metric and insert it in the key package */
	  snprintf(key_buffer, KEY_BUFFER_LEN,
		   "%s.%"PRIu32".%s",
		   METRIC_PATH_PFX2AS,
		   state->pfx2as_records[i]->asn[0],
		   metric_type_names[j]);

	  timeseries_kp_add_key(state->kp, key_buffer);
	}

      /* create empty metrics for this ASN */
      u32metric_hash_new_record(state->asn_hash,
				key_id,
				state->pfx2as_records[i]->asn[0]);

      key_id += METRIC_TYPE_CNT;
    }
#endif

#ifdef WITH_PROTOCOL_STATS
  state->protocol_hash = kh_init(u32metric);

  /* initialize the protocols */
  /* and an empty metric for each possible asn */
  for(i=0; i < METRIC_PROTOCOL_VAL_MAX; i++)
    {
      for(j=0; j<METRIC_TYPE_CNT; j++)
	{
	  /* generate a key for this metric and insert it in the key package */
	  snprintf(key_buffer, KEY_BUFFER_LEN,
		   "%s.%"PRIu32".%s",
		   METRIC_PATH_PROTOCOL,
		   i,
		   metric_type_names[j]);

	  timeseries_kp_add_key(state->kp, key_buffer);
	}

      /* create empty metrics for this country */
      u32metric_hash_new_record(state->protocol_hash,
				key_id,
				i);

      key_id += METRIC_TYPE_CNT;
    }
#endif

#ifdef WITH_PORT_STATS
  for(i=0; i<METRIC_PORT_HASH_CNT; i+=(METRIC_DIRECTION_MAX+1))
    {
        state->port_hash[i+METRIC_DIRECTION_SRC] = kh_init(u32metric);
        state->port_hash[i+METRIC_DIRECTION_DST] = kh_init(u32metric);
    }

  /* and an empty metric for each possible port */
  /* @todo consider re-working the nesting order of these loops */
  for(i=0; i < METRIC_PORT_VAL_MAX; i++) /* PORT NUMBER */
    {
      for(j=0; j<METRIC_PORT_HASH_CNT; j+=(METRIC_DIRECTION_MAX+1)) /* PROTOCOL */
	{
	  for(k=0; k<=METRIC_DIRECTION_MAX; k++) /* DIRECTION */
	    {
	      for(l=0; l<METRIC_TYPE_CNT; l++) /* suffix */
		{
		  /* generate a key for this metric and insert it in the key
		     package */
		  snprintf(key_buffer, KEY_BUFFER_LEN,
			   "%s.%"PRIu32".%s",
			   port_metric_paths[j+k],
			   i,
			   metric_type_names[l]);

		  timeseries_kp_add_key(state->kp, key_buffer);
		}

	      u32metric_hash_new_record(state->port_hash[j+k],
					key_id,
					i);
	      key_id += METRIC_TYPE_CNT;
	    }
	}
    }
#endif

  /* set up the RRD stuff here? */

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

#ifdef WITH_PORT_STATS
  int i;
#endif

  if(state != NULL)
    {
#ifdef WITH_MAXMIND_STATS
      if(state->country_hash != NULL)
	{
	  u32metric_hash_destroy(state->country_hash);
	  state->country_hash = NULL;
	}
#endif

#ifdef WITH_PFX2AS_STATS
      if(state->asn_hash != NULL)
	{
	  u32metric_hash_destroy(state->asn_hash);
	  state->asn_hash = NULL;
	}
#endif

#ifdef WITH_PROTOCOL_STATS
      if(state->protocol_hash != NULL)
	{
	  u32metric_hash_destroy(state->protocol_hash);
	  state->protocol_hash = NULL;
	}
#endif

#ifdef WITH_PORT_STATS
      for(i = 0; i < METRIC_PORT_HASH_CNT; i+=(METRIC_DIRECTION_MAX+1))
	{
	  if(state->port_hash[i+METRIC_DIRECTION_SRC] != NULL)
	    {
	      u32metric_hash_destroy(state->port_hash[i+METRIC_DIRECTION_SRC]);
	      state->port_hash[i+METRIC_DIRECTION_SRC] = NULL;
	    }
	  if(state->port_hash[i+METRIC_DIRECTION_DST] != NULL)
	    {
	      u32metric_hash_destroy(state->port_hash[i+METRIC_DIRECTION_DST]);
	      state->port_hash[i+METRIC_DIRECTION_DST] = NULL;
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
#if defined(WITH_MAXMIND_STATS) || defined(WITH_PFX2AS_STATS) ||	\
  defined(WITH_PROTOCOL_STATS) || defined(WITH_PORT_STATS)
  struct corsaro_report_state_t *state = STATE(corsaro);
  int i;
#endif

#ifdef WITH_MAXMIND_STATS
  /* dump the country hash */
  u32metric_hash_dump(state, state->country_hash);
#endif

#ifdef WITH_PFX2AS_STATS
  /* dump the asn hash */
  u32metric_hash_dump(state, state->asn_hash);
#endif

#ifdef WITH_PROTOCOL_STATS
  /* dump the protocol hash */
  u32metric_hash_dump(state, state->protocol_hash);
#endif

#ifdef WITH_PORT_STATS
  for(i = 0; i < METRIC_PORT_HASH_CNT;  i+=(METRIC_DIRECTION_MAX+1))
    {
      u32metric_hash_dump(state, state->port_hash[i+METRIC_DIRECTION_SRC]);
      u32metric_hash_dump(state, state->port_hash[i+METRIC_DIRECTION_DST]);
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
