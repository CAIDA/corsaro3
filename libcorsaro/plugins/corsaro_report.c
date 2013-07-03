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

#include "libtrace.h"

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

/* ---------- TURN THINGS ON AND OFF ---------- */

#define WITH_MAXMIND_STATS
#define WITH_PFX2AS_STATS
#define WITH_PROTOCOL_STATS
#define WITH_PORT_STATS 

/* ---------- GLOBAL METRIC SETTINGS ---------- */

/** The prefix to attach to all metrics */
#define METRIC_PREFIX "darknet.ucsd-nt"

#define METRIC_UNIQ_SRC_IP "uniq_src_ip"
#define METRIC_UNIQ_DST_IP "uniq_dst_ip"
#define METRIC_PKT_CNT "pkt_cnt"
#define METRIC_IP_LEN "ip_len"

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

#define METRIC_PORT_HASH_CNT (METRIC_PROTOCOL_MAX+METRIC_DIRECTION_MAX+1)

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


#define DUMP_METRIC(path, key_format, key, metric, value, time)	    \
  fprintf(stdout, "%s."key_format"."metric" %"PRIu64" %"PRIu32"\n", \
	  path, key, value, time);

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
				     khiter_t *khiter,
				     uint32_t key)
{
  corsaro_report_metrics_t *new_metrics = NULL;
  int khret;

  /* check if this key is in the hash already */
  if((*khiter = kh_get(u32metric, hash, key)) == kh_end(hash))
    {
      /* create a new country struct */
      if((new_metrics = malloc(sizeof(corsaro_report_metrics_t))) == NULL)
	{
	  /* could not malloc the memory. this is bad */
	  return -1;
	}

      /* create a new src ip map */
      new_metrics->uniq_src_ip = kh_init(32xx);
      /* create a new dst ip map */
      new_metrics->uniq_dst_ip = kh_init(32xx);

      /* zero the packet count (better than a memset 0 on all of it?) */
      new_metrics->pkt_cnt = 0;
      /* and the byte count */
      new_metrics->ip_len = 0;

      /* add it to the hash */
      *khiter = kh_put(u32metric, hash, key, &khret);
      kh_value(hash, *khiter) = new_metrics;
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

  if(u32metric_hash_new_record(hash, &khiter, key) != 0)
    {
      return -1;
    }

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

static void u32metric_hash_dump(khash_t(u32metric) *hash, char *metric_path,
				int is_country, 
				uint32_t time)
{
  corsaro_report_metrics_t *metrics = NULL;
  khiter_t i;
  char country_code[6];
  country_code[5] = '\0';
  country_code[2] = '.';

  uint32_t key_val;

  for(i = kh_begin(hash); i != kh_end(hash); ++i)
    {	
      if(kh_exist(hash, i))
	{
	  metrics = kh_value(hash, i);
	  
	  if(is_country != 0)
	    {
	      country_code[0] = (kh_key(hash, i) & 0xFF000000) >> 24;
	      country_code[1] = (kh_key(hash, i) & 0x00FF0000) >> 16;
	      /* country_code[2] = '.'; */
	      country_code[3] = (kh_key(hash, i) & 0x0000FF00) >> 8;
	      country_code[4] = kh_key(hash, i)  & 0x000000FF;

	      DUMP_METRIC(metric_path, "%s", country_code, METRIC_UNIQ_SRC_IP,
			  (uint64_t)kh_size(metrics->uniq_src_ip), time);

	      DUMP_METRIC(metric_path, "%s", country_code, METRIC_UNIQ_DST_IP,
			  (uint64_t)kh_size(metrics->uniq_dst_ip), time);

	      DUMP_METRIC(metric_path, "%s", country_code, METRIC_PKT_CNT,
			  metrics->pkt_cnt, time);

	      DUMP_METRIC(metric_path, "%s", country_code, METRIC_IP_LEN,
			  metrics->ip_len, time);
	    }
	  else
	    {
	      key_val = kh_key(hash, i);

	      DUMP_METRIC(metric_path, "%"PRIu32, key_val, 
			  METRIC_UNIQ_SRC_IP,
			  (uint64_t)kh_size(metrics->uniq_src_ip), time);

	      DUMP_METRIC(metric_path, "%"PRIu32, key_val, 
			  METRIC_UNIQ_DST_IP,
			  (uint64_t)kh_size(metrics->uniq_dst_ip), time);

	      DUMP_METRIC(metric_path, "%"PRIu32, key_val, 
			  METRIC_PKT_CNT,
			  metrics->pkt_cnt, time);

	      DUMP_METRIC(metric_path, "%"PRIu32, key_val, 
			  METRIC_IP_LEN,
			  metrics->ip_len, time);
	    }

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

#if defined(WITH_MAXMIND_STATS) || defined(WITH_PFX2AS_STATS) ||	\
  defined(WITH_PROTOCOL_STATS) || defined(WITH_PORT_STATS)
  int i;
  khiter_t khiter;
#endif

#ifdef WITH_MAXMIND_STATS
  const char **countries;
  int country_cnt;
  const char **continents;
  int continent_cnt;
  uint32_t cc;
#endif

#ifdef WITH_PORT_STATS
  int j;
#endif

  assert(plugin != NULL);
 
  if((state = malloc_zero(sizeof(struct corsaro_report_state_t))) == NULL)
    {
      corsaro_log(__func__, corsaro, 
		"could not malloc corsaro_report_state_t");
      goto err;
    }
  corsaro_plugin_register_state(corsaro->plugin_manager, plugin, state);

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

      /* create empty metrics for this country */
      u32metric_hash_new_record(state->country_hash,
				&khiter,
				cc);
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

      /* create empty metrics for this country */
      u32metric_hash_new_record(state->asn_hash,
				&khiter,
				state->pfx2as_records[i]->asn[0]);
    }
#endif

#ifdef WITH_PROTOCOL_STATS
  state->protocol_hash = kh_init(u32metric);

  /* initialize the protocols */
  /* and an empty metric for each possible asn */
  for(i=0; i < METRIC_PROTOCOL_VAL_MAX; i++)
    {
      /* create empty metrics for this country */
      u32metric_hash_new_record(state->protocol_hash,
				&khiter,
				i);
    }
#endif

#ifdef WITH_PORT_STATS
  for(i=0;i<METRIC_PORT_HASH_CNT; i+=(METRIC_DIRECTION_MAX+1))
    {
        state->port_hash[i+METRIC_DIRECTION_SRC] = kh_init(u32metric);
        state->port_hash[i+METRIC_DIRECTION_DST] = kh_init(u32metric);
    }

  /* and an empty metric for each possible port */
  for(i=0; i < METRIC_PORT_VAL_MAX; i++)
    {
      for(j=0; j<METRIC_PORT_HASH_CNT; j+=(METRIC_DIRECTION_MAX+1))
	{
	  u32metric_hash_new_record(state->port_hash[j+METRIC_DIRECTION_SRC],
				  &khiter,
				  i);
	  u32metric_hash_new_record(state->port_hash[j+METRIC_DIRECTION_DST],
				  &khiter,
				  i);
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
  /*corsaro_io_print_interval_start(int_start);*/
  STATE(corsaro)->time = int_start->time;
  return 0;
}

int corsaro_report_end_interval(corsaro_t *corsaro, 
				corsaro_interval_t *int_end)
{
#if defined(WITH_MAXMIND_STATS) || defined(WITH_PFX2AS_STATS) ||	\
  defined(WITH_PROTOCOL_STATS) || defined(WITH_PORT_STATS)
  struct corsaro_report_state_t *state = STATE(corsaro);
#endif

#ifdef WITH_PORT_STATS
  int i;
#endif

#ifdef WITH_MAXMIND_STATS
  /* dump the country hash */
  u32metric_hash_dump(state->country_hash, METRIC_PATH_MAXMIND_COUNTRY, 1,
		      state->time);
#endif

#ifdef WITH_PFX2AS_STATS
  /* dump the asn hash */
  u32metric_hash_dump(state->asn_hash, METRIC_PATH_PFX2AS, 0,
		      state->time);
#endif

#ifdef WITH_PROTOCOL_STATS
  /* dump the protocol hash */
  u32metric_hash_dump(state->protocol_hash, METRIC_PATH_PROTOCOL, 0,
		      state->time);
#endif

#ifdef WITH_PORT_STATS
  for(i = 0; i < METRIC_PORT_HASH_CNT;  i+=(METRIC_DIRECTION_MAX+1))
    {
      u32metric_hash_dump(state->port_hash[i+METRIC_DIRECTION_SRC], 
			  port_metric_paths[i+METRIC_DIRECTION_SRC], 0,
			  state->time);
      u32metric_hash_dump(state->port_hash[i+METRIC_DIRECTION_DST], 
			  port_metric_paths[i+METRIC_DIRECTION_DST], 0,
			  state->time);
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
