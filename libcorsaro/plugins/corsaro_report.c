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
#include "corsaro_tag.h"

#ifdef WITH_PLUGIN_SIXT
#include "corsaro_flowtuple.h"
#endif

#include "corsaro_report.h"
#include "corsaro_report_config.h"

/** @file
 *
 * @brief Corsaro FlowTuple Reporting plugin
 *
 * @author Alistair King
 *
 */

/** The magic number for this plugin - "REPT" */
#define CORSARO_REPORT_MAGIC 0x52455054

/** The name of this plugin */
#define PLUGIN_NAME "report"

/** The length of the buffer used to construct key names */
#define KEY_BUFFER_LEN 1024

/* to count the number of unique src ips per country */
KHASH_INIT(32xx, khint32_t, char, 0, kh_int_hash_func2, kh_int_hash_equal)

/** Common plugin information across all instances */
static corsaro_plugin_t corsaro_report_plugin = {
  PLUGIN_NAME,                                 /* name */
  CORSARO_PLUGIN_ID_REPORT,                    /* id */
  CORSARO_REPORT_MAGIC,                        /* magic */
  CORSARO_PLUGIN_GENERATE_PTRS(corsaro_report),
  CORSARO_PLUGIN_GENERATE_TAIL,
};

/** Structure which holds state about sub-metrics for each metric */
typedef struct leafmetric_package {
  uint32_t id_offset;
  enum tree_id tree_id;
  enum submetric_id submetric_id;
  khash_t(32xx) *uniq_src_ip;
  khash_t(32xx) *uniq_dst_ip;
  uint64_t pkt_cnt;
  uint64_t ip_len;
} leafmetric_package_t;

/** a hash type to map ISO3 country codes to a continent.ISO2 string */
KHASH_INIT(strstr, char*, char*, 1, kh_str_hash_func, kh_str_hash_equal)

/** Convert a 2 char byte array to a 16 bit number */
#define CC_16(bytes)    ((bytes[0] << 8) | bytes[1])

static inline void str_free(char *str)
{
  free(str);
}

KSORT_INIT(pfx2as_ip_cnt_desc, ipmeta_record_t*, pfx2as_ip_cnt_lt);

KHASH_INIT(u32metric, uint32_t, leafmetric_package_t *, 1,
	   kh_int_hash_func2, kh_int_hash_equal)

/** Holds the state for an instance of a filter */
typedef struct metric_tree {

  /** ID of this tree
   *
   * The tree ID, in conjunction with tree_submetrics[id] will determine which
   * of these fields are used in a given tree
   *
   */
  enum tree_id id;

  /** The tag group that will determine whether metrics in this tree get
      updated */
  corsaro_tag_group_t *group;

  /** Bit flags indicating which sub metrics are in use in this tree */
  uint8_t used_metrics;

  /** Bit flags indicating which leaf metrics are in use in this tree */
  uint8_t used_leaf_metrics;

  /** Array of continents (converted to integers) that point to metrics.
   *
   * Even though it uses more memory, we create an array that can hold 2^16
   * continents -- this allows us to directly index a country based on the
   * conversion of the ascii characters in each 2 character code.
   */
  leafmetric_package_t *maxmind_continent_metrics[METRIC_MAXMIND_ASCII_MAX];

  /** Array of countries (converted to integers) that point to metrics.
   *
   * Even though it uses more memory, we create an array that can hold 2^16
   * countries -- this allows us to directly index a country based on the
   * conversion of the ascii characters in each ISO 3166 2 character code.
   */
  leafmetric_package_t *maxmind_country_metrics[METRIC_MAXMIND_ASCII_MAX];

  /** Array of continent codes (specific to netacq) that point to metrics.
   *
   * Even though it uses more memory, we create an array that can hold 2^16
   * countries -- this allows us to directly index a continent based on the
   * conversion of the ascii characters in each 2 character code.
   */
  leafmetric_package_t *netacq_continent_metrics[METRIC_NETACQ_EDGE_ASCII_MAX];

  /** Array of country codes (specific to netacq) that point to metrics.
   *
   * Even though it uses more memory, we create an array that can hold 2^16
   * countries -- this allows us to directly index a country based on the
   * conversion of the ascii characters in each ISO 3166 2 character code.
   */
  leafmetric_package_t *netacq_country_metrics[METRIC_NETACQ_EDGE_ASCII_MAX];

  /** Array of region codes (specific to netacq) that point to metrics.
   *
   * Note that many of these will be NULL
   */
  leafmetric_package_t *netacq_region_metrics[METRIC_NETACQ_EDGE_ASCII_MAX];

  /** Array of polygon ids (specific to vasco) that point to metrics.
   *
   * Note that many of these will be NULL
   */
  leafmetric_package_t *netacq_poly_metrics[METRIC_NETACQ_EDGE_POLYS_TBL_CNT][METRIC_NETACQ_EDGE_ASCII_MAX];

  /** The minimum number of IPs that an ASN can have before it is considered for
      reporting (based on smallest the top METRIC_PFX2AS_VAL_MAX ASes) */
  int pfx2as_min_ip_cnt;

  /** Hash of asns that point to metrics */
  khash_t(u32metric) *pfx2as_metrics;

  /** Array of protocols that each contain a metric */
  leafmetric_package_t *protocol_metrics[METRIC_PROTOCOL_VAL_MAX];

  /** Array of port metrics */
  leafmetric_package_t *port_metrics[METRIC_PORT_PROTOCOL_MAX+1]	\
  [METRIC_PORT_DIRECTION_MAX+1][METRIC_PORT_VAL_CNT];

  /** Array of filter metrics
   * This will have the same number of elements, and be in the same order, as
   * the array of tags returned by corsaro_tag_group_get_tags
   */
  leafmetric_package_t **filter_metrics;

  /** number of elements in the filter metrics array */
  int filter_metrics_cnt;

  /** Overall stats for a tree */
  leafmetric_package_t *tree_metrics;
} metric_tree_t;

/** Holds the state for an instance of this plugin */
struct corsaro_report_state_t {
  /** which tree(s) are we actually tracking (run-time config) */
  int trees_enabled;

  /** array of metric trees that we are tracking */
  metric_tree_t *trees[TREE_ID_CNT];

  /** Array of tags that we are filtering packets with */
  corsaro_tag_t *tags[ARR_CNT(tag_defs)];

  /** Total number of tags that we are applying */
  int tags_cnt;

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

  /* CACHED INFO FOR TREE BUILDING */

  /** Array of continents that correspond to maxmind countries */
  const char **maxmind_continents;

  /** Number of maxmind country-continent entries */
  int maxmind_continents_cnt;

  /** Array of maxmind countries */
  const char **maxmind_countries;

  /** Number of maxmind countries */
  int maxmind_countries_cnt;
};

/** Extends the generic plugin state convenience macro in corsaro_plugin.h */
#define STATE(corsaro)						\
  (CORSARO_PLUGIN_STATE(corsaro, report, CORSARO_PLUGIN_ID_REPORT))

/** Extends the generic plugin plugin convenience macro in corsaro_plugin.h */
#define PLUGIN(corsaro)						\
  (CORSARO_PLUGIN_PLUGIN(corsaro, CORSARO_PLUGIN_ID_REPORT))

#define METRIC_KEY_INIT(lmid)						\
  do {									\
  snprintf(key_buffer, KEY_BUFFER_LEN,					\
	   "%s.%s", metric_prefix, leafmetric_names[lmid]);		\
  timeseries_kp_add_key(state->kp, key_buffer);				\
  (*id_offset)++;							\
  } while(0)

#define LMP_IF(lmflag)					\
  if((tree_submetric_leafmetrics[mp->tree_id][mp->submetric_id] & lmflag) != 0)

static leafmetric_package_t *leafmetric_package_new(
					struct corsaro_report_state_t *state,
					enum tree_id tree_id,
					enum submetric_id submetric_id,
					const char *metric_prefix,
					uint32_t *id_offset)
{
  leafmetric_package_t *mp = NULL;
  char key_buffer[KEY_BUFFER_LEN];

  /* allocate memory for the metric package */
  if((mp = malloc(sizeof(leafmetric_package_t))) == NULL)
    {
      /* could not malloc the memory. this is bad */
      return NULL;
    }

  /* store the tree that owns this leafmetric package
     needed to determine which elements of the package are in use */
  mp->tree_id = tree_id;

  /* store the submetric id that owns this leafmetric package
     this allows us to determine which elements of the package are in use */
  mp->submetric_id = submetric_id;

  /* the id of the first metric in the key package */
  mp->id_offset = *id_offset;

  LMP_IF(LEAFMETRIC_FLAG_UNIQ_SRC_IP)
    {
      mp->uniq_src_ip = kh_init(32xx);
      METRIC_KEY_INIT(LEAFMETRIC_ID_UNIQ_SRC_IP);
    }

  LMP_IF(LEAFMETRIC_FLAG_UNIQ_DST_IP)
    {
      mp->uniq_dst_ip = kh_init(32xx);
      METRIC_KEY_INIT(LEAFMETRIC_ID_UNIQ_DST_IP);
    }

  LMP_IF(LEAFMETRIC_FLAG_PKT_CNT)
    {
      mp->pkt_cnt = 0;
      METRIC_KEY_INIT(LEAFMETRIC_ID_PKT_CNT);
    }

  LMP_IF(LEAFMETRIC_FLAG_IP_LEN)
    {
      mp->ip_len = 0;
      METRIC_KEY_INIT(LEAFMETRIC_ID_IP_LEN);
    }

  return mp;
}

static void metric_package_destroy(leafmetric_package_t *mp)
{
  assert(mp != NULL);

  /* free the src ip map */
  LMP_IF(LEAFMETRIC_FLAG_UNIQ_SRC_IP)
    {
      kh_destroy(32xx, mp->uniq_src_ip);
    }

  /* free the dst ip map */
  LMP_IF(LEAFMETRIC_FLAG_UNIQ_DST_IP)
    {
      kh_destroy(32xx, mp->uniq_dst_ip);
    }

  /* finally, free the metric package */
  free(mp);

  return;
}

static void metric_package_update(leafmetric_package_t *mp,
				  uint32_t src_ip,
				  uint32_t dst_ip,
				  uint16_t ip_len,
				  uint64_t pkt_cnt)
{
  int khret;
  assert(mp != NULL);

  LMP_IF(LEAFMETRIC_FLAG_UNIQ_SRC_IP)
    {
      /* add the src ip to the map */
      kh_put(32xx, mp->uniq_src_ip, src_ip, &khret);
    }

  LMP_IF(LEAFMETRIC_FLAG_UNIQ_DST_IP)
    {
      /* add the dst ip */
      kh_put(32xx, mp->uniq_dst_ip, dst_ip, &khret);
    }

  LMP_IF(LEAFMETRIC_FLAG_PKT_CNT)
    {
      /* increment the packet count */
      mp->pkt_cnt+=pkt_cnt;
    }

  LMP_IF(LEAFMETRIC_FLAG_IP_LEN)
    {
      /* increment the byte counter */
      mp->ip_len+=(ip_len*pkt_cnt);
    }

  return;
}

static void metric_package_dump(struct corsaro_report_state_t *state,
				leafmetric_package_t *mp)
{
  int offset = 0;
  LMP_IF(LEAFMETRIC_FLAG_UNIQ_SRC_IP)
    {
      timeseries_kp_set(state->kp,
			mp->id_offset+offset,
			(uint64_t)kh_size(mp->uniq_src_ip));

      kh_clear(32xx, mp->uniq_src_ip);
      offset++;
    }

  LMP_IF(LEAFMETRIC_FLAG_UNIQ_DST_IP)
    {
      timeseries_kp_set(state->kp,
			mp->id_offset+offset,
			(uint64_t)kh_size(mp->uniq_dst_ip));

      kh_clear(32xx, mp->uniq_dst_ip);
      offset++;
    }

  LMP_IF(LEAFMETRIC_FLAG_PKT_CNT)
    {
      timeseries_kp_set(state->kp,
			mp->id_offset+offset,
			mp->pkt_cnt);

      mp->pkt_cnt = 0;
      offset++;
    }

  LMP_IF(LEAFMETRIC_FLAG_IP_LEN)
    {
      timeseries_kp_set(state->kp,
			mp->id_offset+offset,
			mp->ip_len);

      mp->ip_len = 0;
      offset++;
    }
}

#define METRIC_PREFIX_INIT(treeid, smid, target, prefix, format, instance) \
  do {									\
    char key_buffer[KEY_BUFFER_LEN];					\
    snprintf(key_buffer, KEY_BUFFER_LEN, METRIC_PREFIX".%s%s."format,	\
	     tree->group->name, prefix, instance);			\
    if((target = leafmetric_package_new(state,				\
					treeid,				\
					smid,				\
					key_buffer,			\
					&key_id)) == NULL)		\
      {									\
	goto err;							\
      }									\
  } while(0)

#define SM_IF(smid)							\
    if((tree_submetric_leafmetrics[tree->id][smid]) != 0)

/** Create a new metric tree for the given tag
 *
 * @todo this code is copied directly from when it only ran once, so it builds
 * several data structures and massages metric names etc in a way that could
 * perhaps be abstracted into a prep function that gets run only once prior to
 * building the trees.
 */
static metric_tree_t *metric_tree_new(corsaro_t *corsaro, int tree_id,
				      uint32_t *id_offset)
{
  metric_tree_t *tree = NULL;
  struct corsaro_report_state_t *state = STATE(corsaro);

  uint32_t key_id = *id_offset;

  ipmeta_provider_t *provider;

  corsaro_tag_t **tags;
  int tags_cnt;

  int i;
  khiter_t khiter;
  int khret;
  /* Array of ASNs, sorted in descending order by number of IPs each AS owns */
  ipmeta_record_t **pfx2as_records;
  /* Number of records in the pfx2as_records array */
  int pfx2as_records_cnt;
  leafmetric_package_t *tmp_mp;
  uint32_t tmp_asn;

  char cc_str[6] = "--.--";
  uint16_t country_idx;
  uint16_t continent_idx;

  ipmeta_provider_netacq_edge_country_t **netacq_countries = NULL;
  int netacq_countries_cnt = 0;
  ipmeta_provider_netacq_edge_region_t **regions = NULL;
  int regions_cnt = 0;
  ipmeta_polygon_table_t **poly_tbls = NULL;
  int poly_tbls_cnt = 0;
  ipmeta_polygon_table_t *table = NULL;

  ipmeta_record_t **records;
  int records_cnt = 0;

  char *cc_ptr;
  char *cc_cpy;
  khash_t(strstr) *country_hash = kh_init(strstr);
  int j;

  char rc_str[10]; /* XX.XX.XXX\0 */

  int proto, dir, port;

  assert(tree_id >= 0 && tree_id < TREE_ID_CNT);

  /* create a new tree */
  if((tree = malloc_zero(sizeof(metric_tree_t))) == NULL)
    {
      corsaro_log(__func__, corsaro, "could not malloc metric tree");
      return NULL;
    }

  tree->id = tree_id;

  /* create a tag group for this tree */
  if((tree->group = corsaro_tag_group_init(corsaro,
					   tree_names[tree_id],
					   CORSARO_TAG_GROUP_MATCH_MODE_ALL,
					   NULL)) == NULL)
    {
      corsaro_log(__func__, corsaro,
		  "could not create group for %s",
		  tree_names[tree_id]);
      goto err;
    }

  /* loop over all the tags and add appropriate ones to our group */
  for(i=0; i<state->tags_cnt; i++)
    {
      assert(state->tags[i] != NULL);
      if((tag_defs[i].tree_flags & tree_flags[tree_id]) != 0)
	{
	  if(corsaro_tag_group_add_tag(tree->group, state->tags[i]) != 0)
	    {
	      corsaro_log(__func__, corsaro,
			  "could not add tag %s to group %s",
			  state->tags[i]->name, tree_names[tree_id]);
	      goto err;
	    }
	}
    }

  /* initialize only the submetrics that this tree needs */

  SM_IF(SUBMETRIC_ID_TREE)
  {
    char key_buffer[KEY_BUFFER_LEN];
    snprintf(key_buffer, KEY_BUFFER_LEN, METRIC_PREFIX ".%s" METRIC_PATH_TREE,
	     tree->group->name);
    if((tree->tree_metrics = leafmetric_package_new(state,
						    tree_id,
						    SUBMETRIC_ID_TREE,
						    key_buffer,
						    &key_id)) == NULL)
      {
	goto err;
      }
  }

  SM_IF(SUBMETRIC_ID_FILTER)
  {
    /* get the tags for this tree */
    if((tags_cnt = corsaro_tag_group_get_tags(tree->group, &tags)) < 0)
      {
	corsaro_log(__func__, corsaro, "could not get tags for tree group");
	return NULL;
      }

    /* malloc enough space to hold the leaf packages */
    if((tree->filter_metrics =
	malloc_zero(sizeof(leafmetric_package_t*)*(tags_cnt))) == NULL)
      {
	return NULL;
      }

    tree->filter_metrics_cnt = tags_cnt;

    /* add a metric package for each tag */
    for(i=0; i<tags_cnt; i++)
      {
	METRIC_PREFIX_INIT(tree_id, SUBMETRIC_ID_FILTER,
			   tree->filter_metrics[i],
			   METRIC_PATH_FILTER,
			   "%s", tags[i]->name);
      }
  }

  SM_IF(SUBMETRIC_ID_MAXMIND_CONTINENT)
  {
    /* add a metric package for all possible continents */
    for(i=0; i < ARR_CNT(continent_strings); i++)
      {
	/* what is the index of this continent in the
	   maxmind_continent_metrics array? */
	continent_idx = CC_16(continent_strings[i]);

	METRIC_PREFIX_INIT(tree_id, SUBMETRIC_ID_MAXMIND_CONTINENT,
			   tree->maxmind_continent_metrics[continent_idx],
			   METRIC_PATH_MAXMIND_CONTINENT,
			   "%s", continent_strings[i]);
      }
  }

  SM_IF(SUBMETRIC_ID_MAXMIND_COUNTRY)
  {
    /* we want to add an empty metric for all possible countries */
    for(i=0; i< state->maxmind_countries_cnt; i++)
      {
	/* what is the index of this country in the maxmind_country_metrics
	 * array? */
	country_idx = CC_16(state->maxmind_countries[i]);

	/* build a string which contains the continent and country code */
	memcpy(cc_str, state->maxmind_continents[i], 2);
	memcpy(&cc_str[3], state->maxmind_countries[i], 2);

	METRIC_PREFIX_INIT(tree_id, SUBMETRIC_ID_MAXMIND_COUNTRY,
			   tree->maxmind_country_metrics[country_idx],
			   METRIC_PATH_MAXMIND_COUNTRY,
			   "%s", cc_str);
      }
  }


  if(tree_submetric_leafmetrics[tree_id][SUBMETRIC_ID_NETACQ_EDGE_CONTINENT] != 0
     ||
     tree_submetric_leafmetrics[tree_id][SUBMETRIC_ID_NETACQ_EDGE_COUNTRY] != 0
     ||
     tree_submetric_leafmetrics[tree_id][SUBMETRIC_ID_NETACQ_EDGE_REGION] != 0)
    {
      /* get the netacq edge provider */
      if((provider =
	  corsaro_ipmeta_get_provider(corsaro, IPMETA_PROVIDER_NETACQ_EDGE))
	 == NULL || ipmeta_is_provider_enabled(provider) == 0)
	{
	  corsaro_log(__func__, corsaro,
		      "ERROR: Net Acuity Edge provider must be enabled");
	  return NULL;
	}

      /* ensure there are actually some records */
      if((records_cnt = ipmeta_provider_get_all_records(provider, &records)) == 0)
	{
	  corsaro_log(__func__, corsaro,
		      "ERROR: Net Acuity is reporting no records loaded.");
	  return NULL;
	}
      free(records); /* @todo add a simple record count func to ipmeta */

      netacq_countries_cnt =
	ipmeta_provider_netacq_edge_get_countries(provider, &netacq_countries);

      if(netacq_countries == NULL || netacq_countries_cnt == 0)
	{
	  corsaro_log(__func__, corsaro,
		      "ERROR: Net Acuity Edge provider must be used with the -c"
		      " option to load country information");
	  return NULL;
	}

      SM_IF(SUBMETRIC_ID_NETACQ_EDGE_CONTINENT)
      {
	/* add a metric package for all possible continents */
	for(i=0; i < ARR_CNT(continent_strings); i++)
	  {
	    /* what is the index of this continent in the array? */
	    continent_idx = CC_16(continent_strings[netacq_cont_map[i]]);

	    METRIC_PREFIX_INIT(tree_id, SUBMETRIC_ID_NETACQ_EDGE_CONTINENT,
			       tree->netacq_continent_metrics[continent_idx],
			       METRIC_PATH_NETACQ_EDGE_CONTINENT,
			       "%s", continent_strings[netacq_cont_map[i]]);
	  }
      }

      for(i=0; i < netacq_countries_cnt; i++)
	{
	  assert(netacq_countries[i] != NULL);

	  /* convert the ascii country code to a 16bit uint */
	  country_idx = CC_16(netacq_countries[i]->iso2);

	  /* build a string which contains the continent and country code*/
	  cc_ptr = cc_str;
	  cc_ptr = stpncpy(cc_ptr,
			   continent_strings[netacq_cont_map[netacq_countries[i]->continent_code]],
			   3);
	  *cc_ptr = '.';
	  cc_ptr++;
	  stpncpy(cc_ptr, netacq_countries[i]->iso2, 3);

	  /* graphite dislikes metrics with *'s in them, replace with '-' */
	  /* NOTE: this is only for the time series string */
	  for(j=0; j<strnlen(cc_str, 5); j++)
	    {
	      if(cc_str[j] == '*')
		{
		  cc_str[j] = '-';
		}
	    }

	  if((cc_cpy = strndup(cc_str, 5)) == NULL)
	    {
	      corsaro_log(__func__, corsaro,
			  "could not allocate country string");
	      return NULL;
	    }
	  khiter = kh_put(strstr, country_hash,
			  netacq_countries[i]->iso3, &khret);
	  kh_value(country_hash, khiter) = cc_cpy;

	  SM_IF(SUBMETRIC_ID_NETACQ_EDGE_COUNTRY)
	    {
	      METRIC_PREFIX_INIT(tree_id, SUBMETRIC_ID_NETACQ_EDGE_COUNTRY,
				 tree->netacq_country_metrics[country_idx],
				 METRIC_PATH_NETACQ_EDGE_COUNTRY,
				 "%s", cc_str);
	    }
	}

      SM_IF(SUBMETRIC_ID_NETACQ_EDGE_REGION)
	{
	  regions_cnt = ipmeta_provider_netacq_edge_get_regions(provider,
								&regions);
	  if(regions == NULL || regions_cnt == 0)
	    {
	      corsaro_log(__func__, corsaro,
			  "ERROR: Net Acuity Edge provider must be used with "
			  "the -r option to load region information");
	      return NULL;
	    }

	  for(i=0; i < regions_cnt; i++)
	    {
	      assert(regions[i] != NULL);
	      /* if netacq starts to allocate region codes > 2**16 we probably
	       * need to switch to using a hash here. Cannot use an assert
	       * because we disable those in production */
	      if(regions[i]->code > METRIC_NETACQ_EDGE_ASCII_MAX)
		{
		  corsaro_log(__func__, corsaro,
			      "ERROR: Net Acuity Edge region code > 2^16 found");
		  return NULL;
		}

	      /* get the continent/country code string */
	      khiter = kh_get(strstr, country_hash, regions[i]->country_iso);
	      assert(khiter != kh_end(country_hash));

	      cc_ptr = kh_value(country_hash, khiter);
	      cc_ptr = stpncpy(rc_str, cc_ptr, 6);
	      cc_ptr = stpncpy(cc_ptr, ".", 1);
	      strncpy(cc_ptr, regions[i]->region_iso, 4);

	      /* fix the *'s */
	      for(; *cc_ptr != '\0'; cc_ptr++)
		{
		  if(*cc_ptr == '*')
		    {
		      *cc_ptr = '-';
		    }
		}

	      METRIC_PREFIX_INIT(tree_id, SUBMETRIC_ID_NETACQ_EDGE_REGION,
				 tree->netacq_region_metrics[regions[i]->code],
				 METRIC_PATH_NETACQ_EDGE_REGION,
				 "%s", rc_str);
	    }
	}

      SM_IF(SUBMETRIC_ID_NETACQ_EDGE_POLYS)
	{
	  poly_tbls_cnt =
            ipmeta_provider_netacq_edge_get_polygon_tables(provider,
                                                           &poly_tbls);
	  if(poly_tbls == NULL || poly_tbls_cnt == 0)
	    {
	      corsaro_log(__func__, corsaro,
			  "ERROR: Net Acuity Edge provider must be used with "
			  "the -p and -t options to load polygon information");
	      return NULL;
	    }

          if(poly_tbls_cnt != METRIC_NETACQ_EDGE_POLYS_TBL_CNT)
            {
              corsaro_log(__func__, corsaro,
                          "ERROR: Exactly %d polygon tables required, %d found",
                          METRIC_NETACQ_EDGE_POLYS_TBL_CNT,
                          poly_tbls_cnt);
              return NULL;
            }

          for(i=0; i<poly_tbls_cnt; i++)
            {
              table = poly_tbls[i];
              for(j=0; j<table->polygons_cnt; j++)
                {
                  assert(table->polygons[j] != NULL);
                  /* if vasco starts to allocate polygon codes > 2**16 we
                   * probably need to switch to using a hash here. Cannot use an
                   * assert because we disable those in production */
                  if(table->polygons[j]->id > METRIC_NETACQ_EDGE_ASCII_MAX)
                    {
                      corsaro_log(__func__, corsaro,
			      "ERROR: Net Acuity Edge polygon id > 2^16 found");
                      return NULL;
                    }

                  METRIC_PREFIX_INIT(tree_id, SUBMETRIC_ID_NETACQ_EDGE_POLYS,
                                     tree->netacq_poly_metrics[i][
                                                      table->polygons[j]->id],
                                     METRIC_PATH_NETACQ_EDGE_POLYS,
                                     "%s", table->polygons[j]->fqid);
                }
            }
        }

      kh_free_vals(strstr, country_hash, str_free);
      kh_destroy(strstr, country_hash);
    }


  SM_IF(SUBMETRIC_ID_PFX2AS)
    {
      /* initialize the metrics hash (i can't think of a way around having this
	 be a hash...) */
      tree->pfx2as_metrics = kh_init(u32metric);

      /* initialize the ASNs */

      if((provider =
	  corsaro_ipmeta_get_provider(corsaro, IPMETA_PROVIDER_PFX2AS))
	 == NULL ||
	 ipmeta_is_provider_enabled(provider) == 0)
	{
	  corsaro_log(__func__, corsaro,
		      "ERROR: CAIDA Prefix-to-AS provider must be enabled");
	  return NULL;
	}

      /* first, get a list of the ASN records from the pfx2as provider */
      if((pfx2as_records_cnt =
	  ipmeta_provider_get_all_records(provider,
					  &pfx2as_records)) <= 0)
	{
	  corsaro_log(__func__, corsaro,
		      "ERROR: could not get array of pfx2as records");
	  return NULL;
	}

      /* now, sort that array */
      /* note that this is sorted so that the ASNs with >1 ASN are at the end */
      ks_introsort(pfx2as_ip_cnt_desc,
		   pfx2as_records_cnt,
		   pfx2as_records);

      /* find out how big the smallest AS is that we are going to track */
      /* but if we want to track more ASes than actually exist, just leave the
	 smallest size at it's default of zero - that will track them all */
      if(tree_pfx2as_max[tree->id] < pfx2as_records_cnt)
	{
	  /* now, jump to index 2999 and ask it how many IPs are in that ASN */
	  assert(pfx2as_records[tree_pfx2as_max[tree->id]-1] != NULL);
	  assert(pfx2as_records[tree_pfx2as_max[tree->id]-1]->asn_ip_cnt > 0);
	  tree->pfx2as_min_ip_cnt =
	    pfx2as_records[tree_pfx2as_max[tree->id]-1]->asn_ip_cnt;

	  corsaro_log(__func__, corsaro,
		      "there are %d ASNs, the ASN at index %d is %d "
		      "and has %d IPs",
		      pfx2as_records_cnt,
		      tree_pfx2as_max[tree->id]-1,
		      pfx2as_records[tree_pfx2as_max[tree->id]-1]->asn[0],
		      tree->pfx2as_min_ip_cnt);
	}

      /* and an empty metric for each asn that we will track */
      for(i = 0;
	  i < pfx2as_records_cnt &&
	    pfx2as_records[i]->asn_ip_cnt >= tree->pfx2as_min_ip_cnt;
	  i++)
	{
	  /* we simply refuse to deal with those pesky group ASNs */
	  if(pfx2as_records[i]->asn_cnt != 1)
	    {
	      continue;
	    }

	  tmp_asn = pfx2as_records[i]->asn[0];

	  /* create a metric package for this asn */
	  METRIC_PREFIX_INIT(tree_id, SUBMETRIC_ID_PFX2AS,
			     tmp_mp, METRIC_PATH_PFX2AS, "%"PRIu32, tmp_asn);

	  /* now insert the mp into the hash */
	  assert(kh_get(u32metric, tree->pfx2as_metrics, tmp_asn)
		 == kh_end(tree->pfx2as_metrics)
		 );

	  khiter = kh_put(u32metric, tree->pfx2as_metrics, tmp_asn, &khret);
	  kh_value(tree->pfx2as_metrics, khiter) = tmp_mp;
	}

      /* we're done initializing pfx2as metrics, free the pfx2as record array */
      free(pfx2as_records);
    }

  SM_IF(SUBMETRIC_ID_PROTOCOL)
    {
      /* initialize the protocols */
      for(i=0; i < METRIC_PROTOCOL_VAL_MAX; i++)
	{
	  /* create an empty metric package for this protocol */
	  METRIC_PREFIX_INIT(tree_id, SUBMETRIC_ID_PROTOCOL,
			     tree->protocol_metrics[i], METRIC_PATH_PROTOCOL,
			     "%"PRIu32, i);
	}
    }

  SM_IF(SUBMETRIC_ID_PORT)
    {
      for(proto = 0; proto <= METRIC_PORT_PROTOCOL_MAX; proto++)
	{
	  for(dir = 0; dir <= METRIC_PORT_DIRECTION_MAX; dir++)
	    {
	      for(port = 0; port < tree_port_max[tree_id]; port++)
		{
		  /* initialize a metric package for this proto/dir/port combo */
		  METRIC_PREFIX_INIT(tree_id, SUBMETRIC_ID_PORT,
				     tree->port_metrics[proto][dir][port],
				     port_metric_paths[
				        (proto*(METRIC_PORT_PROTOCOL_MAX+1))+dir
				     ],
				     "%"PRIu32, port);
		}
	    }
	}
    }

  /* pass back the updated key id */
  *id_offset = key_id;
  return tree;

 err:
  corsaro_report_close_output(corsaro);
  return NULL;
}

static void metric_tree_destroy(metric_tree_t *tree)
{
  if(tree == NULL)
    {
      return;
    }

  int i, j;
  khiter_t khiter;
  int proto, dir, port;

  SM_IF(SUBMETRIC_ID_TREE)
  {
    if(tree->tree_metrics != NULL)
      {
	    metric_package_destroy(tree->tree_metrics);
	    tree->tree_metrics = NULL;
      }
  }

  SM_IF(SUBMETRIC_ID_FILTER)
  {
    for(i = 0; i < tree->filter_metrics_cnt; i++)
      {
	if(tree->filter_metrics[i] != NULL)
	  {
	    metric_package_destroy(tree->filter_metrics[i]);
	    tree->filter_metrics[i] = NULL;
	  }
      }
    tree->filter_metrics_cnt = 0;
  }

  SM_IF(SUBMETRIC_ID_MAXMIND_CONTINENT)
  {
    for(i = 0; i < METRIC_MAXMIND_ASCII_MAX; i++)
      {
	if(tree->maxmind_continent_metrics[i] != NULL)
	  {
	    metric_package_destroy(tree->maxmind_continent_metrics[i]);
	    tree->maxmind_continent_metrics[i] = NULL;
	  }
      }
  }

  SM_IF(SUBMETRIC_ID_MAXMIND_COUNTRY)
  {
    for(i = 0; i < METRIC_MAXMIND_ASCII_MAX; i++)
      {
	if(tree->maxmind_country_metrics[i] != NULL)
	  {
	    metric_package_destroy(tree->maxmind_country_metrics[i]);
	    tree->maxmind_country_metrics[i] = NULL;
	  }
      }
  }

  SM_IF(SUBMETRIC_ID_NETACQ_EDGE_CONTINENT)
  {
    for(i = 0; i < METRIC_NETACQ_EDGE_ASCII_MAX; i++)
      {
	if(tree->netacq_continent_metrics[i] != NULL)
	  {
	    metric_package_destroy(tree->netacq_continent_metrics[i]);
	    tree->netacq_continent_metrics[i] = NULL;
	  }
      }
  }

  SM_IF(SUBMETRIC_ID_NETACQ_EDGE_COUNTRY)
  {
    for(i = 0; i < METRIC_NETACQ_EDGE_ASCII_MAX; i++)
      {
	if(tree->netacq_country_metrics[i] != NULL)
	  {
	    metric_package_destroy(tree->netacq_country_metrics[i]);
	    tree->netacq_country_metrics[i] = NULL;
	  }
      }
  }

  SM_IF(SUBMETRIC_ID_NETACQ_EDGE_REGION)
  {
    for(i = 0; i < METRIC_NETACQ_EDGE_ASCII_MAX; i++)
      {
	if(tree->netacq_region_metrics[i] != NULL)
	  {
	    metric_package_destroy(tree->netacq_region_metrics[i]);
	    tree->netacq_region_metrics[i] = NULL;
	  }
      }
  }

  SM_IF(SUBMETRIC_ID_NETACQ_EDGE_POLYS)
  {
    for(i=0; i<METRIC_NETACQ_EDGE_POLYS_TBL_CNT; i++)
      {
        for(j=0; j<METRIC_NETACQ_EDGE_ASCII_MAX; j++)
          {
            if(tree->netacq_poly_metrics[i][j] != NULL)
              {
                metric_package_destroy(tree->netacq_poly_metrics[i][j]);
                tree->netacq_poly_metrics[i][j] = NULL;
              }
          }
      }
  }

  SM_IF(SUBMETRIC_ID_PFX2AS)
  {
    if(tree->pfx2as_metrics != NULL)
      {
	for(khiter = kh_begin(tree->pfx2as_metrics);
	    khiter != kh_end(tree->pfx2as_metrics);
	    ++khiter)
	  {
	    if(kh_exist(tree->pfx2as_metrics, khiter))
	      {
		metric_package_destroy(kh_val(tree->pfx2as_metrics,
					      khiter));
	      }
	  }
	kh_destroy(u32metric, tree->pfx2as_metrics);
	tree->pfx2as_metrics = NULL;
      }
  }

  SM_IF(SUBMETRIC_ID_PROTOCOL)
  {
    for(i=0; i < METRIC_PROTOCOL_VAL_MAX; i++)
      {
	if(tree->protocol_metrics[i] != NULL)
	  {
	    metric_package_destroy(tree->protocol_metrics[i]);
	    tree->protocol_metrics[i] = NULL;
	  }
      }
  }

  SM_IF(SUBMETRIC_ID_PORT)
  {
    for(proto = 0; proto <= METRIC_PORT_PROTOCOL_MAX; proto++)
      {
	for(dir = 0; dir <= METRIC_PORT_DIRECTION_MAX; dir++)
	  {
	    for(port = 0; port < tree_port_max[tree->id]; port++)
	      {
		if(tree->port_metrics[proto][dir][port] != NULL)
		  {
		    metric_package_destroy(
					   tree->port_metrics[proto][dir][port]);
		    tree->port_metrics[proto][dir][port] = NULL;
		  }
	      }
	  }
      }
  }

  return;
}

#define DUMP_ARRAY(array, length)					\
  for(i = 0; i < length; i++)						\
    {									\
      if(array[i] != NULL)						\
	{								\
	  metric_package_dump(state, array[i]);				\
	}								\
    }

static int metric_tree_dump(struct corsaro_report_state_t *state,
			    enum tree_id tree_id)
{
  int i, j;
  khiter_t khiter;
  int proto, dir, port;

  metric_tree_t *tree = state->trees[tree_id];

  SM_IF(SUBMETRIC_ID_TREE)
  {
    metric_package_dump(state, tree->tree_metrics);
  }

  SM_IF(SUBMETRIC_ID_FILTER)
  {
    DUMP_ARRAY(tree->filter_metrics, tree->filter_metrics_cnt)
  }

  SM_IF(SUBMETRIC_ID_MAXMIND_CONTINENT)
  {
    DUMP_ARRAY(tree->maxmind_continent_metrics, METRIC_MAXMIND_ASCII_MAX)
  }

  SM_IF(SUBMETRIC_ID_MAXMIND_COUNTRY)
  {
    DUMP_ARRAY(tree->maxmind_country_metrics, METRIC_MAXMIND_ASCII_MAX)
  }

  SM_IF(SUBMETRIC_ID_NETACQ_EDGE_CONTINENT)
  {
    DUMP_ARRAY(tree->netacq_continent_metrics, METRIC_NETACQ_EDGE_ASCII_MAX)
  }

  SM_IF(SUBMETRIC_ID_NETACQ_EDGE_COUNTRY)
  {
    DUMP_ARRAY(tree->netacq_country_metrics, METRIC_NETACQ_EDGE_ASCII_MAX)
  }

  SM_IF(SUBMETRIC_ID_NETACQ_EDGE_REGION)
  {
    DUMP_ARRAY(tree->netacq_region_metrics, METRIC_NETACQ_EDGE_ASCII_MAX)
  }

  SM_IF(SUBMETRIC_ID_NETACQ_EDGE_POLYS)
  {
    for(j=0; j<METRIC_NETACQ_EDGE_POLYS_TBL_CNT; j++)
      {
        DUMP_ARRAY(tree->netacq_poly_metrics[j], METRIC_NETACQ_EDGE_ASCII_MAX)
      }
  }

  SM_IF(SUBMETRIC_ID_PFX2AS)
  {
    for(khiter = kh_begin(tree->pfx2as_metrics);
	khiter != kh_end(tree->pfx2as_metrics);
	++khiter)
      {
	if(kh_exist(tree->pfx2as_metrics, khiter))
	  {
	    metric_package_dump(state, kh_val(tree->pfx2as_metrics,
					      khiter));
	  }
      }
  }

  SM_IF(SUBMETRIC_ID_PROTOCOL)
  {
    DUMP_ARRAY(tree->protocol_metrics, METRIC_PROTOCOL_VAL_MAX)
  }

  SM_IF(SUBMETRIC_ID_PORT)
  {
    for(proto = 0; proto <= METRIC_PORT_PROTOCOL_MAX; proto++)
      {
	for(dir = 0; dir <= METRIC_PORT_DIRECTION_MAX; dir++)
	  {
	    for(port = 0; port < tree_port_max[tree->id]; port++)
	      {
		if(tree->port_metrics[proto][dir][port] != NULL)
		  {
		    metric_package_dump(state,
					tree->port_metrics[proto][dir][port]);
		  }
	      }
	  }
      }
  }

  return 0;
}

static inline uint16_t lookup_convert_cc(corsaro_packet_state_t *state,
					 ipmeta_provider_id_t provider_id,
					 uint16_t def,
					 uint16_t *cont)
{
  ipmeta_record_t *record;

  if((record =
      corsaro_ipmeta_get_record(state, provider_id))
     != NULL)
    {
      if(record->continent_code != NULL)
	{
	  *cont = CC_16(record->continent_code);
	}
      else
	{
	  *cont = def;
	}
      if(record->country_code != NULL)
	{
	  return CC_16(record->country_code);
	}
      else
        {
          return def;
        }
    }

  *cont = def;
  return def;
}

static int process_generic(corsaro_t *corsaro, corsaro_packet_state_t *state,
			   uint32_t src_ip, uint32_t dst_ip,
			   uint16_t src_port, uint16_t dst_port,
			   uint16_t ip_len, uint8_t protocol, uint64_t pkt_cnt)
{
  struct corsaro_report_state_t *plugin_state = STATE(corsaro);
  int tree_idx, i,j;
  metric_tree_t *tree = NULL;
  int proto;
  uint16_t maxmind_cont;
  uint16_t maxmind_cc;

  uint16_t netacq_cont;
  uint16_t netacq_cc;
  uint16_t netacq_rc = 0;
  uint16_t netacq_poly_ids[METRIC_NETACQ_EDGE_POLYS_TBL_CNT];

  khiter_t khiter;
  ipmeta_record_t *record;

  corsaro_tag_t **tags;
  int tags_cnt;

  assert(plugin_state != NULL);

  /* prep all the results */

  /* maxmind country and continent code */
  maxmind_cc = lookup_convert_cc(state, IPMETA_PROVIDER_MAXMIND,
				 0x3F3F, /* "??" */
				 &maxmind_cont);
  /* netacq edge country code */
  netacq_cc = lookup_convert_cc(state, IPMETA_PROVIDER_NETACQ_EDGE,
				0x3F3F, /* "??" */
				&netacq_cont);
  /* netacq edge region code */
  if((record =
      corsaro_ipmeta_get_record(state, IPMETA_PROVIDER_NETACQ_EDGE))
     != NULL)
    {
      netacq_rc = record->region_code;
      assert(record->polygon_ids_cnt == METRIC_NETACQ_EDGE_POLYS_TBL_CNT);
      for(i=0; i<record->polygon_ids_cnt; i++)
        {
          netacq_poly_ids[i] = record->polygon_ids[i];
        }
    }

  /* now iterate over each tag and build the tree */
  for(tree_idx = 0; tree_idx < TREE_ID_CNT; tree_idx++)
    {
      /* skip this tree if it is not enabled (run-time config) */
      if(plugin_state->trees_enabled != 0 &&
	 (plugin_state->trees_enabled & tree_flags[tree_idx]) == 0)
	{
	  continue;
	}

      tree = plugin_state->trees[tree_idx];
      assert(tree != NULL);

      /* regardless of whether our group matches, update the filter stats */
      SM_IF(SUBMETRIC_ID_FILTER)
      {
	tags_cnt = corsaro_tag_group_get_tags(tree->group, &tags);
	assert(tags_cnt >= 0);

	for(j=0; j<tags_cnt; j++)
	  {
	    assert(tree->filter_metrics[j] != NULL);
	    /* only update if the filter DID NOT MATCH */
	    if(corsaro_tag_is_match(state, tags[j]) == 0)
	      {
		metric_package_update(tree->filter_metrics[j],
				      src_ip, dst_ip, ip_len, pkt_cnt);
	      }
	  }
      }

      /** @note, the filters for report MUST identify packets that are
	  allowed. That is, ALL tags for a group must match for the group to
	  match */
      if(corsaro_tag_group_is_match(state, tree->group) != 0)
	{
	  /* process this packet for this tree */
	  assert(tree != NULL);

	  SM_IF(SUBMETRIC_ID_TREE)
	  {
	    metric_package_update(tree->tree_metrics,
				  src_ip, dst_ip, ip_len, pkt_cnt);
	  }

	  SM_IF(SUBMETRIC_ID_MAXMIND_CONTINENT)
	  {
	    assert(tree->maxmind_continent_metrics[maxmind_cont] != NULL);
	    metric_package_update(tree->maxmind_continent_metrics[maxmind_cont],
				  src_ip, dst_ip, ip_len, pkt_cnt);
	  }

	  SM_IF(SUBMETRIC_ID_MAXMIND_COUNTRY)
	  {
	    assert(tree->maxmind_country_metrics[maxmind_cc] != NULL);
	    metric_package_update(tree->maxmind_country_metrics[maxmind_cc],
				  src_ip, dst_ip, ip_len, pkt_cnt);
	  }

	  SM_IF(SUBMETRIC_ID_NETACQ_EDGE_CONTINENT)
	  {
	    assert(tree->netacq_continent_metrics[netacq_cont] != NULL);
	    metric_package_update(tree->netacq_continent_metrics[netacq_cont],
				  src_ip, dst_ip, ip_len, pkt_cnt);
	  }

	  SM_IF(SUBMETRIC_ID_NETACQ_EDGE_COUNTRY)
	  {
	    assert(tree->netacq_country_metrics[netacq_cc] != NULL);
	    metric_package_update(tree->netacq_country_metrics[netacq_cc],
				  src_ip, dst_ip, ip_len, pkt_cnt);
	  }

	  SM_IF(SUBMETRIC_ID_NETACQ_EDGE_REGION)
	  {
	    if(netacq_rc != 0)
	      {
		/* if this code is run on old region files, it breaks */
		if(tree->netacq_region_metrics[netacq_rc] == NULL)
		  {
		    corsaro_log(__func__, corsaro,
				"Missing region code %d. "
				"Ensure you are not using old region files",
				netacq_rc);
		    assert(0); /* in case we have asserts on */
		    return -1;
		  }
		metric_package_update(tree->netacq_region_metrics[netacq_rc],
				      src_ip, dst_ip, ip_len, pkt_cnt);
	      }
	  }

	  SM_IF(SUBMETRIC_ID_NETACQ_EDGE_POLYS)
	  {
            for(j=0; j<METRIC_NETACQ_EDGE_POLYS_TBL_CNT; j++)
              {
		if(tree->netacq_poly_metrics[j][netacq_poly_ids[j]] == NULL)
		  {
		    corsaro_log(__func__, corsaro,
				"Missing region polygon %d:%d. ",
				j, netacq_poly_ids[j]);
		    assert(0); /* in case we have asserts on */
		    return -1;
		  }
		metric_package_update(tree->netacq_poly_metrics[j][netacq_poly_ids[j]],
				      src_ip, dst_ip, ip_len, pkt_cnt);
	      }
	  }

	  SM_IF(SUBMETRIC_ID_PFX2AS)
	  {
	    /* note we are deliberately discarding ASN records that have more
	       than one ASN because we consider them an artifact of the
	       measurement */
	    /* we are also discarding any AS that is smaller than the smallest
	       AS in our top METRIC_PFX2AS_VAL_MAX ASes list. */
	    /* note that this means there may *occasionally* be more than
	       METRIC_PFX2AS_VAL_MAX ASes dumped. this will only happen when
	       there are multiple ASes of size
	       plugin_state->pfx2as_min_ip_cnt */
	    /* also note that we are NOT recording stats for packets that we
	       cannot compute ans ASN for */
	    if((record = corsaro_ipmeta_get_record(state, IPMETA_PROVIDER_PFX2AS))
	       != NULL
	       && record->asn_cnt == 1
	       && record->asn_ip_cnt >= tree->pfx2as_min_ip_cnt)
	      {
		khiter = kh_get(u32metric, tree->pfx2as_metrics, record->asn[0]);

		assert(khiter != kh_end(tree->pfx2as_metrics));
		metric_package_update(kh_val(tree->pfx2as_metrics, khiter),
				      src_ip, dst_ip, ip_len, pkt_cnt);
	      }
	  }

	  SM_IF(SUBMETRIC_ID_PROTOCOL)
	  {
	    metric_package_update(tree->protocol_metrics[protocol],
				  src_ip, dst_ip, ip_len, pkt_cnt);
	  }

	  SM_IF(SUBMETRIC_ID_PORT)
	  {
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
		if(src_port < tree_port_max[tree->id])
		  {
		    metric_package_update(tree->
					  port_metrics
					  [proto][METRIC_PORT_DIRECTION_SRC][src_port],
					  src_ip, dst_ip, ip_len, pkt_cnt);
		  }

		if(dst_port < tree_port_max[tree->id])
		  {
		    metric_package_update(tree->
					  port_metrics
					  [proto][METRIC_PORT_DIRECTION_DST][dst_port],
					  src_ip, dst_ip, ip_len, pkt_cnt);
		  }
	      }
	  }
	}
    }

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
	  "                     available backends:\n"
	  "       -t <tree>    process the given tree,\n"
	  "                     -t can be used multiple times\n",
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

  int i, j;
  char *backends[TIMESERIES_BACKEND_ID_LAST];
  int backends_cnt = 0;
  char *backend_arg_ptr = NULL;
  timeseries_backend_t *backend = NULL;

  char *trees[TREE_ID_CNT];
  int trees_cnt = 0;
  int tree_valid = 0;
  int tree_id = 0;

  if(plugin->argc <= 0)
    {
      return 0;
    }

  /* NB: remember to reset optind to 1 before using getopt! */
  optind = 1;

  while((opt = getopt(plugin->argc, plugin->argv, ":b:t:?")) >= 0)
    {
      switch(opt)
	{
	case 'b':
	  backends[backends_cnt++] = strdup(optarg);
	  break;

	case 't':
	  trees[trees_cnt++] = strdup(optarg);
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

  /* enable the trees that were requested */
  for(i=0; i<trees_cnt; i++)
    {
      /* look for this tree name */
      tree_valid = 0;
      for(j=0; j<TREE_ID_CNT; j++)
	{
	  if(strcmp(trees[i], tree_names[j]) == 0)
	    {
	      tree_valid = 1;
	      tree_id = j;
	    }
	}
      if(tree_valid != 0)
	{
	  corsaro_log(__func__, corsaro, "enabling tree (%s)", trees[i]);
	  state->trees_enabled |= tree_flags[tree_id];
	}
      else
	{
	  fprintf(stderr, "ERROR: No tree found with name %s\n", trees[i]);
	  usage(corsaro);
	  goto err;
	}

      /* free the string we dup'd */
      free(trees[i]);
      trees[i] = NULL;
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
  for(i=0; i<trees_cnt; i++)
    {
      if(trees[i] != NULL)
	{
	  free(trees[i]);
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

  ipmeta_provider_t *provider;

  libtrace_filter_t *bpf_filter = NULL;

  int i;

  /* the current key id (used by METRIC_PREFIX_INIT) */
  uint32_t key_id = 0;

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
      goto err;
    }

  if((state->kp = timeseries_kp_init(0)) == NULL)
    {
      corsaro_log(__func__, corsaro,
		  "could not create key package");
      goto err;
    }

  /* create all the tags that we need (the trees will add them to groups)*/
  for(i=0; i<ARR_CNT(tag_defs); i++)
    {
      if(tag_defs[i].bpf != NULL)
	{
	  /* first, create the appropriate bpf */
	  corsaro_log(__func__, corsaro,
		      "creating tag with name '%s' and bpf '%s'",
		      tag_defs[i].name, tag_defs[i].bpf);

	  bpf_filter = trace_create_filter(tag_defs[i].bpf);
	  assert(bpf_filter != NULL);
	}

      if((state->tags[i] =
	  corsaro_tag_init(corsaro, tag_defs[i].name, bpf_filter))
	 == NULL)
	{
	  fprintf(stderr, "ERROR: could not allocate tag for %s.\n",
		  tag_defs[i].bpf);
	  return -1;
	}
    }
  /* just for convenience */
  state->tags_cnt = ARR_CNT(tag_defs);

  /* grab the stuff we need for maxmind */
  if((provider =
      corsaro_ipmeta_get_provider(corsaro, IPMETA_PROVIDER_MAXMIND))
     == NULL || ipmeta_is_provider_enabled(provider) == 0)
    {
      corsaro_log(__func__, corsaro,
		  "ERROR: Maxmind provider must be enabled");
      goto err;
    }
  /* get a list of all the continents */
  state->maxmind_continents_cnt =
    ipmeta_provider_maxmind_get_country_continent_list(
						&state->maxmind_continents);
  /* get a list of all the countries */
  state->maxmind_countries_cnt =
    ipmeta_provider_maxmind_get_iso2_list(&state->maxmind_countries);
  assert(state->maxmind_countries_cnt == state->maxmind_continents_cnt);

  for(i=0; i<TREE_ID_CNT; i++)
    {
      if((state->trees_enabled == 0 ||
	  (state->trees_enabled & tree_flags[i]) != 0) &&
	 (state->trees[i] = metric_tree_new(corsaro, i, &key_id))
	 == NULL)
	{
	  goto err;
	}

      corsaro_log(__func__, corsaro, "Created metric tree (%d)",
                  state->trees[i]->id);
    }

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
  int i;
  struct corsaro_report_state_t *state = STATE(corsaro);

  if(state == NULL)
    {
      return 0;
    }

  /* free the bpf's in the tags */
  for(i=0; i<state->tags_cnt; i++)
    {
      if(state->tags[i]->user != NULL)
	{
	  trace_destroy_filter(state->tags[i]->user);
	  state->tags[i]->user = NULL;
	}
    }

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

  if(state->trees != NULL)
    {
      for(i=0; i<TREE_ID_CNT; i++)
	{
	  if(state->trees[i] != NULL)
	    {
	      metric_tree_destroy(state->trees[i]);
	      state->trees[i] = NULL;
	    }
	}
    }

  corsaro_plugin_free_state(corsaro->plugin_manager, PLUGIN(corsaro));

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
  struct corsaro_report_state_t *state = STATE(corsaro);
  int i;

  for(i=0; i<TREE_ID_CNT; i++)
    {
      if(state->trees_enabled == 0 ||
	 (state->trees_enabled & tree_flags[i]) != 0)
	{
	  assert(state->trees[i] != NULL);
	  if(metric_tree_dump(state, i) != 0)
	    {
	      return -1;
	    }
	}
    }

  /* now flush to each backend */
  for(i=0; i<state->enabled_backends_cnt; i++)
    {
      timeseries_kp_flush(state->enabled_backends[i], state->kp, state->time);
    }

  return 0;
}

int corsaro_report_process_packet(corsaro_t *corsaro,
				  corsaro_packet_t *packet)
{
  struct corsaro_report_state_t *state = STATE(corsaro);
  libtrace_packet_t *ltpacket = LT_PKT(packet);
  libtrace_ip_t  *ip_hdr  = NULL;
  libtrace_icmp_t *icmp_hdr = NULL;
  uint16_t src_port;
  uint16_t dst_port;
  int rc, i;

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

  /* run the bpf for each tag */
  for(i=0; i<state->tags_cnt; i++)
    {
      assert(state->tags[i] != NULL);
      if(state->tags[i]->user != NULL)
	{
	  rc = trace_apply_filter(
				  (libtrace_filter_t*)(state->tags[i]->user),
				  ltpacket
				  );
	  if(rc < 0)
	    {
	      corsaro_log(__func__, corsaro,
			  "invalid bpf filter for tag '%s'",
			  state->tags[i]->name);
	      return -1;
	    }
	}
      else /* the 'all-pkts' tag */
	{
	  rc = 1;
	}

      if(rc > 0)
	{
	  /* mark this filter as a match */
	  corsaro_tag_set_match(&packet->state, state->tags[i], rc);
	}
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
