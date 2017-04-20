/*
 * corsaro
 *
 * Alistair King, CAIDA, UC San Diego
 * alistair@caida.org
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

#include "corsaro_int.h"
#include "config.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "libtrace.h"

#include "utils.h"

#include "corsaro_file.h"
#include "corsaro_io.h"
#include "corsaro_log.h"
#include "corsaro_plugin.h"

#include "corsaro_confickerscan.h"

#include "libp0f/readfp.h" /* for fp_os_names */

/** @file
 *
 * @brief Corsaro conficker scan extractor plug implementation
 *
 * @author Karyn Benson
 *
 */

/** The magic number for this plugin - "COSC" */
#define CORSARO_CONFICKERSCAN_MAGIC 0x434f5343

/** The name of this plugin - should match the file name */
#define PLUGIN_NAME "corsaro_confickerscan"

/** Common plugin information across all instances */
static corsaro_plugin_t corsaro_confickerscan_plugin = {
  PLUGIN_NAME,                                         /* name */
  CORSARO_PLUGIN_ID_CONFICKERSCAN,                     /* id */
  CORSARO_CONFICKERSCAN_MAGIC,                         /* magic */
  CORSARO_PLUGIN_GENERATE_PTRS(corsaro_confickerscan), /* func ptrs */
  CORSARO_PLUGIN_GENERATE_TAIL,
};

KHASH_MAP_INIT_INT(ip_hash, uint32_t)

KHASH_INIT(confickerscan_hash, corsaro_confickerscan_hash_key_t *,
           corsaro_confickerscan_hash_value_t *, 1,
           corsaro_confickerscan_hash_func, corsaro_confickerscan_hash_eq)

KHASH_INIT(confickerscan_intermediate_aggregate_hash,
           corsaro_confickerscan_intermediate_aggregate_hash_key_t *,
           corsaro_confickerscan_intermediate_aggregate_hash_value_t *, 1,
           corsaro_confickerscan_intermediate_aggregate_hash_func,
           corsaro_confickerscan_intermediate_aggregate_hash_eq)

KHASH_INIT(confickerscan_aggregate_hash,
           corsaro_confickerscan_aggregate_hash_key_t *,
           corsaro_confickerscan_aggregate_hash_value_t *, 1,
           corsaro_confickerscan_aggregate_hash_func,
           corsaro_confickerscan_aggregate_hash_eq)

KHASH_INIT(confickerscan_how_many_ips_hash,
           corsaro_confickerscan_how_many_ips_hash_key_t *,
           corsaro_confickerscan_how_many_ips_hash_value_t *, 1,
           corsaro_confickerscan_how_many_ips_hash_func,
           corsaro_confickerscan_how_many_ips_hash_eq)

/** Holds the state for an instance of this plugin */
struct corsaro_confickerscan_state_t {
  /** The outfile for the plugin */
  corsaro_file_t *outfile;
  /** hash of flows - so we can count easily **/
  khash_t(confickerscan_hash) * st_hash;
  /** aggregation of flows  **/
  khash_t(confickerscan_intermediate_aggregate_hash) * intermediate_aggregate;
  khash_t(confickerscan_aggregate_hash) * aggregate;
  khash_t(confickerscan_how_many_ips_hash) * hmips;
  /** so we know the current timestamp, from which we can safely remove items
   * **/
  struct timeval max_ts;
};

/** Extends the generic plugin state convenience macro in corsaro_plugin.h */
#define STATE(corsaro)                                                         \
  (CORSARO_PLUGIN_STATE(corsaro, confickerscan,                                \
                        CORSARO_PLUGIN_ID_CONFICKERSCAN))
/** Extends the generic plugin plugin convenience macro in corsaro_plugin.h */
#define PLUGIN(corsaro)                                                        \
  (CORSARO_PLUGIN_PLUGIN(corsaro, CORSARO_PLUGIN_ID_CONFICKERSCAN))

/* == PUBLIC PLUGIN FUNCS BELOW HERE == */

corsaro_plugin_t *corsaro_confickerscan_alloc(corsaro_t *corsaro)
{
  return &corsaro_confickerscan_plugin;
}

int corsaro_confickerscan_probe_filename(const char *fname)
{
  /* look for 'corsaro_confickerscan' in the name */
  return corsaro_plugin_probe_filename(fname, &corsaro_confickerscan_plugin);
}

int corsaro_confickerscan_probe_magic(corsaro_in_t *corsaro,
                                      corsaro_file_in_t *file)
{
  /* we write libtrace files. corsaro doesn't read these using plugins */
  return -1;
}

int corsaro_confickerscan_init_output(corsaro_t *corsaro)
{
  struct corsaro_confickerscan_state_t *state;
  corsaro_plugin_t *plugin = PLUGIN(corsaro);
  assert(plugin != NULL);

  if ((state = malloc_zero(sizeof(struct corsaro_confickerscan_state_t))) ==
      NULL) {
    corsaro_log(__func__, corsaro,
                "could not malloc corsaro_confickerscan_state_t");
    goto err;
  }
  corsaro_plugin_register_state(corsaro->plugin_manager, plugin, state);

  /* open the output file */
  if ((state->outfile = corsaro_io_prepare_file_full(
         corsaro, plugin->name, CORSARO_FILE_MODE_ASCII, corsaro->compress,
         corsaro->compress_level, 0)) == NULL) {
    corsaro_log(__func__, corsaro, "could not open %s output file",
                plugin->name);
    goto err;
  }

  state->st_hash = kh_init(confickerscan_hash);
  state->intermediate_aggregate =
    kh_init(confickerscan_intermediate_aggregate_hash);
  state->aggregate = kh_init(confickerscan_aggregate_hash);
  state->hmips = kh_init(confickerscan_how_many_ips_hash);
  return 0;

err:
  corsaro_confickerscan_close_output(corsaro);
  return -1;
}

int corsaro_confickerscan_init_input(corsaro_in_t *corsaro)
{
  return -1;
}

int corsaro_confickerscan_close_input(corsaro_in_t *corsaro)
{
  return -1;
}

void corsaro_confickerscan_free(corsaro_confickerscan_hash_key_t *t)
{
  free(t);
}

void corsaro_confickerscan_intermediate_aggregate_free(
  corsaro_confickerscan_intermediate_aggregate_hash_key_t *t)
{
  free(t);
}

void corsaro_confickerscan_aggregate_free(
  corsaro_confickerscan_aggregate_hash_key_t *t)
{
  free(t);
}

void corsaro_confickerscan_how_many_ips_free(
  corsaro_confickerscan_how_many_ips_hash_key_t *t)
{
  free(t);
}

off_t corsaro_confickerscan_fprint(corsaro_t *corsaro, corsaro_file_t *file,
                                   khiter_t khiter)
{
  assert(corsaro != NULL);
  assert(file != NULL);
  corsaro_confickerscan_hash_value_t *v =
    kh_value(STATE(corsaro)->st_hash, khiter);

  return corsaro_file_printf(
    corsaro, file, "|%" PRIu32 "|%d.%d.%d.%d|%d.%d.%d.%d|%" PRIu16 "|%" PRIu16
                   "|%" PRIu16 "|%" PRIu16 "\n",
    v->first_timestamp.tv_sec, (v->src_ip) & 0xff, (v->src_ip >> 8) & 0xff,
    (v->src_ip >> 16) & 0xff, (v->src_ip >> 24) & 0xff, (v->dst_ip) & 0xff,
    (v->dst_ip >> 8) & 0xff, (v->dst_ip >> 16) & 0xff, (v->dst_ip >> 24) & 0xff,
    v->src_port, v->dst_port, v->as, v->num_packets);
}

off_t corsaro_confickerscan_intermediate_aggregate_fprint(corsaro_t *corsaro,
                                                          corsaro_file_t *file,
                                                          khiter_t khiter)
{
  assert(corsaro != NULL);
  assert(file != NULL);
  corsaro_confickerscan_hash_value_t *v =
    kh_value(STATE(corsaro)->st_hash, khiter);

  return corsaro_file_printf(
    corsaro, file, "|%" PRIu32 "|%d.%d.%d.%d|%d.%d.%d.%d|%" PRIu16 "|%" PRIu16
                   "|%" PRIu16 "|%" PRIu16 "\n",
    v->first_timestamp.tv_sec, (v->src_ip) & 0xff, (v->src_ip >> 8) & 0xff,
    (v->src_ip >> 16) & 0xff, (v->src_ip >> 24) & 0xff, (v->dst_ip) & 0xff,
    (v->dst_ip >> 8) & 0xff, (v->dst_ip >> 16) & 0xff, (v->dst_ip >> 24) & 0xff,
    v->src_port, v->dst_port, v->as, v->num_packets);
}

off_t corsaro_confickerscan_aggregate_fprint(corsaro_t *corsaro,
                                             corsaro_file_t *file,
                                             khiter_t khiter, khiter_t khiter2,
                                             uint32_t ts)
{

  assert(corsaro != NULL);
  assert(file != NULL);

  corsaro_confickerscan_aggregate_hash_value_t *v =
    kh_value(STATE(corsaro)->aggregate, khiter);
  corsaro_confickerscan_how_many_ips_hash_value_t *hmv =
    kh_value(STATE(corsaro)->hmips, khiter2);

  khash_t(ip_hash) *h_dst = hmv->seen_dst_ips;

  return corsaro_file_printf(
    corsaro, file,
    "|%d|%" PRIu32 "|%f|%" PRIu32 "|%" PRIu32 "|%f|%" PRIu32 "|%" PRIu32
    "|%" PRIu32 "|%" PRIu32 "|%" PRIu32 "|%" PRIu32 "|%" PRIu32 "|\n",
    ts, v->as, v->avg_packets_per_flow_per_src_ip, v->total_packets,
    v->num_flows, ((float)v->total_packets) / v->num_flows,
    v->num_packets_distribution[0], v->num_packets_distribution[1],
    v->num_packets_distribution[2], v->num_packets_distribution[3],
    v->num_packets_distribution[4], v->num_src_ips, kh_size(h_dst));
}

int corsaro_confickerscan_aggregate_seen_ips(
  corsaro_t *corsaro, corsaro_confickerscan_hash_value_t *v)
{

  khiter_t khiter, khiter_ip, hmkhiter;
  int khret;
  corsaro_confickerscan_how_many_ips_hash_key_t k;
  corsaro_confickerscan_how_many_ips_hash_key_t *new_key;

  /*How Many IPS  */
  k.as = v->as;

  if ((khiter = kh_get(confickerscan_how_many_ips_hash, STATE(corsaro)->hmips,
                       &k)) == kh_end(STATE(corsaro)->hmips)) {
    /* create a new key */
    if ((new_key = malloc(
           sizeof(corsaro_confickerscan_how_many_ips_hash_key_t))) == NULL) {
      corsaro_log_file(__func__, NULL, "malloc failed");
      return -1;
    }

    /* fill it */
    memcpy(new_key, &k, sizeof(corsaro_confickerscan_how_many_ips_hash_key_t));

    /* add it to the hash */
    khiter = kh_put(confickerscan_how_many_ips_hash, STATE(corsaro)->hmips,
                    new_key, &khret);
    if (!khret || khiter == kh_end(STATE(corsaro)->hmips)) {
      corsaro_log_file(__func__, NULL,
                       "hash error (adding intermediate_how_many_ips hash)");
      return -1;
    }

    /* create a new value */
    if ((kh_value(STATE(corsaro)->hmips, khiter) = malloc(
           sizeof(corsaro_confickerscan_how_many_ips_hash_value_t))) == NULL) {
      corsaro_log_file(__func__, NULL, "malloc failed");
      return -1;
    }

    /* fill it */
    kh_value(STATE(corsaro)->hmips, khiter)->seen_dst_ips = kh_init(ip_hash);
    khash_t(ip_hash) *h_dst =
      kh_value(STATE(corsaro)->hmips, khiter)->seen_dst_ips;
    khiter_ip = kh_put(ip_hash, h_dst, v->dst_ip, &khret);
    if (!khret || khiter_ip == kh_end(h_dst)) {
      corsaro_log_file(__func__, NULL, "hash error (init ip_hash)");
      return -1;
    }
  } else {
    khash_t(ip_hash) *h_dst =
      kh_value(STATE(corsaro)->hmips, khiter)->seen_dst_ips;
    khiter_ip = kh_put(ip_hash, h_dst, v->dst_ip, &khret);
  }
}

int corsaro_confickerscan_intermediate_aggregate_flows(
  corsaro_t *corsaro, corsaro_confickerscan_hash_value_t *v)
{
  khiter_t khiter, khiter_ip;
  int khret;
  corsaro_confickerscan_intermediate_aggregate_hash_key_t ak;
  corsaro_confickerscan_intermediate_aggregate_hash_key_t *new_key;

  /* ignore if more than 3 packets*/
  if (v->num_packets > 3)
    return 0;

  ak.as = v->as;
  ak.src_ip = v->src_ip;

  /*Intermediate*/

  if ((khiter = kh_get(confickerscan_intermediate_aggregate_hash,
                       STATE(corsaro)->intermediate_aggregate, &ak)) ==
      kh_end(STATE(corsaro)->intermediate_aggregate)) {
    /* create a new key */
    if ((new_key = malloc(sizeof(
           corsaro_confickerscan_intermediate_aggregate_hash_key_t))) == NULL) {
      corsaro_log_file(__func__, NULL, "malloc failed");
      return -1;
    }

    /* fill it */
    memcpy(new_key, &ak,
           sizeof(corsaro_confickerscan_intermediate_aggregate_hash_key_t));

    /* add it to the hash */
    khiter = kh_put(confickerscan_intermediate_aggregate_hash,
                    STATE(corsaro)->intermediate_aggregate, new_key, &khret);
    if (!khret || khiter == kh_end(STATE(corsaro)->intermediate_aggregate)) {
      corsaro_log_file(__func__, NULL,
                       "hash error (adding intermediate_aggregate hash)");
      return -1;
    }

    /* create a new value */
    if ((kh_value(STATE(corsaro)->intermediate_aggregate, khiter) =
           malloc(sizeof(
             corsaro_confickerscan_intermediate_aggregate_hash_value_t))) ==
        NULL) {
      corsaro_log_file(__func__, NULL, "malloc failed");
      return -1;
    }

    /* fill it */
    kh_value(STATE(corsaro)->intermediate_aggregate, khiter)->as = ak.as;
    kh_value(STATE(corsaro)->intermediate_aggregate, khiter)->src_ip =
      ak.src_ip;
    kh_value(STATE(corsaro)->intermediate_aggregate, khiter)->num_flows = 1;
    kh_value(STATE(corsaro)->intermediate_aggregate, khiter)->total_packets =
      v->num_packets;
    for (int i = 0; i < 5; i++)
      kh_value(STATE(corsaro)->intermediate_aggregate, khiter)
        ->num_packets_distribution[i] =
        ((v->num_packets == i - 1) || (i == 4 && v->num_packets > 4));

    kh_value(STATE(corsaro)->intermediate_aggregate, khiter)->seen_dst_ips =
      kh_init(ip_hash);
    khash_t(ip_hash) *h_dst =
      kh_value(STATE(corsaro)->intermediate_aggregate, khiter)->seen_dst_ips;
    khiter_ip = kh_put(ip_hash, h_dst, v->dst_ip, &khret);
    if (!khret || khiter_ip == kh_end(h_dst)) {
      corsaro_log_file(__func__, NULL, "hash error (init ip_hash)");
      return -1;
    }

#ifdef CORSARO_CONFICKERSCAN_DEBUG
    corsaro_log(
      __func__, NULL, "new: as:%d ip:%x flows:%d packets:%d num_dst_ips:%d",
      kh_value(STATE(corsaro)->intermediate_aggregate, khiter)->as,
      kh_value(STATE(corsaro)->intermediate_aggregate, khiter)->src_ip,
      kh_value(STATE(corsaro)->intermediate_aggregate, khiter)->num_flows,
      kh_value(STATE(corsaro)->intermediate_aggregate, khiter)->total_packets,
      kh_size(h_dst));
#endif
  } else {

    kh_value(STATE(corsaro)->intermediate_aggregate, khiter)->num_flows += 1;
    kh_value(STATE(corsaro)->intermediate_aggregate, khiter)->total_packets +=
      v->num_packets;
    if ((v->num_packets - 1) < 5)
      kh_value(STATE(corsaro)->intermediate_aggregate, khiter)
        ->num_packets_distribution[v->num_packets - 1] += 1;
    else
      kh_value(STATE(corsaro)->intermediate_aggregate, khiter)
        ->num_packets_distribution[4] += 1;

    khash_t(ip_hash) *h_dst =
      kh_value(STATE(corsaro)->intermediate_aggregate, khiter)->seen_dst_ips;
    khiter_ip = kh_put(ip_hash, h_dst, v->dst_ip, &khret);
#ifdef CORSARO_CONFICKERSCAN_DEBUG
    corsaro_log(
      __func__, NULL, "old: as:%d ip:%x flows:%d packets:%d num_dst_ips:%d",
      kh_value(STATE(corsaro)->intermediate_aggregate, khiter)->as,
      kh_value(STATE(corsaro)->intermediate_aggregate, khiter)->src_ip,
      kh_value(STATE(corsaro)->intermediate_aggregate, khiter)->num_flows,
      kh_value(STATE(corsaro)->intermediate_aggregate, khiter)->total_packets,
      kh_size(h_dst));
#endif
  }

  /* Aggregate How Many IPs seen for the AS */
  corsaro_confickerscan_aggregate_seen_ips(corsaro, v);
}

int corsaro_confickerscan_aggregate_flows(
  corsaro_t *corsaro,
  corsaro_confickerscan_intermediate_aggregate_hash_value_t *v)
{
  khiter_t khiter, khiter_ip, khiter_v_ip;
  int khret;
  corsaro_confickerscan_aggregate_hash_key_t ak;
  corsaro_confickerscan_aggregate_hash_key_t *new_key;

#ifdef CORSARO_CONFICKERSCAN_DEBUG
  khash_t(ip_hash) *hi_dst_debug = v->seen_dst_ips;
  corsaro_log(
    __func__, NULL, "aggregate: as:%d ip:%x flows:%d packets:%d num_dst_ips:%d",
    v->as, v->src_ip, v->num_flows, v->total_packets, kh_size(hi_dst_debug));
#endif

  ak.as = v->as;

  if ((khiter = kh_get(confickerscan_aggregate_hash, STATE(corsaro)->aggregate,
                       &ak)) == kh_end(STATE(corsaro)->aggregate)) {
    /* create a new key */
    if ((new_key = malloc(
           sizeof(corsaro_confickerscan_aggregate_hash_key_t))) == NULL) {
      corsaro_log_file(__func__, NULL, "malloc failed");
      return -1;
    }

    /* fill it */
    memcpy(new_key, &ak, sizeof(corsaro_confickerscan_aggregate_hash_key_t));

    /* add it to the hash */
    khiter = kh_put(confickerscan_aggregate_hash, STATE(corsaro)->aggregate,
                    new_key, &khret);
    if (!khret || khiter == kh_end(STATE(corsaro)->aggregate)) {
      corsaro_log_file(__func__, NULL, "hash error (adding aggregate hash)");
      return -1;
    }

    /* create a new value */
    if ((kh_value(STATE(corsaro)->aggregate, khiter) = malloc(
           sizeof(corsaro_confickerscan_aggregate_hash_value_t))) == NULL) {
      corsaro_log_file(__func__, NULL, "malloc failed");
      return -1;
    }

    /* fill it */
    kh_value(STATE(corsaro)->aggregate, khiter)->as = ak.as;
    kh_value(STATE(corsaro)->aggregate, khiter)
      ->avg_packets_per_flow_per_src_ip =
      ((float)v->total_packets) / v->num_flows;
    kh_value(STATE(corsaro)->aggregate, khiter)->num_src_ips = 1;
    kh_value(STATE(corsaro)->aggregate, khiter)->num_flows = v->num_flows;
    kh_value(STATE(corsaro)->aggregate, khiter)->total_packets =
      v->total_packets;
    for (int i = 0; i < 5; i++)
      kh_value(STATE(corsaro)->aggregate, khiter)->num_packets_distribution[i] =
        v->num_packets_distribution[i];
#ifdef CORSARO_CONFICKERSCAN_DEBUG
    corsaro_log(__func__, NULL, "new: as:%d ppf:%f src_ips:%d ",
                kh_value(STATE(corsaro)->aggregate, khiter)->as,
                kh_value(STATE(corsaro)->aggregate, khiter)
                  ->avg_packets_per_flow_per_src_ip,
                kh_value(STATE(corsaro)->aggregate, khiter)->num_src_ips);
#endif
  } else {

    kh_value(STATE(corsaro)->aggregate, khiter)
      ->avg_packets_per_flow_per_src_ip =
      ((((float)v->total_packets) / v->num_flows) +
       kh_value(STATE(corsaro)->aggregate, khiter)->num_src_ips *
         kh_value(STATE(corsaro)->aggregate, khiter)
           ->avg_packets_per_flow_per_src_ip) /
      (kh_value(STATE(corsaro)->aggregate, khiter)->num_src_ips + 1);
    kh_value(STATE(corsaro)->aggregate, khiter)->num_src_ips += 1;
    kh_value(STATE(corsaro)->aggregate, khiter)->num_flows += v->num_flows;
    kh_value(STATE(corsaro)->aggregate, khiter)->total_packets +=
      v->total_packets;
    for (int i = 0; i < 5; i++)
      kh_value(STATE(corsaro)->aggregate, khiter)
        ->num_packets_distribution[i] += v->num_packets_distribution[i];
#ifdef CORSARO_CONFICKERSCAN_DEBUG
    corsaro_log(__func__, NULL, "old: as:%d ppf:%f src_ips:%d",
                kh_value(STATE(corsaro)->aggregate, khiter)->as,
                kh_value(STATE(corsaro)->aggregate, khiter)
                  ->avg_packets_per_flow_per_src_ip,
                kh_value(STATE(corsaro)->aggregate, khiter)->num_src_ips);
#endif
  }
}

int corsaro_confickerscan_close_output(corsaro_t *corsaro)
{
  struct corsaro_confickerscan_state_t *state = STATE(corsaro);
  khiter_t k, aik, ak, hmk;
  corsaro_confickerscan_hash_value_t *v;
  corsaro_confickerscan_intermediate_aggregate_hash_value_t *aiv;
  corsaro_confickerscan_aggregate_hash_value_t *av;
  corsaro_confickerscan_how_many_ips_hash_value_t *hmv;

  corsaro_io_write_interval_start(corsaro, STATE(corsaro)->outfile,
                                  &corsaro->interval_start);
  if (state != NULL) {
    if (state->outfile != NULL) {

      for (k = kh_begin(state->st_hash); k != kh_end(state->st_hash); ++k) {
        if (kh_exist(state->st_hash, k)) {
          float elapsed_sec =
            (state->max_ts.tv_sec -
             kh_value(state->st_hash, k)->last_timestamp.tv_sec);
          elapsed_sec +=
            ((float)(state->max_ts.tv_usec -
                     kh_value(state->st_hash, k)->last_timestamp.tv_usec)) /
            1000000;

          if (elapsed_sec > CORSARO_CONFICKERSCAN_FLOW_TIMEOUT) {
/* is old: aggregate and free */
#ifdef CORSARO_CONFICKERSCAN_DEBUG
            corsaro_confickerscan_fprint(corsaro, state->outfile, k);
#endif
            v = kh_val(state->st_hash, k);
            corsaro_confickerscan_intermediate_aggregate_flows(corsaro, v);
            free(v);
            kh_del(confickerscan_hash, state->st_hash, k);
          }
        }
      }

      for (aik = kh_begin(state->intermediate_aggregate);
           aik != kh_end(state->intermediate_aggregate); ++aik) {
        if (kh_exist(state->intermediate_aggregate, aik)) {
          aiv = kh_val(state->intermediate_aggregate, aik);
          corsaro_confickerscan_aggregate_flows(corsaro, aiv);
          khiter_t dik;
          khash_t(ip_hash) *h_dst = aiv->seen_dst_ips;
          for (dik = kh_begin(h_dst); dik != kh_end(h_dst); ++dik)
            if (kh_exist(h_dst, dik))
              kh_del(ip_hash, h_dst, dik);
          kh_destroy(ip_hash, h_dst);
          free(aiv);
          kh_del(confickerscan_intermediate_aggregate_hash,
                 state->intermediate_aggregate, aik);
        }
      }

      /* print out the aggregations */
      for (ak = kh_begin(state->aggregate); ak != kh_end(state->aggregate);
           ++ak) {
        if (kh_exist(state->aggregate, ak)) {
          corsaro_confickerscan_how_many_ips_hash_key_t hmipk;
          khiter_t ip_k;
          av = kh_val(state->aggregate, ak);
          hmipk.as = av->as;
          ip_k = kh_get(confickerscan_how_many_ips_hash, state->hmips, &hmipk);
          corsaro_confickerscan_aggregate_fprint(corsaro, state->outfile, ak,
                                                 ip_k, -1);
          free(av);
          kh_del(confickerscan_aggregate_hash, state->aggregate, ak);
        }
      }

      /* Clear the aggregation of number of IPs*/
      for (hmk = kh_begin(state->hmips); hmk != kh_end(state->hmips); ++hmk) {
        if (kh_exist(state->hmips, hmk)) {
          khiter_t dik;
          hmv = kh_val(state->hmips, hmk);
          khash_t(ip_hash) *h_dst = hmv->seen_dst_ips;
          for (dik = kh_begin(h_dst); dik != kh_end(h_dst); ++dik)
            if (kh_exist(h_dst, dik))
              kh_del(ip_hash, h_dst, dik);
          kh_clear(ip_hash, h_dst);
          free(hmv);
          kh_del(confickerscan_how_many_ips_hash, state->hmips, hmk);
        }
      }

      corsaro_file_close(corsaro, state->outfile);
      state->outfile = NULL;
    }
    corsaro_plugin_free_state(corsaro->plugin_manager, PLUGIN(corsaro));
  }

  /* free hashes */
  kh_free(confickerscan_hash, state->st_hash, &corsaro_confickerscan_free);
  kh_destroy(confickerscan_hash, state->st_hash);
  state->st_hash = NULL;

  kh_free(confickerscan_intermediate_aggregate_hash,
          state->intermediate_aggregate,
          &corsaro_confickerscan_intermediate_aggregate_free);
  kh_destroy(confickerscan_intermediate_aggregate_hash,
             state->intermediate_aggregate);
  state->intermediate_aggregate = NULL;

  kh_free(confickerscan_aggregate_hash, state->aggregate,
          &corsaro_confickerscan_aggregate_free);
  kh_destroy(confickerscan_aggregate_hash, state->aggregate);
  state->aggregate = NULL;

  kh_free(confickerscan_how_many_ips_hash, state->hmips,
          &corsaro_confickerscan_how_many_ips_free);
  kh_destroy(confickerscan_how_many_ips_hash, state->hmips);
  state->hmips = NULL;

  return 0;
}

off_t corsaro_confickerscan_read_record(struct corsaro_in *corsaro,
                                        corsaro_in_record_type_t *record_type,
                                        corsaro_in_record_t *record)
{
  /* This plugin can't read it's data back. just use libtrace */
  corsaro_log_in(__func__, corsaro,
                 "corsaro_confickerscan files are simply trace files."
                 " use libtrace instead of corsaro");
  return -1;
}

off_t corsaro_confickerscan_read_global_data_record(
  struct corsaro_in *corsaro, enum corsaro_in_record_type *record_type,
  struct corsaro_in_record *record)
{
  /* we write nothing to the global file. someone messed up */
  return -1;
}

int corsaro_confickerscan_start_interval(corsaro_t *corsaro,
                                         corsaro_interval_t *int_start)
{
  /* we don't care */
  return 0;
}

int corsaro_confickerscan_end_interval(corsaro_t *corsaro,
                                       corsaro_interval_t *int_end)
{
  struct corsaro_confickerscan_state_t *state = STATE(corsaro);
  khiter_t k, aik, ak, hmk;
  corsaro_confickerscan_hash_value_t *v;
  corsaro_confickerscan_intermediate_aggregate_hash_value_t *aiv;
  corsaro_confickerscan_aggregate_hash_value_t *av;
  corsaro_confickerscan_how_many_ips_hash_value_t *hmv;

  corsaro_io_write_interval_start(corsaro, STATE(corsaro)->outfile,
                                  &corsaro->interval_start);

  /* aggregate things that are old/we would expire if printed */
  for (k = kh_begin(state->st_hash); k != kh_end(state->st_hash); ++k) {
    if (kh_exist(state->st_hash, k)) {
      float elapsed_sec = (state->max_ts.tv_sec -
                           kh_value(state->st_hash, k)->last_timestamp.tv_sec);
      elapsed_sec +=
        ((float)(state->max_ts.tv_usec -
                 kh_value(state->st_hash, k)->last_timestamp.tv_usec)) /
        1000000;

      if (elapsed_sec > CORSARO_CONFICKERSCAN_FLOW_TIMEOUT) {
/* is old: aggregate and free */
#ifdef CORSARO_CONFICKERSCAN_DEBUG
        corsaro_confickerscan_fprint(corsaro, state->outfile, k);
#endif
        v = kh_val(state->st_hash, k);
        corsaro_confickerscan_intermediate_aggregate_flows(corsaro, v);
        free(v);
        kh_del(confickerscan_hash, state->st_hash, k);
      }
    }
  }

  for (aik = kh_begin(state->intermediate_aggregate);
       aik != kh_end(state->intermediate_aggregate); ++aik) {
    if (kh_exist(state->intermediate_aggregate, aik)) {
      aiv = kh_val(state->intermediate_aggregate, aik);
      corsaro_confickerscan_aggregate_flows(corsaro, aiv);
      khiter_t dik;
      khash_t(ip_hash) *h_dst = aiv->seen_dst_ips;
      for (dik = kh_begin(h_dst); dik != kh_end(h_dst); ++dik)
        if (kh_exist(h_dst, dik))
          kh_del(ip_hash, h_dst, dik);
      kh_destroy(ip_hash, h_dst);
      free(aiv);
      kh_del(confickerscan_intermediate_aggregate_hash,
             state->intermediate_aggregate, aik);
    }
  }

  /* print out the aggregations */
  for (ak = kh_begin(state->aggregate); ak != kh_end(state->aggregate); ++ak) {
    if (kh_exist(state->aggregate, ak)) {
      corsaro_confickerscan_how_many_ips_hash_key_t hmipk;
      khiter_t ip_k;
      av = kh_val(state->aggregate, ak);
      hmipk.as = av->as;
      ip_k = kh_get(confickerscan_how_many_ips_hash, state->hmips, &hmipk);
      corsaro_confickerscan_aggregate_fprint(corsaro, state->outfile, ak, ip_k,
                                             corsaro->interval_start.time);
      free(av);
      kh_del(confickerscan_aggregate_hash, state->aggregate, ak);
    }
  }

  /* Clear the aggregation of number of IPs*/
  for (hmk = kh_begin(state->hmips); hmk != kh_end(state->hmips); ++hmk) {
    if (kh_exist(state->hmips, hmk)) {
      khiter_t dik;
      hmv = kh_val(state->hmips, hmk);
      khash_t(ip_hash) *h_dst = hmv->seen_dst_ips;
      for (dik = kh_begin(h_dst); dik != kh_end(h_dst); ++dik)
        if (kh_exist(h_dst, dik))
          kh_del(ip_hash, h_dst, dik);
      kh_clear(ip_hash, h_dst);
      free(hmv);
      kh_del(confickerscan_how_many_ips_hash, state->hmips, hmk);
    }
  }

  corsaro_io_write_interval_end(corsaro, STATE(corsaro)->outfile, int_end);

  return 0;
}

int corsaro_confickerscan_add_inc(kh_confickerscan_hash_t *h,
                                  corsaro_confickerscan_hash_key_t *k,
                                  corsaro_confickerscan_hash_value_t *v,
                                  corsaro_t *corsaro)
{
  int khret;
  khiter_t khiter;
  corsaro_confickerscan_hash_key_t *new_key = NULL;
  corsaro_confickerscan_hash_value_t *new_value = NULL;

  assert(h != NULL);

  /* check if this is in the hash already */
  if ((khiter = kh_get(confickerscan_hash, h, k)) == kh_end(h)) {
    /* create a new key */
    if ((new_key = malloc(sizeof(corsaro_confickerscan_hash_key_t))) == NULL) {
      corsaro_log_file(__func__, NULL, "malloc failed");
      return -1;
    }

    /* fill it */
    memcpy(new_key, k, sizeof(corsaro_confickerscan_hash_key_t));

    /* add it to the hash */
    khiter = kh_put(confickerscan_hash, h, new_key, &khret);
    if (!khret || khiter == kh_end(h)) {
      corsaro_log_file(__func__, NULL, "hash error");
      return -1;
    }

    /* create a new value */
    if ((kh_value(h, khiter) =
           malloc(sizeof(corsaro_confickerscan_hash_value_t))) == NULL) {
      corsaro_log_file(__func__, NULL, "malloc failed");
      return -1;
    }

    /* fill it */
    memcpy(kh_value(h, khiter), v, sizeof(corsaro_confickerscan_hash_value_t));
#ifdef CORSARO_CONFICKERSCAN_DEBUG
// corsaro_log(__func__, NULL, "new flow: %d %d\n", kh_value(h,khiter)->as,
// kh_value(h,khiter)->num_packets);
#endif
  } else {
    /* test if we should expire based on time */
    float elapsed_sec =
      (v->last_timestamp.tv_sec - kh_value(h, khiter)->last_timestamp.tv_sec);
    elapsed_sec += ((float)(v->last_timestamp.tv_usec -
                            kh_value(h, khiter)->last_timestamp.tv_usec)) /
                   1000000;

    if (elapsed_sec > CORSARO_CONFICKERSCAN_FLOW_TIMEOUT) {
      /* is old: store the old and copy in the new */
      corsaro_confickerscan_intermediate_aggregate_flows(corsaro,
                                                         kh_value(h, khiter));
      /*corsaro_confickerscan_fprint(corsaro, STATE(corsaro)->outfile,
       * khiter);*/
      memcpy(kh_value(h, khiter), v,
             sizeof(corsaro_confickerscan_hash_value_t));
    } else {
      if (!kh_value(h, khiter)->as) {
        kh_value(h, khiter)->as = v->as;
      }
      kh_value(h, khiter)->num_packets += 1;
      kh_value(h, khiter)->last_timestamp = v->last_timestamp;
#ifdef CORSARO_CONFICKERSCAN_DEBUG
// corsaro_log(__func__, NULL, "old: %d %d\n", kh_value(h,khiter)->as,
// kh_value(h,khiter)->num_packets);
#endif
    }
  }
  return 0;
}

int corsaro_confickerscan_process_packet(corsaro_t *corsaro,
                                         corsaro_packet_t *packet)
{

  libtrace_packet_t *ltpacket = LT_PKT(packet);
  void *temp = NULL;
  uint16_t ethertype;
  uint32_t remaining;

  libtrace_ip_t *ip_hdr = NULL;
  libtrace_tcp_t *tcp_hdr = NULL;

  corsaro_confickerscan_hash_key_t k;
  corsaro_confickerscan_hash_value_t v;

  /* is this a confickerscan packet?*/

  if (((packet->state.flags & (CORSARO_PACKET_STATE_FLAG_ASNUM)) == 0) ||
      ((packet->state.flags & (CORSARO_PACKET_STATE_FLAG_P0F)) == 0)) {
    /* AS Number not set */
    return 0;
  }

  if (!(packet->state.os_class_id == 0 &&
        strcmp(fp_os_names[packet->state.os_name_id], "Windows") == 0 &&
        ((strcmp(packet->state.os_flavor, "XP") == 0) ||
         strstr(packet->state.os_flavor, "NT") == 0))) {
    return 0; // only want Windows XP and NT
  }

  /* check for ipv4 */
  if ((temp = trace_get_layer3(ltpacket, &ethertype, &remaining)) != NULL &&
      ethertype == TRACE_ETHERTYPE_IP) {
    ip_hdr = (libtrace_ip_t *)temp;
  } else {
    /* not an ip packet */
    return 0;
  }

  if (ip_hdr->ip_p != TRACE_IPPROTO_TCP ||
      !(ntohs(ip_hdr->ip_len) == 48 || ntohs(ip_hdr->ip_len) == 52)) {
    /* not a tcp packet length 48 or 52*/
    return 0;
  }

  if (trace_get_destination_port(ltpacket) != 445) {
    /* not destined to port 445*/
    return 0;
  }

  tcp_hdr = (libtrace_tcp_t *)trace_get_tcp(ltpacket);
  if ((tcp_hdr == NULL) || (!tcp_hdr->syn) || (tcp_hdr->fin) ||
      (tcp_hdr->rst) || (tcp_hdr->psh) || (tcp_hdr->ack) || (tcp_hdr->urg) ||
      (tcp_hdr->ece) || (tcp_hdr->cwr)) {
    /* not TCP or TCP flags other than just SYN*/
    return 0;
  }

  STATE(corsaro)->max_ts = trace_get_timeval(ltpacket);

#ifdef CORSARO_CONFICKERSCAN_DEBUG
  char sip[100];
  strncpy(sip, inet_ntoa(ip_hdr->ip_src), 100);
  char dip[100];
  strncpy(dip, inet_ntoa(ip_hdr->ip_dst), 100);
// corsaro_log(__func__, corsaro, "FLAGS: %x   confickerscan packet: (%s %s %d
// %d) with asnum %d and os (%d %s %s)", packet->state.flags, sip, dip,
// trace_get_source_port(ltpacket), trace_get_destination_port(ltpacket),
// packet->state.asn, packet->state.os_class_id,
// fp_os_names[packet->state.os_name_id], packet->state.os_flavor);
#endif

  k.src_ip = ip_hdr->ip_src.s_addr;
  k.dst_ip = ip_hdr->ip_dst.s_addr;
  k.src_port = trace_get_source_port(ltpacket);
  k.dst_port = trace_get_destination_port(ltpacket);

  v.src_ip = ip_hdr->ip_src.s_addr;
  v.dst_ip = ip_hdr->ip_dst.s_addr;
  v.src_port = trace_get_source_port(ltpacket);
  v.dst_port = trace_get_destination_port(ltpacket);
  v.as = packet->state.asn;
  v.num_packets = 1;
  v.first_timestamp = trace_get_timeval(ltpacket);
  v.last_timestamp = trace_get_timeval(ltpacket);

  if (corsaro_confickerscan_add_inc(STATE(corsaro)->st_hash, &k, &v, corsaro) !=
      0) {
    corsaro_log(__func__, corsaro, "could not add packet");
  }

  return 0;
}
