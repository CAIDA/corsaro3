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


#ifndef __CORSARO_CONFICKERSCAN_H
#define __CORSARO_CONFICKERSCAN_H

#include "corsaro_plugin.h"
#include "khash.h"

CORSARO_PLUGIN_GENERATE_PROTOS(corsaro_confickerscan)

typedef struct corsaro_confickerscan_hash_key  {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
} PACKED corsaro_confickerscan_hash_key_t;

typedef struct corsaro_confickerscan_hash_value {
  uint32_t as;
  struct timeval first_timestamp;
  struct timeval last_timestamp;
  uint16_t num_packets;
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
} PACKED corsaro_confickerscan_hash_value_t;

typedef struct corsaro_confickerscan_intermediate_aggregate_hash_key {
  uint32_t as;
  uint32_t src_ip;
} PACKED corsaro_confickerscan_intermediate_aggregate_hash_key_t;

typedef struct corsaro_confickerscan_intermediate_aggregate_hash_value {
  uint32_t as;
  uint32_t num_flows;
  uint32_t total_packets;
  uint32_t num_packets_distribution [5];
  void *seen_dst_ips;
  uint32_t src_ip;
} PACKED corsaro_confickerscan_intermediate_aggregate_hash_value_t;



typedef struct corsaro_confickerscan_aggregate_hash_key {
  uint32_t as;
} PACKED corsaro_confickerscan_aggregate_hash_key_t;

typedef struct corsaro_confickerscan_aggregate_hash_value {
  uint32_t as;
  float avg_packets_per_flow_per_src_ip;
  uint32_t num_flows;
  uint32_t total_packets;
  uint32_t num_packets_distribution [5];
  uint32_t num_src_ips;
} PACKED corsaro_confickerscan_aggregate_hash_value_t;


typedef struct corsaro_confickerscan_how_many_ips_hash_key {
  uint32_t as;
} PACKED corsaro_confickerscan_how_many_ips_hash_key_t;

typedef struct corsaro_confickerscan_how_many_ips_hash_value {
  void *seen_dst_ips;
} PACKED corsaro_confickerscan_how_many_ips_hash_value_t;

/** Convenience macro to help with the hashing function (from corsaro_flowtuple) */
#define CORSARO_CONFICKERSCAN_SHIFT_AND_XOR(value)  h ^= (h<<5) + (h>>27) + (value)

static inline khint32_t corsaro_confickerscan_hash_func(corsaro_confickerscan_hash_key_t *t)
{
  khint32_t h = (khint32_t)t->src_ip*59;
  CORSARO_CONFICKERSCAN_SHIFT_AND_XOR(t->dst_ip);
  CORSARO_CONFICKERSCAN_SHIFT_AND_XOR(t->src_port<<16);
  CORSARO_CONFICKERSCAN_SHIFT_AND_XOR(t->dst_port);
  return h;
}

#define corsaro_confickerscan_hash_eq(alpha, bravo) \
  ((alpha)->src_ip    == (bravo)->src_ip    &&      \
   (alpha)->dst_ip    == (bravo)->dst_ip    &&      \
   (alpha)->src_port  == (bravo)->src_port  &&	    \
   (alpha)->dst_port  == (bravo)->dst_port          )


static inline khint32_t corsaro_confickerscan_intermediate_aggregate_hash_func(corsaro_confickerscan_intermediate_aggregate_hash_key_t *t)
{
  khint32_t h = (khint32_t)t->as*59;
  CORSARO_CONFICKERSCAN_SHIFT_AND_XOR(t->src_ip);
}

#define corsaro_confickerscan_intermediate_aggregate_hash_eq(alpha, bravo) \
  ((alpha)->as     == (bravo)->as && \
   (alpha)->src_ip == (bravo)->src_ip )


static inline khint32_t corsaro_confickerscan_aggregate_hash_func(corsaro_confickerscan_aggregate_hash_key_t *t)
{
  khint32_t h = (khint32_t)t->as*59;
}

#define corsaro_confickerscan_aggregate_hash_eq(alpha, bravo) \
  ((alpha)->as    == (bravo)->as)

static inline khint32_t corsaro_confickerscan_how_many_ips_hash_func(corsaro_confickerscan_how_many_ips_hash_key_t *t)
{
  khint32_t h = (khint32_t)t->as*59;
}

#define corsaro_confickerscan_how_many_ips_hash_eq(alpha, bravo) \
  ((alpha)->as    == (bravo)->as)

//#define CORSARO_CONFICKERSCAN_DEBUG

#define CORSARO_CONFICKERSCAN_FLOW_TIMEOUT 30

#endif /* __CORSARO_CONFICKERSCAN_H */
