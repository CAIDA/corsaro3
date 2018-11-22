/*
 * corsaro
 *
 * Alistair King, CAIDA, UC San Diego
 * Shane Alcock, WAND, University of Waikato
 *
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

#ifndef CORSARO_FLOWTUPLE_PLUGIN_H_
#define CORSARO_FLOWTUPLE_PLUGIN_H_

#include "pqueue.h"
#include "config.h"
#include "khash.h"
#include "ksort.h"
#include "libcorsaro3.h"
#include "libcorsaro3_plugin.h"
#include "libcorsaro3_memhandler.h"

corsaro_plugin_t *corsaro_flowtuple_alloc(void);

/**
 * @name FlowTuple Structures
 *
 * These data structures are used when reading flowtuple files.
 */

/**
 * Represents the eight important fields in the ip header that we will use to
 * 'uniquely' identify a packet
 *
 * Alberto and i think that most other analysis can be derived from this
 * distribution
 *
 * This struct will be used as the key for the hash.
 *
 * Values are stored in *network* byte order to allow easy (de)serialization.
 *
 * The 'PACKED' attribute instructs GCC to not do any byte alignment. This
 * allows us to directly write the structure to disk
 *
 */
struct corsaro_flowtuple {
  /** The start time for the interval that this flow appeared in */ 
  uint32_t interval_ts;

  /** The source IP */
  uint32_t src_ip;

  /** The destination IP */
  uint32_t dst_ip;

  /** The source port (or ICMP type) */
  uint16_t src_port;

  /** The destination port (or ICMP code) */
  uint16_t dst_port;

  /** The protocol */
  uint8_t protocol;

  /** The TTL */
  uint8_t ttl;

  /** TCP Flags (excluding NS) */
  uint8_t tcp_flags;

  /** Length of the IP packet (from the IP header) */
  uint16_t ip_len;

  /** The number of packets that comprise this flowtuple
      This is populated immediately before the tuple is written out */
  uint32_t packet_cnt;
  uint32_t hash_val;

  uint16_t maxmind_country;
  uint16_t maxmind_continent;
  uint16_t netacq_country;
  uint16_t netacq_continent;
  uint32_t prefixasn;
  uint16_t tagproviders;

  corsaro_memsource_t *memsrc;
  size_t pqueue_pos;
  pqueue_pri_t pqueue_pri;
  void *from;
  int fromind;
} PACKED;

CORSARO_PLUGIN_GENERATE_PROTOTYPES(corsaro_flowtuple)

/*
 * @name FlowTuple Hashing Functions
 *
 * These functions and data structures can be used by third-party programs
 * to efficiently store eight tuple records in a hash table.
 */

/**
 * Used to give the length of the binary representation of a flowtuple
 */
#define CORSARO_FLOWTUPLE_BYTECNT                                              \
  (sizeof(struct corsaro_flowtuple)) /* (4+3+2+2+1+1+1+2)+4*/

/** Convenience macro to help with the hashing function */
#define CORSARO_FLOWTUPLE_SHIFT_AND_XOR(value)                                 \
  h ^= (h << 5) + (h >> 27) + (value)

/** Hash the given flowtuple into a 32bit value
 *
 * @param ft            Pointer to the flowtuple record to hash
 * @return the hashed value
 *
 * The flowtuple is hashed based on the following table:
 *
 *         --------------------------------
 *         |           SRC_IP * 59        |
 *         --------------------------------
 *         |            DST_IP            |
 *         --------------------------------
 *         | SRC_PORT <<16 |   DST_PORT   |
 *         --------------------------------
 *         |  TTL  |TCP_FLG|PROTO|  LEN   |
 *         --------------------------------
 */
uint32_t corsaro_flowtuple_hash_func(struct corsaro_flowtuple *ft);

/** Tests two flowtuples for equality */
#define corsaro_flowtuple_hash_equal(alpha, bravo)                             \
  ((alpha)->src_ip == (bravo)->src_ip && (alpha)->dst_ip == (bravo)->dst_ip && \
   (alpha)->src_port == (bravo)->src_port &&                                   \
   (alpha)->dst_port == (bravo)->dst_port &&                                   \
   (alpha)->protocol == (bravo)->protocol && (alpha)->ttl == (bravo)->ttl &&   \
   (alpha)->tcp_flags == (bravo)->tcp_flags &&                                 \
   (alpha)->ip_len == (bravo)->ip_len &&                                       \
   (alpha)->interval_ts == (bravo)->interval_ts)

/** Tests if one flowtuple is less than another
 *
 * This sort macro has been optimized to provide the best compression
 * when dumping the flowtuple to binary and using GZIP compression
 */
#define corsaro_flowtuple_lt(alpha, bravo)                                   \
  (((alpha)->interval_ts < (bravo)->interval_ts) ||                          \
   (((alpha)->interval_ts == (bravo)->interval_ts) &&                        \
    (((alpha)->protocol < (bravo)->protocol) ||                              \
     (((alpha)->protocol == (bravo)->protocol) &&                            \
      (((alpha)->ttl < (bravo)->ttl) ||                                      \
       (((alpha)->ttl == (bravo)->ttl) &&                                    \
        (((alpha)->tcp_flags < (bravo)->tcp_flags) ||                        \
         (((alpha)->tcp_flags == (bravo)->tcp_flags) &&                      \
          (((alpha)->src_ip < (bravo)->src_ip) ||                            \
           (((alpha)->src_ip == (bravo)->src_ip) &&                          \
            (((alpha)->dst_ip < (bravo)->dst_ip) ||                          \
             (((alpha)->dst_ip == (bravo)->dst_ip) &&                        \
              (((alpha)->src_port < (bravo)->src_port) ||                    \
               (((alpha)->src_port == (bravo)->src_port) &&                  \
                (((alpha)->dst_port < (bravo)->dst_port) ||                  \
                 (((alpha)->dst_port == (bravo)->dst_port) &&                \
                  (((alpha)->ip_len < (bravo)->ip_len))))))))))))))))))


#define FLOWTUPLE_PROC_FUNC_START(name, failret) \
    conf = (corsaro_flowtuple_config_t *)(p->config); \
    state = (struct corsaro_flowtuple_state_t *)local; \
    if (state == NULL) { \
        corsaro_log(p->logger, "NULL state in %s()", name); \
        return failret; \
    } \
    if (conf == NULL) { \
        corsaro_log(p->logger, "NULL config in %s()", name); \
        return failret; \
    }

#define FLOWTUPLE_READ_FUNC_START(name, failret) \
    conf = (corsaro_flowtuple_config_t *)(p->config); \
    if (conf == NULL) { \
        corsaro_log(p->logger, "NULL config in %s()", name); \
        return failret; \
    }


#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
