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

#include "config.h"
#include "khash.h"
#include "ksort.h"
#include "libcorsaro3.h"
#include "libcorsaro3_plugin.h"

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
 * Values are stored in *network* byte order to allow easy (de)serialization
 * Note that since we have a /8, only 3 bytes of the destination IP address
 * are kept (if configured/built with --with-slash-eight)
 *
 * The 'PACKED' attribute instructs GCC to not do any byte alignment. This
 * allows us to directly write the structure to disk
 *
 * @todo make the /8 optimizations generic for any darknet size
 */
struct corsaro_flowtuple {
  /** The source IP */
  uint32_t src_ip;

/** A Structure which represents the 3 useful bytes of the destination ip */
#ifdef CORSARO_SLASH_EIGHT
  struct {
    /** Bits 8-15 */
    uint8_t b;
    /** Bits 16-23 */
    uint8_t c;
    /** Bits 24-31 */
    uint8_t d;
  } dst_ip;
#else
  uint32_t dst_ip;
#endif

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
} PACKED;

/** Possible classification types for a flowtuple */
typedef enum corsaro_flowtuple_class_type {
  /** This packet is a backscatter packet */
  CORSARO_FLOWTUPLE_CLASS_BACKSCATTER = 0,

  /** This packet is an ICMP Request packet */
  CORSARO_FLOWTUPLE_CLASS_ICMPREQ = 1,

  /** The packet is not backscatter, not ICMP Request */
  CORSARO_FLOWTUPLE_CLASS_OTHER = 2,

  /** The highest class value currently in use */
  CORSARO_FLOWTUPLE_CLASS_MAX = CORSARO_FLOWTUPLE_CLASS_OTHER,

} corsaro_flowtuple_class_type_t;

/** Represents the start record of a flowtuple class
 *
 * All values will be in HOST byte order
 */
struct corsaro_flowtuple_class_start {
  /** The flowtuple magic number 'SIXT' (or 'SIXU' if not using /8 opts) */
  uint32_t magic;
  /** The type of class (of type corsaro_flowtuple_class_type_t) */
  uint16_t class_type;
  /** The number of flowtuples in the class */
  uint32_t count;
} PACKED;

/** Represents the end record of a flowtuple class
 *
 * All values will be in HOST byte order
 */
struct corsaro_flowtuple_class_end {
  /** The flowtuple magic number 'SIXT' */
  uint32_t magic;
  /** The type of class (of type corsaro_flowtuple_class_type_t) */
  uint16_t class_type;
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
 *
 * These values correspond to:
 *<pre>
 *     0                              32                              64
 *     ----------------------------------------------------------------
 *     |            src_ip             |      dst_ip >> 8      |  src_
 *     ----------------------------------------------------------------
 *      port   |   dst_port    | proto |  ttl  |tcp_flg|    ip_len    |
 *     ----------------------------------------------------------------
 *     | value...     |
 *     ---------------- </pre>
 *
 * DEPRECATED:
 * Note that the 'value' field is not considered part of the flowtuple
 * and as such, the total record length will be FLOWTUPLE_BITCNT + value_len
 * which, given the current implementation is FLOWTUPLE_BITCNT + 4 or
 * (4+3+2+2+1+1+1+2) + 4 or 160 bits (20 bytes)
 */
#define CORSARO_FLOWTUPLE_BYTECNT                                              \
  (sizeof(struct corsaro_flowtuple)) /* (4+3+2+2+1+1+1+2)+4*/

/** Convert a 32bit network order IP address into the 3 byte flowtuple format */
/* is this platform independent? */
#ifdef CORSARO_SLASH_EIGHT
#define CORSARO_FLOWTUPLE_IP_TO_SIXT(n32, flowtuple)                           \
  {                                                                            \
    (flowtuple)->dst_ip.b = ((n32 & htonl(0x00FF0000)) >> 8);                  \
    (flowtuple)->dst_ip.c = ((n32 & htonl(0x0000FF00)) >> 16);                 \
    (flowtuple)->dst_ip.d = ((n32 & htonl(0x000000FF)) >> 24);                 \
  }
#else
#define CORSARO_FLOWTUPLE_IP_TO_SIXT(n32, flowtuple)                           \
  {                                                                            \
    (flowtuple)->dst_ip = n32;                                                 \
  }
#endif

/** Convert the 3byte flowtuple dest ip to 32bits of network ordered uint32 */
#ifdef CORSARO_SLASH_EIGHT
#define CORSARO_FLOWTUPLE_SIXT_TO_IP(flowtuple)                                \
  (CORSARO_SLASH_EIGHT | (flowtuple)->dst_ip.b << 8 |                          \
   (flowtuple)->dst_ip.c << 16 | (flowtuple)->dst_ip.d << 24)
#else
#define CORSARO_FLOWTUPLE_SIXT_TO_IP(flowtuple) ((flowtuple)->dst_ip)
#endif

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
 * With slash eight optimization:
 *         --------------------------------
 *         |           SRC_IP * 59        |
 * ----------------------------------------
 * |       |     DST_IP << 8      | PROTO |
 * ----------------------------------------
 *         | SRC_PORT <<16 |   DST_PORT   |
 *         --------------------------------
 *         |  TTL  |TCP_FLG|     LEN      |
 *         --------------------------------
 *
 * Without slash eight optimization:
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
khint32_t corsaro_flowtuple_hash_func(struct corsaro_flowtuple *ft);

/** Tests two flowtuples for equality */
#ifdef CORSARO_SLASH_EIGHT
#define corsaro_flowtuple_hash_equal(alpha, bravo)                             \
  ((alpha)->src_ip == (bravo)->src_ip &&                                       \
   (alpha)->dst_ip.b == (bravo)->dst_ip.b &&                                   \
   (alpha)->dst_ip.c == (bravo)->dst_ip.c &&                                   \
   (alpha)->dst_ip.d == (bravo)->dst_ip.d &&                                   \
   (alpha)->src_port == (bravo)->src_port &&                                   \
   (alpha)->dst_port == (bravo)->dst_port &&                                   \
   (alpha)->protocol == (bravo)->protocol && (alpha)->ttl == (bravo)->ttl &&   \
   (alpha)->tcp_flags == (bravo)->tcp_flags &&                                 \
   (alpha)->ip_len == (bravo)->ip_len)
#else
#define corsaro_flowtuple_hash_equal(alpha, bravo)                             \
  ((alpha)->src_ip == (bravo)->src_ip && (alpha)->dst_ip == (bravo)->dst_ip && \
   (alpha)->src_port == (bravo)->src_port &&                                   \
   (alpha)->dst_port == (bravo)->dst_port &&                                   \
   (alpha)->protocol == (bravo)->protocol && (alpha)->ttl == (bravo)->ttl &&   \
   (alpha)->tcp_flags == (bravo)->tcp_flags &&                                 \
   (alpha)->ip_len == (bravo)->ip_len)
#endif

/** Tests if one flowtuple is less than another
 *
 * This sort macro has been optimized to provide the best compression
 * when dumping the flowtuple to binary and using GZIP compression
 */
#ifdef CORSARO_SLASH_EIGHT
#define corsaro_flowtuple_lt(alpha, bravo)                                     \
  (((alpha)->protocol < (bravo)->protocol) ||                                  \
   (((alpha)->protocol == (bravo)->protocol) &&                                \
    (((alpha)->ttl < (bravo)->ttl) ||                                          \
     (((alpha)->ttl == (bravo)->ttl) &&                                        \
      (((alpha)->tcp_flags < (bravo)->tcp_flags) ||                            \
       (((alpha)->tcp_flags == (bravo)->tcp_flags) &&                          \
        (((alpha)->src_ip < (bravo)->src_ip) ||                                \
         (((alpha)->src_ip == (bravo)->src_ip) &&                              \
          (((alpha)->dst_ip.d < (bravo)->dst_ip.d) ||                          \
           (((alpha)->dst_ip.d == (bravo)->dst_ip.d) &&                        \
            (((alpha)->dst_ip.c < (bravo)->dst_ip.c) ||                        \
             (((alpha)->dst_ip.c == (bravo)->dst_ip.c) &&                      \
              (((alpha)->dst_ip.b < (bravo)->dst_ip.b) ||                      \
               (((alpha)->dst_ip.b == (bravo)->dst_ip.b) &&                    \
                (((alpha)->src_port < (bravo)->src_port) ||                    \
                 (((alpha)->src_port == (bravo)->src_port) &&                  \
                  (((alpha)->dst_port < (bravo)->dst_port) ||                  \
                   (((alpha)->dst_port == (bravo)->dst_port) &&                \
                    (((alpha)->ip_len < (bravo)->ip_len))))))))))))))))))))
#else
#define corsaro_flowtuple_lt(alpha, bravo)                                     \
  (((alpha)->protocol < (bravo)->protocol) ||                                  \
   (((alpha)->protocol == (bravo)->protocol) &&                                \
    (((alpha)->ttl < (bravo)->ttl) ||                                          \
     (((alpha)->ttl == (bravo)->ttl) &&                                        \
      (((alpha)->tcp_flags < (bravo)->tcp_flags) ||                            \
       (((alpha)->tcp_flags == (bravo)->tcp_flags) &&                          \
        (((alpha)->src_ip < (bravo)->src_ip) ||                                \
         (((alpha)->src_ip == (bravo)->src_ip) &&                              \
          (((alpha)->dst_ip < (bravo)->dst_ip) ||                              \
           (((alpha)->dst_ip == (bravo)->dst_ip) &&                            \
            (((alpha)->src_port < (bravo)->src_port) ||                        \
             (((alpha)->src_port == (bravo)->src_port) &&                      \
              (((alpha)->dst_port < (bravo)->dst_port) ||                      \
               (((alpha)->dst_port == (bravo)->dst_port) &&                    \
                (((alpha)->ip_len < (bravo)->ip_len))))))))))))))))
#endif


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
    state = (struct corsaro_flowtuple_result_state_t *)local; \
    if (state == NULL) { \
        corsaro_log(p->logger, "NULL state in %s()", name); \
        return failret; \
    } \
    if (conf == NULL) { \
        corsaro_log(p->logger, "NULL config in %s()", name); \
        return failret; \
    }


#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
