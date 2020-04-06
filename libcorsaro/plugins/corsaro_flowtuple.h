/*
 * corsaro
 *
 * Alistair King, CAIDA, UC San Diego
 * Shane Alcock, WAND, University of Waikato
 *
 * corsaro-info@caida.org
 *
 * Copyright (C) 2012-2019 The Regents of the University of California.
 * All Rights Reserved.
 *
 * This file is part of corsaro.
 *
 * Permission to copy, modify, and distribute this software and its
 * documentation for academic research and education purposes, without fee, and
 * without a written agreement is hereby granted, provided that
 * the above copyright notice, this paragraph and the following paragraphs
 * appear in all copies.
 *
 * Permission to make use of this software for other than academic research and
 * education purposes may be obtained by contacting:
 *
 * Office of Innovation and Commercialization
 * 9500 Gilman Drive, Mail Code 0910
 * University of California
 * La Jolla, CA 92093-0910
 * (858) 534-5815
 * invent@ucsd.edu
 *
 * This software program and documentation are copyrighted by The Regents of the
 * University of California. The software program and documentation are supplied
 * “as is”, without any accompanying services from The Regents. The Regents does
 * not warrant that the operation of the program will be uninterrupted or
 * error-free. The end-user understands that the program was developed for
 * research purposes and is advised not to rely exclusively on the program for
 * any reason.
 *
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,
 * EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED
 * HEREUNDER IS ON AN “AS IS” BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO
 * OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 */

#ifndef CORSARO_FLOWTUPLE_PLUGIN_H_
#define CORSARO_FLOWTUPLE_PLUGIN_H_

#include "pqueue.h"
#include "libcorsaro.h"
#include "libcorsaro_plugin.h"
#include "libcorsaro_memhandler.h"
#include "libcorsaro_avro.h"

static const char FLOWTUPLE_RESULT_SCHEMA[] =
"{\"type\": \"record\",\
  \"namespace\":\"org.caida.corsaro\",\
  \"name\":\"flowtuple\",\
  \"doc\":\"A Corsaro FlowTuple record. All byte fields are in network byte order.\",\
  \"fields\":[\
      {\"name\": \"time\", \"type\": \"long\"}, \
      {\"name\": \"src_ip\", \"type\": \"long\"}, \
      {\"name\": \"dst_ip\", \"type\": \"long\"}, \
      {\"name\": \"src_port\", \"type\": \"int\"}, \
      {\"name\": \"dst_port\", \"type\": \"int\"}, \
      {\"name\": \"protocol\", \"type\": \"int\"}, \
      {\"name\": \"ttl\", \"type\": \"int\"}, \
      {\"name\": \"tcp_flags\", \"type\": \"int\"}, \
      {\"name\": \"ip_len\", \"type\": \"int\"}, \
      {\"name\": \"tcp_synlen\", \"type\": \"int\"}, \
      {\"name\": \"tcp_synwinlen\", \"type\": \"int\"}, \
      {\"name\": \"packet_cnt\", \"type\": \"long\"}, \
      {\"name\": \"is_spoofed\", \"type\": \"int\"}, \
      {\"name\": \"is_masscan\", \"type\": \"int\"}, \
      {\"name\": \"maxmind_continent\", \"type\": \"string\"}, \
      {\"name\": \"maxmind_country\", \"type\": \"string\"}, \
      {\"name\": \"netacq_continent\", \"type\": \"string\"}, \
      {\"name\": \"netacq_country\", \"type\": \"string\"}, \
      {\"name\": \"prefix2asn\", \"type\": \"long\"} \
      ]}";


typedef struct corsaro_flowtuple_kafka_record {
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

  /** Size of the TCP SYN (including options) */
  uint16_t tcp_synlen;

  /** Announced receive window size in the TCP SYN (including options) */
  uint16_t tcp_synwinlen;

  /** The number of packets that comprise this flowtuple
      This is populated immediately before the tuple is written out */
  uint32_t packet_cnt;

  /** Flag indicating whether the source address was probably spoofed */
  uint8_t is_spoofed;

  /** Flag indicating whether the flow appeared to be a TCP Masscan attempt */
  uint8_t is_masscan;

  /** Country that the source IP corresponds to, according to maxmind */
  char maxmind_country[2];
  /** Continent that the source IP corresponds to, according to maxmind */
  char maxmind_continent[2];
  /** Country that the source IP corresponds to, according to netacq-edge */
  char netacq_country[2];
  /** Continent that the source IP corresponds to, according to netacq-edge */
  char netacq_continent[2];
  /** ASN that the source IP corresponds to, according to pf2asn data */
  uint32_t prefixasn;

} PACKED corsaro_flowtuple_kafka_record_t;

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

  /** Size of the TCP SYN (including options) */
  uint16_t tcp_synlen;

  /** Announced receive window size in the TCP SYN (including options) */
  uint16_t tcp_synwinlen;

  /** The number of packets that comprise this flowtuple
      This is populated immediately before the tuple is written out */
  uint32_t packet_cnt;

  /** The result of applying the hash function to this flowtuple */
  uint32_t hash_val;

  /** Flag indicating whether the source address was probably spoofed */
  uint8_t is_spoofed;

  /** Flag indicating whether the flow appeared to be a TCP Masscan attempt */
  uint8_t is_masscan;

  /** Country that the source IP corresponds to, according to maxmind */
  uint16_t maxmind_country;
  /** Continent that the source IP corresponds to, according to maxmind */
  uint16_t maxmind_continent;
  /** Country that the source IP corresponds to, according to netacq-edge */
  uint16_t netacq_country;
  /** Continent that the source IP corresponds to, according to netacq-edge */
  uint16_t netacq_continent;
  /** ASN that the source IP corresponds to, according to pf2asn data */
  uint32_t prefixasn;
  /** Bitmap indicating which libipmeta tags are valid for this flow */
  uint16_t tagproviders;

  /** Pointer to local memory manager that allocated this flowtuple (only
   *  used if tcmalloc is not available.
   */
  corsaro_memsource_t *memsrc;

  uint64_t sort_key_top;
  uint64_t sort_key_bot;

  /** Local variables used for merging sorted flowtuple maps */
  size_t pqueue_pos;
  pqueue_pri_t pqueue_pri;
  void *from;
  int fromind;
} PACKED;

/* Utility functions for other programs that want to handle flowtuple
 * objects, e.g. corsaroftmerge
 */
void encode_flowtuple_as_avro(struct corsaro_flowtuple *ft,
		corsaro_avro_writer_t *writer, corsaro_logger_t *logger);

int decode_flowtuple_from_avro(avro_value_t *record,
		struct corsaro_flowtuple *ft);

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


/* Top key looks like (IP DST1 is assumed constant) :
 *
 *      -----------------------------------------
 *      | PROTO   | TTL     | FLAGS   | IP_SRC1 |
 *      -----------------------------------------
 *      | IP_SRC2 | IP_SRC3 | IP_SRC4 | IP_DST2 |
 *      -----------------------------------------
 */
#define FT_CALC_SORT_KEY_TOP(ft) \
    ( \
        (((uint64_t)(ft->protocol)) << 56) | \
        (((uint64_t)(ft->ttl)) << 48) | \
        (((uint64_t)(ft->tcp_flags)) << 40) | \
        (((uint64_t)(ft->src_ip)) << 8) | \
        (((uint64_t)(ft->dst_ip & 0x00FFFFFF)) >> 16) \
    )

/* Bottom key looks like :
 *
 *      -----------------------------------------
 *      | IP_DST3 | IP_DST4 | SPORT_1 | SPORT_2 |
 *      -----------------------------------------
 *      | DPORT_1 | DPORT_2 | IP_LEN1 | IP_LEN2 |
 *      -----------------------------------------
 */
#define FT_CALC_SORT_KEY_BOTTOM(ft) \
    ( \
        (((uint64_t)(ft->dst_ip)) << 48) | \
        (((uint64_t)(ft->src_port)) << 32) | \
        (((uint64_t)(ft->dst_port)) << 16) | \
        (((uint64_t)(ft->ip_len))) \
    )


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
