/*
 * corsaro
 *
 * Alistair King, CAIDA, UC San Diego
 * Shane Alcock, WAND, University of Waikato
 *
 * corsaro-info@caida.org
 *
 * Copyright (C) 2012-2021 The Regents of the University of California.
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

#ifndef LIBCORSARO_FLOWTUPLE_H_
#define LIBCORSARO_FLOWTUPLE_H_

#include <inttypes.h>
#include "libcorsaro_avro.h"
#include "libcorsaro_log.h"

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
struct corsaro_flowtuple_data {
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
} PACKED;

/* Utility functions for other programs that want to handle flowtuple
 * objects, e.g. corsaroftmerge
 */
void encode_flowtuple_as_avro(struct corsaro_flowtuple_data *ft,
        corsaro_avro_writer_t *writer, corsaro_logger_t *logger);

int decode_flowtuple_from_avro(avro_value_t *record,
        struct corsaro_flowtuple_data *ft);


#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
