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


#ifndef __CORSARO_REPORT_CONFIG_H
#define __CORSARO_REPORT_CONFIG_H

/* ---------- GLOBAL METRIC SETTINGS ---------- */

/** The prefix to attach to all metrics */
/** @todo make the darknet name configurable */
#define METRIC_PREFIX "darknet.ucsd-nt"

enum leafmetric_id {
  LEAFMETRIC_ID_UNIQ_SRC_IP = 0,
  LEAFMETRIC_ID_UNIQ_DST_IP = 1,
  LEAFMETRIC_ID_PKT_CNT     = 2,
  LEAFMETRIC_ID_IP_LEN      = 3,

  LEAFMETRIC_ID_CNT         = 4
};

const char *leafmetric_names[] = {
  "uniq_src_ip",
  "uniq_dst_ip",
  "pkt_cnt",
  "ip_len"
};

enum leafmetric_flag {
  LEAFMETRIC_FLAG_UNIQ_SRC_IP   = 0x01,
  LEAFMETRIC_FLAG_UNIQ_DST_IP   = 0x02,
  LEAFMETRIC_FLAG_PKT_CNT       = 0x04,
  LEAFMETRIC_FLAG_IP_LEN        = 0x08,
};

enum submetric_id {
  SUBMETRIC_ID_MAXMIND_CONTINENT     = 0,
  SUBMETRIC_ID_MAXMIND_COUNTRY       = 1,

  SUBMETRIC_ID_NETACQ_EDGE_CONTINENT = 2,
  SUBMETRIC_ID_NETACQ_EDGE_COUNTRY   = 3,
  SUBMETRIC_ID_NETACQ_EDGE_REGION    = 4,

  SUBMETRIC_ID_PFX2AS                = 5,

  SUBMETRIC_ID_PROTOCOL              = 6,

  SUBMETRIC_ID_PORT                  = 7,

  SUBMETRIC_ID_FILTER                = 8,

  SUBMETRIC_ID_TREE                  = 9,

  SUBMETRIC_ID_CNT                   = 10,
};

enum tree_id {
  TREE_ID_UNFILTERED  = 0,
  TREE_ID_NONSPOOFED  = 1,
  TREE_ID_NONERRATIC  = 2,
  TREE_ID_CNT         = 3,
};

const char *tree_names[] = {
  "unfiltered",
  "non-spoofed",
  "non-erratic",
};

#define UNFILTERED_TAG_NAME "all-pkts"

/* for each tree/submetric combo, list the leafmetrics */
const uint8_t tree_submetric_leafmetrics[TREE_ID_CNT][SUBMETRIC_ID_CNT] = {
  /* Unfiltered */
  {
    /* Maxmind continent */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP |
    LEAFMETRIC_FLAG_UNIQ_DST_IP |
    LEAFMETRIC_FLAG_PKT_CNT,

    /* Maxmind country */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP |
    LEAFMETRIC_FLAG_UNIQ_DST_IP |
    LEAFMETRIC_FLAG_PKT_CNT,

    /* Netacq continent */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP |
    LEAFMETRIC_FLAG_UNIQ_DST_IP |
    LEAFMETRIC_FLAG_PKT_CNT,

    /* Netacq country */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP |
    LEAFMETRIC_FLAG_UNIQ_DST_IP |
    LEAFMETRIC_FLAG_PKT_CNT,

    /* Netacq region */
    0,

    /* pfx2as */
    0,

    /* Protocol */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP |
    LEAFMETRIC_FLAG_UNIQ_DST_IP |
    LEAFMETRIC_FLAG_PKT_CNT,

    /* Port */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP |
    LEAFMETRIC_FLAG_UNIQ_DST_IP |
    LEAFMETRIC_FLAG_PKT_CNT,

    /* Filter */
    0,

    /* Tree */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP |
    LEAFMETRIC_FLAG_UNIQ_DST_IP |
    LEAFMETRIC_FLAG_PKT_CNT |
    LEAFMETRIC_FLAG_IP_LEN,
  },

  /** Non-spoofed */
  {
   /* Maxmind continent */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP |
    LEAFMETRIC_FLAG_UNIQ_DST_IP |
    LEAFMETRIC_FLAG_PKT_CNT,

   /* Maxmind country */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP |
    LEAFMETRIC_FLAG_UNIQ_DST_IP |
    LEAFMETRIC_FLAG_PKT_CNT,

    /* Netacq continent */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP |
    LEAFMETRIC_FLAG_UNIQ_DST_IP |
    LEAFMETRIC_FLAG_PKT_CNT,

    /* Netacq country */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP |
    LEAFMETRIC_FLAG_UNIQ_DST_IP |
    LEAFMETRIC_FLAG_PKT_CNT,

    /* Netacq region */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP,

    /* pfx2as */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP |
    LEAFMETRIC_FLAG_UNIQ_DST_IP |
    LEAFMETRIC_FLAG_PKT_CNT |
    LEAFMETRIC_FLAG_IP_LEN,

    /* Protocol */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP |
    LEAFMETRIC_FLAG_UNIQ_DST_IP |
    LEAFMETRIC_FLAG_PKT_CNT,

    /* Port */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP |
    LEAFMETRIC_FLAG_UNIQ_DST_IP |
    LEAFMETRIC_FLAG_PKT_CNT |
    LEAFMETRIC_FLAG_IP_LEN,

    /* Filter */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP |
    LEAFMETRIC_FLAG_UNIQ_DST_IP |
    LEAFMETRIC_FLAG_PKT_CNT |
    LEAFMETRIC_FLAG_IP_LEN,

    /* Tree */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP |
    LEAFMETRIC_FLAG_UNIQ_DST_IP |
    LEAFMETRIC_FLAG_PKT_CNT |
    LEAFMETRIC_FLAG_IP_LEN,
  },

  /** Non-erratic */
  {
   /* Maxmind continent */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP,

   /* Maxmind country */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP,

    /* Netacq continent */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP,

    /* Netacq country */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP,

    /* Netacq region */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP,

    /* pfx2as */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP,

    /* Protocol */
    0,

    /* Port */
    0,

    /* Filter */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP |
    LEAFMETRIC_FLAG_UNIQ_DST_IP |
    LEAFMETRIC_FLAG_PKT_CNT |
    LEAFMETRIC_FLAG_IP_LEN,

    /* Tree */
    LEAFMETRIC_FLAG_UNIQ_SRC_IP |
    LEAFMETRIC_FLAG_UNIQ_DST_IP |
    LEAFMETRIC_FLAG_PKT_CNT |
    LEAFMETRIC_FLAG_IP_LEN,
  },
};

/* ---------- TREE METRIC SETTINGS ---------- */

#define METRIC_PATH_TREE ".overall"

/* ---------- FILTER CRITERIA METRIC SETTINGS ---------- */

#define METRIC_PATH_FILTER ".filter-criteria"

/* ---------- MAXMIND METRIC SETTINGS ---------- */
const char *continent_strings[] = {
  "--",
  "AF",
  "AN",
  "AS",
  "EU",
  "NA",
  "OC",
  "SA",
};

#define METRIC_PATH_MAXMIND_CONTINENT ".geo.maxmind"

#define METRIC_PATH_MAXMIND_COUNTRY    ".geo.maxmind"

/** The max number of values in a 16 bit number (two 8-bit ascii characters) */
#define METRIC_MAXMIND_ASCII_MAX UINT16_MAX


/* ---------- NETACQ EDGE METRIC SETTINGS ---------- */
#define METRIC_PATH_NETACQ_EDGE_CONTINENT     \
  ".geo.netacuity.edge"

#define METRIC_PATH_NETACQ_EDGE_COUNTRY     \
  ".geo.netacuity.edge"

#define METRIC_PATH_NETACQ_EDGE_REGION     \
  ".geo.netacuity.edge"

/** The max region code value (currently the actual max is 30,404, but this
 * could easily go higher. be careful) */
#define METRIC_NETACQ_EDGE_ASCII_MAX UINT16_MAX



/* ---------- PFX2AS METRIC SETTINGS ---------- */
#define METRIC_PATH_PFX2AS             ".routing.pfx2as.asn"

uint32_t tree_pfx2as_max[] = {
  /** unfiltered */
  0,

  /** Non-spoofed */
  3000,

  /** Non-erratic */
  UINT32_MAX,
};

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


/* ---------- PROTOCOL METRIC SETTINGS ---------- */
#define METRIC_PATH_PROTOCOL            ".traffic.protocol"
#define METRIC_PROTOCOL_VAL_MAX         256


/* ---------- PORT METRIC SETTINGS ---------- */
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

#define METRIC_PORT_VAL_CNT UINT16_MAX+1

uint16_t tree_port_max[] = {
  /** unfiltered */
  1024,

  /** Non-spoofed */
  /* ideally we want this to be UINT16_MAX, but until we get DBATS... */
  6000,

  /** Non-erratic */
  0, /* no port info */
};

#define PORT_PREFIX ".traffic.port"

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

#endif /* __CORSARO_REPORT_CONFIG_H */
