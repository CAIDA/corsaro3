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

#ifndef CORSARO_TAGGING_H_
#define CORSARO_TAGGING_H_

#include <libtrace/linked_list.h>
#include <libipmeta.h>
#include <libtrace.h>
#include <Judy.h>
#include <yaml.h>

#include "libcorsaro_log.h"

#define TAGGER_MAX_MSGSIZE (1 * 1024 * 1024)

/* These are our "built-in" tags */
/* TODO think about how we could support "custom" tags? */

/** An upper bound on the number of built-in tags supported by Corsaro.
 *  Used for array sizing, feel free to increase if we end up adding
 *  more tags.
 */
#define CORSARO_MAX_SUPPORTED_TAGS 2000

/** Each value in this enum represents a bit that can be set to indicate
 *  whether a packet matched a filter condition or not.
 */
enum {
    /** Packet matched the filter for recognising spoofed source addresses */
    CORSARO_FILTERBIT_SPOOFED = 1,
    /** Packet matched the filter for erratic traffic types */
    CORSARO_FILTERBIT_ERRATIC = 2,
    /** Packet matched the filter for RFC 5735 addresses */
    CORSARO_FILTERBIT_NONROUTABLE = 4,
    /** Packet matched the filter for widely deployed scanning tools */
    CORSARO_FILTERBIT_LARGE_SCALE_SCAN = 8,
    /** Packet is not an IP packet, so can be ignored by most applications */
    CORSARO_FILTERBIT_NOTIP = 32768,
};

#define DEFAULT_CONTROL_SOCKET_URI "ipc:///tmp/corsarotagger-control"
#define DEFAULT_IPMETA_SOCKET_URI "ipc:///tmp/corsarotagger-ipmeta-reload"

/** Identifiers for each of the supported built-in tags.
 *  Each identifier should be fairly self-explanatory.
 */
enum {
    CORSARO_TAGID_NETACQ_REGION,
    CORSARO_TAGID_NETACQ_POLYGON,
    CORSARO_TAGID_NETACQ_COUNTRY,
    CORSARO_TAGID_NETACQ_CONTINENT,
    CORSARO_TAGID_MAXMIND_COUNTRY,
    CORSARO_TAGID_MAXMIND_CONTINENT,
    CORSARO_TAGID_PREFIXASN,
    CORSARO_TAGID_SOURCEPORT,
    CORSARO_TAGID_DESTPORT,
    CORSARO_TAGID_PROTOCOL,

};

#define MAX_NETACQ_POLYGONS 8

/** A set of tags that have been derived for an individual packet. */
typedef struct corsaro_packet_tags {

    /** A bitmap that is used to identify which libipmeta tags are
     *  valid, i.e. which providers were enabled.
     */
    uint32_t providers_used;

    /** The ID of the geo-location region for the source IP, as
     *  determined using the netacq-edge data */
    uint16_t netacq_region;

    /** The ID of the geo-location 'polygon' for the source IP, as
     *  determined using the netacq-edge data. Note that there can
     *  be multiple polygons for a single packet, as there are
     *  multiple sources of polygon data. */
    uint32_t netacq_polygon[MAX_NETACQ_POLYGONS];

    /** The ASN that owns the source IP, according to the prefix2asn
     *  data. */
    uint32_t prefixasn;

    /** The 2-letter code describing the geo-location country
     *  for the source IP, as determined using the maxmind data.
     *  Encoded as a uint16_t, one byte for each character. */
    uint16_t maxmind_country;

    /** The 2-letter code describing the geo-location country
     *  for the source IP, as determined using the netacq-edge data.
     *  Encoded as a uint16_t, one byte for each character. */
    uint16_t netacq_country;

    /** The source port used by the packet */
    uint16_t src_port;

    /** The destiantion port used by the packet */
    uint16_t dest_port;

    /** The 2-letter code describing the geo-location continent
     *  for the source IP, as determined using the maxmind data.
     *  Encoded as a uint16_t, one byte for each character. */
    uint16_t maxmind_continent;

    /** The 2-letter code describing the geo-location continent
     *  for the source IP, as determined using the netacq-edge data.
     *  Encoded as a uint16_t, one byte for each character. */
    uint16_t netacq_continent;

    /** Bitmask showing which filters this packet matches, i.e.
     * is it spoofed, is it erratic, is it non-routable */
    uint64_t filterbits;

    /** The hash of the flowtuple ID for this packet -- note this is more
     *  than just a standard 5-tuple and includes fields such as TTL,
     *  IP length, TCP flags etc.
     */
    uint32_t ft_hash;

    /** The post-IP protocol used by the packet */
    uint8_t protocol;
} PACKED corsaro_packet_tags_t;

/** Meta-data that is sent in advance of any published packets, including
 *  the tags that were applied to the packet.
 */
typedef struct corsaro_tagged_packet_header {
    uint8_t hashbin;

    /** Bitmask showing which filters were matched by the packet.
     *  MUST be the second field in this structure so that zeromq
     *  subscription filtering can be applied properly.
     */
    uint16_t filterbits;

    /** The seconds portion of the packet timestamp */
    uint32_t ts_sec;

    /** The microseconds portion of the packet timestamp */
    uint32_t ts_usec;

    /** The length of the packet, starting from the Ethernet header */
    uint16_t pktlen;

    uint16_t wirelen;

    uint32_t tagger_id;

    uint64_t seqno;

    /** The tags that were applied to this packet by the tagging module */
    corsaro_packet_tags_t tags;
} PACKED corsaro_tagged_packet_header_t;


enum {
    TAGGER_REQUEST_HELLO,
    TAGGER_REQUEST_IPMETA_UPDATE,
};

enum {
    TAGGER_LABEL_COUNTRY,
    TAGGER_LABEL_REGION,
    TAGGER_LABEL_POLYGON,
};

typedef struct corsaro_tagger_control_request {
    uint8_t request_type;

    union {
        uint32_t last_version;
    } data;
} PACKED corsaro_tagger_control_request_t;

typedef struct corsaro_tagger_label_hdr {
    uint8_t subject_type;
    uint32_t subject_id;
    uint16_t label_len;
} PACKED corsaro_tagger_label_hdr_t;

typedef struct corsaro_tagger_control_reply {
    uint8_t hashbins;
    uint32_t ipmeta_version;
    uint32_t label_count;

} PACKED corsaro_tagger_control_reply_t;

typedef struct corsaro_ipmeta_state {
    ipmeta_t *ipmeta;

    /** A instance of the Maxmind geolocation provider for libipmeta */
    ipmeta_provider_t *maxmindipmeta;
    /** A instance of the Netacq-edge geolocation provider for libipmeta */
    ipmeta_provider_t *netacqipmeta;
    /** A instance of the prefix to ASN provider for libipmeta */
    ipmeta_provider_t *pfxipmeta;

    pthread_mutex_t mutex;
    uint8_t refcount;
    uint8_t ending;

    Pvoid_t country_labels;
    Pvoid_t region_labels;
    Pvoid_t polygon_labels;

    uint32_t last_reload;
    Pvoid_t recently_added_country_labels;
    Pvoid_t recently_added_region_labels;
    Pvoid_t recently_added_polygon_labels;

} corsaro_ipmeta_state_t;

/** Structure that maintains state required for tagging packets. */
typedef struct corsaro_packet_tagger {

    /** Reference to the corsaro logging instance */
    corsaro_logger_t *logger;

	corsaro_ipmeta_state_t *ipmeta_state;

    /** Number of active libipmeta providers */
    uint8_t providers;

    /** A record set that is used to store the results of a libipmeta lookup */
    ipmeta_record_set_t *records;

} corsaro_packet_tagger_t;

/** Set of configuration options for the libipmeta prefix2asn provider. */
typedef struct prefix2asn_options {
    /** Name of the data structure to use for storing the data. */
    char *ds_name;

    /** Name of the file to read the prefix2asn data from. */
    char *pfx2as_file;

    /** Flag to indicate whether the provider should be enabled or not. */
    uint8_t enabled;
} pfx2asn_opts_t;

typedef struct corsaro_tagged_loss_tracker {
    uint64_t nextseq;
    uint32_t taggerid;

    uint64_t packetsreceived;
    uint64_t bytesreceived;
    uint64_t lostpackets;
    uint32_t lossinstances;
} corsaro_tagged_loss_tracker_t;

/** Set of configuration options for the libipmeta maxmind geo-location
  * provider. */
typedef struct maxmind_options {
    /** Name of the directory to search for blocks and location files. */
    char *directory;

    /** Name of the data structure to use for storing the data. */
    char *ds_name;

    /** Absolute path to the file containing the geo-location blocks. */
    char *blocks_file;

    /** Absolute path to the file containing the geo-location locations. */
    char *locations_file;

    /** Flag to indicate whether the provider should be enabled or not. */
    uint8_t enabled;
} maxmind_opts_t;


/** Set of configuration options for the libipmeta netacq-edge geo-location
  * provider. */
typedef struct netacq_options {
    /** Absolute path to the file containing the geo-location blocks. */
    char *blocks_file;

    /** Absolute path to the file containing the geo-location countries. */
    char *country_file;

    /** Name of the data structure to use for storing the data. */
    char *ds_name;

    /** Absolute path to the file containing the geo-location locations. */
    char *locations_file;

    /** Absolute path to the file containing the geo-location regions. */
    char *region_file;

    /** Absolute path to the file containing the polygon map information. */
    char *polygon_map_file;

    /** List of file names containing the polygon tables. */
    libtrace_list_t *polygon_table_files;

    /** Flag to indicate whether the provider should be enabled or not. */
    uint8_t enabled;
} netacq_opts_t;

/** Creates and initialises a corsaro packet tagger instance.
 *
 *  @param logger       A corsaro logging instance that the tagger can write
 *                      any log messages to.
 *  @param ipmeta       An initialised libipmeta state instance.
 *  @return a pointer to a newly initialised packet tagger, or NULL if an
 *          error occurred.
 */
corsaro_packet_tagger_t *corsaro_create_packet_tagger(corsaro_logger_t *logger,
        corsaro_ipmeta_state_t *ipmeta);

/** Initialises and configures a libipmeta data provider for use with the
 *  corsaro tagger.
 *
 *  @param ipmeta       An initialised libipmeta instance to attach the
 *                      provider to.
 *  @param provid       The identifier for the provider to be configured.
 *  @param options      A pointer to a set of configuration options to be
 *                      applied to the provider (should point to one of
 *                      netacq_opts_t, maxmind_opts_t or pfx2asn_opts_t).
 *  @param logger       A corsaro logging instance to write any errors to.
 *  @return A pointer to a successfully configured libipmeta provider, or
 *          NULL if an error occurred.
 */
ipmeta_provider_t *corsaro_init_ipmeta_provider(ipmeta_t *ipmeta,
        ipmeta_provider_id_t provid, void *options, corsaro_logger_t *logger);

void corsaro_free_ipmeta_state(corsaro_ipmeta_state_t *state);
void corsaro_free_ipmeta_label_map(Pvoid_t labelmap, int dofree);

void corsaro_replace_tagger_ipmeta(corsaro_packet_tagger_t *tagger,
        corsaro_ipmeta_state_t *replace);

/** Destroys a corsaro packet tagger instance, freeing any allocated memory.
 *
 *  @param tagger       The corsaro tagger to be destroyed.
 *
 *  @note the tagger itself is freed by this function, so do not attempt
 *  to free it yourself after calling this function.
 */
void corsaro_destroy_packet_tagger(corsaro_packet_tagger_t *tagger);

/** Derives the set of tags that should be applied to a given packet.
 *
 *  @param tagger       The corsaro tagger to use when doing the tagging.
 *  @param tags         A pointer to the set of tags that is to be updated by
 *                      this function.
 *  @param packet       The packet that will be 'tagged'.
 *  @return 0 in all situations.
 *
 *  @note Any tag information previously contained in 'tags' will be
 *  overwritten by this function with the tags for the provided packet.
 */
int corsaro_tag_packet(corsaro_packet_tagger_t *tagger,
        corsaro_packet_tags_t *tags, libtrace_packet_t *packet);

/** Derives the set of tags that should be applied to a given IP packet.
 *  In this case, the packet is provided via a pointer to the IP header.
 *
 *  @param tagger       The corsaro tagger to use when doing the tagging.
 *  @param tags         A pointer to the set of tags that is to be updated by
 *                      this function.
 *  @param ip           The IP header of the packet that will be 'tagged'.
 *  @param rem          The amount of bytes remaining in the packet, starting
 *                      from the IP header.
 *  @return 0 in all situations.
 *
 *  @note Any tag information previously contained in 'tags' will be
 *  overwritten by this function with the tags for the provided packet.
 */
int corsaro_tag_ippayload(corsaro_packet_tagger_t *tagger,
        corsaro_packet_tags_t *tags, libtrace_ip_t *ip, uint32_t rem);


corsaro_tagged_loss_tracker_t *corsaro_create_tagged_loss_tracker(
        uint8_t maxhashbins);

int corsaro_update_tagged_loss_tracker(corsaro_tagged_loss_tracker_t *tracker,
        corsaro_tagged_packet_header_t *taghdr);

void corsaro_reset_tagged_loss_tracker(corsaro_tagged_loss_tracker_t *tracker);
void corsaro_free_tagged_loss_tracker(corsaro_tagged_loss_tracker_t *tracker);

int corsaro_parse_tagging_provider_config(pfx2asn_opts_t *pfxopts,
        maxmind_opts_t *maxopts, netacq_opts_t *netacqopts,
        yaml_document_t *doc, yaml_node_t *provlist,
        corsaro_logger_t *logger);

void corsaro_load_ipmeta_data(corsaro_logger_t *logger, pfx2asn_opts_t *pfxopts,
        maxmind_opts_t *maxopts, netacq_opts_t *netacqopts,
        corsaro_ipmeta_state_t *ipmeta_state);

void corsaro_free_tagging_provider_config(pfx2asn_opts_t *pfxopts,
        maxmind_opts_t *maxopts, netacq_opts_t *netacqopts);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
