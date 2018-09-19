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

#ifndef CORSARO_TAGGING_H_
#define CORSARO_TAGGING_H_

#include <libtrace/linked_list.h>
#include <libipmeta.h>
#include <libtrace.h>

#include "libcorsaro3_log.h"

/* These are our "built-in" tags */
/* TODO think about how we could support "custom" tags? */

/** An upper bound on the number of built-in tags supported by Corsaro.
 *  Used for array sizing, feel free to increase if we end up adding
 *  more tags.
 */
#define CORSARO_MAX_SUPPORTED_TAGS 16

/** A set of tags that have been derived for an individual packet. */
typedef struct corsaro_packet_tags {

    /** A bitmap that is used to identify which libipmeta tags are
     *  valid, i.e. which providers were enabled.
     */
    uint32_t providers_used;

    /** The ID of the geo-location region for the source IP, as
     *  determined using the netacq-edge data */
    uint32_t netacq_region;

    /** The ID of the geo-location 'polygon' for the source IP, as
     *  determined using the netacq-edge data */
    uint32_t netacq_polygon;

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

    /** The post-IP protocol used by the packet */
    uint8_t protocol;
} corsaro_packet_tags_t;

/** Structure that maintains state required for tagging packets. */
typedef struct corsaro_packet_tagger {

    /** Reference to the corsaro logging instance */
    corsaro_logger_t *logger;

    /** Reference to an instance of libipmeta */
    ipmeta_t *ipmeta;

    /** List of active libipmeta providers */
    libtrace_list_t *providers;
    libtrace_list_t *tagfreelist;
    uint32_t providermask;
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
 *  @param ipmeta       An initialised libipmeta instance.
 *  @return a pointer to a newly initialised packet tagger, or NULL if an
 *          error occurred.
 */
corsaro_packet_tagger_t *corsaro_create_packet_tagger(corsaro_logger_t *logger,
        ipmeta_t *ipmeta);

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

/** Update a corsaro tagger to use the given libipmeta provider to tag
 *  packets.
 *
 *  @param tagger       The corsaro tagger that will be using the provider.
 *  @param prov         The libipmeta provider to enable on the tagger.
 *  @return 0 if the provider is enabled successfully, -1 if an error occurs.
 *
 *  @note if prov is NULL, it will be silently ignored.
 */
int corsaro_enable_ipmeta_provider(corsaro_packet_tagger_t *tagger,
        ipmeta_provider_t *prov);

/** Replace a libipmeta provider that is currently being used by a corsaro
 *  tagger with a new one.
 *
 *  This function is intended to help with situations where the underlying
 *  source data file has changed and we need to update the tagger to start
 *  using the new version of the data.
 *
 *  @param tagger       The corsaro tagger that needs to be updated.
 *  @param prov         The replacement libipmeta provider.
 *  @return 0 if successful, -1 if an error occurred.
 *
 *  @note an existing provider is only replaced if it has the same provider
 *  identifier as the one that is in 'prov'. If no existing providers match
 *  the given replacement, the replacement will be appended to the provider
 *  list.
 */
int corsaro_replace_ipmeta_provider(corsaro_packet_tagger_t *tagger,
        ipmeta_provider_t *prov);

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

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
