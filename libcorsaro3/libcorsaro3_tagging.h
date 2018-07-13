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

#define CORSARO_MAX_SUPPORTED_TAGS 16

typedef struct corsaro_packet_tags {
    uint32_t providers_used;
    uint32_t netacq_region;
    uint32_t netacq_polygon;
    uint32_t prefixasn;
    uint16_t maxmind_country;
    uint16_t netacq_country;
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t maxmind_continent;
    uint16_t netacq_continent;
    uint8_t protocol;

} corsaro_packet_tags_t;

typedef struct corsaro_packet_tagger {
    corsaro_logger_t *logger;
    ipmeta_t *ipmeta;
    libtrace_list_t *providers;
    libtrace_list_t *tagfreelist;
} corsaro_packet_tagger_t;

typedef struct prefix2asn_options {
    char *ds_name;
    char *pfx2as_file;
    uint8_t enabled;
} pfx2asn_opts_t;

typedef struct maxmind_options {
    char *directory;
    char *ds_name;
    char *blocks_file;
    char *locations_file;
    uint8_t enabled;
} maxmind_opts_t;

typedef struct netacq_options {
    char *blocks_file;
    char *country_file;
    char *ds_name;
    char *locations_file;
    char *region_file;
    char *polygon_map_file;
    libtrace_list_t *polygon_table_files;
    uint8_t enabled;
} netacq_opts_t;

corsaro_packet_tagger_t *corsaro_create_packet_tagger(corsaro_logger_t *logger);
int corsaro_enable_ipmeta_provider(corsaro_packet_tagger_t *tagger,
        ipmeta_provider_id_t provid, void *options);
void corsaro_destroy_packet_tagger(corsaro_packet_tagger_t *tagger);

int corsaro_tag_packet(corsaro_packet_tagger_t *tagger,
        corsaro_packet_tags_t *tags, libtrace_packet_t *packet);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
