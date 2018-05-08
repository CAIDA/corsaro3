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

#ifndef CORSARO_FILTERING_H_
#define CORSARO_FILTERING_H_

#include <libtrace/linked_list.h>
#include <libtrace.h>

#include "libcorsaro3_log.h"

typedef struct corsaro_filter {

    char *filterstring;
    char *filtername;

} corsaro_filter_t;

typedef enum {

    CORSARO_FILTERID_SPOOFED,
    CORSARO_FILTERID_ERRATIC,
    CORSARO_FILTERID_ROUTED,

    CORSARO_FILTERID_ABNORMAL_PROTOCOL,
    CORSARO_FILTERID_TTL_200,
    CORSARO_FILTERID_FRAGMENT,
    CORSARO_FILTERID_LAST_SRC_IP_0,
    CORSARO_FILTERID_LAST_SRC_IP_255,
    CORSARO_FILTERID_SAME_SRC_DEST_IP,
    CORSARO_FILTERID_UDP_PORT_0,
    CORSARO_FILTERID_TCP_PORT_0,
    CORSARO_FILTERID_RFC5735,
    CORSARO_FILTERID_BACKSCATTER,
    CORSARO_FILTERID_BITTORRENT,
    CORSARO_FILTERID_UDP_0X31,
    CORSARO_FILTERID_UDP_IPLEN_96,
    CORSARO_FILTERID_PORT_53,
    CORSARO_FILTERID_TCP_PORT_23,
    CORSARO_FILTERID_TCP_PORT_80,
    CORSARO_FILTERID_TCP_PORT_5000,
    CORSARO_FILTERID_DNS_RESP_NONSTANDARD,
    CORSARO_FILTERID_NETBIOS_QUERY_NAME,

    CORSARO_FILTERID_MAX
} corsaro_builtin_filter_id_t;

int corsaro_apply_filter_by_id(corsaro_logger_t *logger,
        corsaro_builtin_filter_id_t filtid, libtrace_packet_t *packet);
const char *corsaro_get_builtin_filter_name(corsaro_logger_t *logger,
        corsaro_builtin_filter_id_t filtid);

/* Custom filter API, where extra filters can be specified in a file */
libtrace_list_t *corsaro_create_filters(corsaro_logger_t *logger, char *fname);
void corsaro_destroy_filters(libtrace_list_t *filtlist);

int corsaro_apply_custom_filters_AND(corsaro_logger_t *logger,
        libtrace_list_t *filtlist, libtrace_packet_t *packet);
int corsaro_apply_custom_filters_OR(corsaro_logger_t *logger,
        libtrace_list_t *filtlist, libtrace_packet_t *packet);
int corsaro_apply_single_custom_filter(corsaro_logger_t *logger,
        corsaro_filter_t *filter, libtrace_packet_t *packet);

/* High level built-in filters */
int corsaro_apply_spoofing_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_erratic_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_routable_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);

/* Low level built-in filters (subfilters) */
int corsaro_apply_abnormal_protocol_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_ttl200_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_fragment_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_last_src_byte0_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_last_src_byte255_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_same_src_dest_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_udp_port_zero_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_tcp_port_zero_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_rfc5735_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_backscatter_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_bittorrent_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_udp_0x31_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_udp_iplen_96_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_port_53_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_port_tcp23_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_port_tcp80_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_port_tcp5000_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_dns_resp_oddport_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_netbios_name_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);


#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
