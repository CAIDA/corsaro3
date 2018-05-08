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
