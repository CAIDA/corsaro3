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

#include "libcorsaro_log.h"

/** Structure for a custom corsaro filter */
typedef struct corsaro_filter {

    /** BPF string to be applied to the packet for this filter */
    char *filterstring;

    /** Label used to identify this filter in output */
    char *filtername;

} corsaro_filter_t;

/** List of IDs for built-in filters.
 *
 *  Built-in filters are those that are implemented within corsaro
 *  using libtrace code rather than by compiling BPF at run-time.
 *  Note that filter descriptions in the documentation are generalised
 *  and may not fully describe the filter -- refer to the source code
 *  for the relevant filter for this information.
 */
typedef enum {

    /** Matches if the packet is likely to have a spoofed source address.
     *  Encompasses a number of sub-filters (if any match, then spoofed
     *  also matches). */
    CORSARO_FILTERID_SPOOFED,

    /** Matches if the packet is likely to match traffic that is known
     *  to be erratic in volume (as opposed to consistent base-line
     *  background traffic). Encompasses a number of sub-filters
     *  (if any match, then erratic also matches).
     */
    CORSARO_FILTERID_ERRATIC,

    /** Matches if the source address belongs to any of the non-routable
     *  RFC5735 address ranges.
     */
    CORSARO_FILTERID_ROUTED,

    CORSARO_FILTERID_LARGE_SCALE_SCAN,

    /** Matches packets that are using a protocol other than TCP, UDP or
     *  ICMP. Also matches TCP packets that have unconventional flag
     *  combinations.
     */
    CORSARO_FILTERID_ABNORMAL_PROTOCOL,

    /** Matches if the packet has a TTL >= 200 */
    CORSARO_FILTERID_TTL_200,

    CORSARO_FILTERID_NO_TCP_OPTIONS,

    /** Matches if the packet is an IP fragment */
    CORSARO_FILTERID_FRAGMENT,

    /** Matches if the last byte of the source IP address is zero */
    CORSARO_FILTERID_LAST_SRC_IP_0,

    /** Matches if the last byte of the source IP address is 255 */
    CORSARO_FILTERID_LAST_SRC_IP_255,

    /** Matches if the source IP address and destination IP address are
     *  the same. */
    CORSARO_FILTERID_SAME_SRC_DEST_IP,

    /** Matches if the packet is UDP and has either a source or destination
     *  port of zero.
     */
    CORSARO_FILTERID_UDP_PORT_0,

    /** Matches if the packet is TCP and has either a source or destination
     *  port of zero.
     */
    CORSARO_FILTERID_TCP_PORT_0,

    /** Matches if the source address belongs to any of the non-routable
     *  RFC5735 address ranges.
     */
    CORSARO_FILTERID_RFC5735,

    /** Matches packets that are likely to be backscatter, e.g. ICMP
     *  replies, TCP SYN ACKs and RSTs, DNS replies
     */
    CORSARO_FILTERID_BACKSCATTER,

    /** Matches UDP bittorrent packets */
    CORSARO_FILTERID_BITTORRENT,

    /** Matches UDP packets with a specific payload pattern */
    CORSARO_FILTERID_UDP_0X31,

    /** Matches UDP packets with an IP length of 96 */
    CORSARO_FILTERID_UDP_IPLEN_96,

    /** Matches packets where either the source or destination port is 53
     *  (i.e. DNS)
     */
    CORSARO_FILTERID_PORT_53,

    /** Matches TCP packets where either the source or destination port is 23
     *  (i.e. telnet)
     */
    CORSARO_FILTERID_TCP_PORT_23,

    /** Matches TCP packets where either the source or destination port is 80
     *  (i.e. HTTP)
     */
    CORSARO_FILTERID_TCP_PORT_80,

    /** Matches TCP packets where either the source or destination port is 5000
     *  (i.e. UPnP)
     */
    CORSARO_FILTERID_TCP_PORT_5000,

    /** Matches UDP packets where the payload appears to be a DNS response */
    CORSARO_FILTERID_DNS_RESP_NONSTANDARD,

    /** Matches UDP packets that appear to be NetBIOS queries */
    CORSARO_FILTERID_NETBIOS_QUERY_NAME,

    /** Special reserved ID for the "last" filter -- this should always
     *  be at the end of enum declaration.
     */
    CORSARO_FILTERID_MAX
} corsaro_builtin_filter_id_t;

typedef struct corsaro_filter_torun {
    corsaro_builtin_filter_id_t filterid;
    uint8_t result;
} corsaro_filter_torun_t;

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

/* Function for running multiple filters in a single function call,
 * can be more efficient since we don't end up doing multiple IP, TCP, etc.
 * header lookups for each filter as can happen if you apply the filters
 * individually.
 */
int corsaro_apply_multiple_filters(corsaro_logger_t *logger,
        libtrace_ip_t *ip, uint32_t iprem, corsaro_filter_torun_t *torun,
        int torun_count);

/* High level built-in filters */
int corsaro_apply_spoofing_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_erratic_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_routable_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_large_scale_scan_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);

/* Low level built-in filters (subfilters) */
int corsaro_apply_abnormal_protocol_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_ttl200_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_no_tcp_options_filter(corsaro_logger_t *logger,
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
