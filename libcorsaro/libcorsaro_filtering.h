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

    /** Matches if the packet looks like a masscan TCP packet */
    CORSARO_FILTERID_LARGE_SCALE_SCAN,

    /** Matches packets that are using a protocol other than TCP, UDP or
     *  ICMP. Also matches TCP packets that have unconventional flag
     *  combinations.
     */
    CORSARO_FILTERID_ABNORMAL_PROTOCOL,

    /** Matches if the packet has a TTL >= 200 */
    CORSARO_FILTERID_TTL_200,

    /** Matches if the packet is a TCP SYN with no options */
    CORSARO_FILTERID_NO_TCP_OPTIONS,

    /** Matches if the packet is a TCP SYN with a receive window of 1024 */
    CORSARO_FILTERID_TCPWIN_1024,

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

    /** Matches if the packet is UDP and has a destination
     *  port of eighty.
     */
    CORSARO_FILTERID_UDP_DESTPORT_80,
    
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

    /** Matches SIP packets sent over UDP to dest port 5060 over source port 5060 and with a SIP status-code in the first 7 characters of the payload */
    CORSARO_FILTERID_SIP_STATUS,
    
    /** Matches UDP packets with an IP length of 96 */
    CORSARO_FILTERID_UDP_IPLEN_96,

    /** Matches UDP packets with an IP length of 1500 */
    CORSARO_FILTERID_UDP_IPLEN_1500,
    
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

    CORSARO_FILTERID_NOTIP,

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

/* If you want to run *all* filters, use this function instead for
 * maximum performance.
 */
int corsaro_apply_all_filters(corsaro_logger_t *logger,
        libtrace_ip_t *ip, uint32_t iprem, corsaro_filter_torun_t *torun);

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
int corsaro_apply_tcpwin_1024_filter(corsaro_logger_t *logger,
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
int corsaro_apply_udp_destport_eighty_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_rfc5735_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_backscatter_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_bittorrent_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_udp_0x31_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_sip_status_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_udp_iplen_96_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet);
int corsaro_apply_udp_iplen_1500_filter(corsaro_logger_t *logger,
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
