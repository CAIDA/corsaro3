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

#include <stdlib.h>
#include <string.h>
#include <libtrace.h>

#include "libcorsaro3_filtering.h"
#include "libcorsaro3_log.h"

static inline int _apply_ttl200_filter(corsaro_logger_t *logger,
        libtrace_ip_t *ip) {

    if (!ip) {
        return -1;
    }
    if (ip->ip_p == TRACE_IPPROTO_ICMP) {
        return 0;
    }
    if (ip->ip_ttl < 200) {
        return 0;
    }

    return 1;
}

static inline int _apply_fragment_filter(corsaro_logger_t *logger,
        libtrace_ip_t *ip) {

    if (!ip) {
        return -1;
    }

    if ((ntohs(ip->ip_off) & 0x9fff) == 0) {
        return 0;
    }
    /* Fragment offset is non-zero OR reserved flag is non-zero */
    return 1;
}

static inline int _apply_last_src_byte0_filter(corsaro_logger_t *logger,
        libtrace_ip_t *ip) {

    if (!ip) {
        return -1;
    }

    /* Do byte-swap just in case someone tries to run this on big-endian */
    if ((ntohl(ip->ip_src.s_addr) & 0xff) == 0) {
        return 1;
    }

    return 0;
}

static inline int _apply_last_src_byte255_filter(corsaro_logger_t *logger,
        libtrace_ip_t *ip) {

    if (!ip) {
        return -1;
    }

    /* Do byte-swap just in case someone tries to run this on big-endian */
    if ((ntohl(ip->ip_src.s_addr) & 0xff) == 0xff) {
        return 1;
    }

    return 0;
}

static inline int _apply_same_src_dest_filter(corsaro_logger_t *logger,
        libtrace_ip_t *ip) {

    if (!ip) {
        return -1;
    }

    if (ip->ip_src.s_addr == ip->ip_dst.s_addr) {
        return 1;
    }
    return 0;
}

static inline int _apply_udp_port_zero_filter(corsaro_logger_t *logger,
        libtrace_udp_t *udp, uint32_t udplen, uint16_t source_port,
        uint16_t dest_port) {

    if (!udp) {
        return 0;
    }

    if (udplen < 4) {
        return -1;
    }

    if (source_port == 0 || dest_port == 0) {
        return 1;
    }

    return 0;
}

static inline int _apply_tcp_port_zero_filter(corsaro_logger_t *logger,
        libtrace_tcp_t *tcp, uint32_t tcplen, uint16_t source_port,
        uint16_t dest_port) {

    if (!tcp) {
        return 0;
    }

    if (tcplen < 4) {
        return -1;
    }

    if (source_port == 0 || dest_port == 0) {
        return 1;
    }

    return 0;
}

static inline int _apply_udp_0x31_filter(corsaro_logger_t *logger,
        libtrace_ip_t *ip, libtrace_udp_t *udp, uint8_t *udppayload,
        uint32_t payloadlen) {

    uint8_t pattern[10] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x31, 0x00};

    if (udppayload == NULL) {
        return 0;
    }

    if (payloadlen < 10) {
        return 0;
    }

    if (ntohs(ip->ip_len) != 58) {
        return 0;
    }

    if (memcmp(pattern, udppayload, 10) == 0) {
        return 1;
    }

    return 0;
}

static inline int _apply_udp_iplen_96_filter(corsaro_logger_t *logger,
        libtrace_ip_t *ip) {

    if (!ip) {
        return -1;
    }

    if (ip->ip_p == TRACE_IPPROTO_UDP && ntohs(ip->ip_len) == 96) {
        return 1;
    }

    return 0;
}

static inline int _apply_port_53_filter(corsaro_logger_t *logger,
        uint16_t source_port, uint16_t dest_port) {

    if (source_port == 53 || dest_port == 53) {
        return 1;
    }

    return 0;
}

static inline int _apply_port_tcp23_filter(corsaro_logger_t *logger,
        libtrace_tcp_t *tcp, uint16_t source_port, uint16_t dest_port) {

    if (tcp != NULL && (source_port == 23 || dest_port == 23)) {
        return 1;
    }

    return 0;
}

static inline int _apply_port_tcp80_filter(corsaro_logger_t *logger,
        libtrace_tcp_t *tcp, uint16_t source_port, uint16_t dest_port) {

    if (tcp != NULL && (source_port == 80 || dest_port == 80)) {
        return 1;
    }

    return 0;
}

static inline int _apply_port_tcp5000_filter(corsaro_logger_t *logger,
        libtrace_tcp_t *tcp, uint16_t source_port, uint16_t dest_port) {

    if (tcp != NULL && (source_port == 5000 || dest_port == 5000)) {
        return 1;
    }

    return 0;
}

static inline int _apply_dns_resp_oddport_filter(corsaro_logger_t *logger,
        libtrace_ip_t *ip, uint16_t *udppayload, uint32_t payloadlen) {

    if (udppayload == NULL) {
        return 0;
    }

    if (ntohs(ip->ip_len) <= 42) {
        return 0;
    }

    if (payloadlen < 12) {
        return 0;
    }

    /* Check flags and codes */
    if ((ntohs(udppayload[1]) & 0xfff0) != 0x8180) {
        return 0;
    }

    /* Question count */
    if (ntohs(udppayload[2]) >= 10) {
        return 0;
    }

    /* Answer record count */
    if (ntohs(udppayload[3]) >= 10) {
        return 0;
    }

    /* NS (authority record) count */
    if (ntohs(udppayload[4]) >= 10) {
        return 0;
    }

    /* Additional record count */
    if (ntohs(udppayload[5]) >= 10) {
        return 0;
    }

    return 1;
}

static inline int _apply_netbios_name_filter(corsaro_logger_t *logger,
        libtrace_ip_t *ip, uint16_t *udppayload, uint32_t payloadlen,
        uint16_t source_port, uint16_t dest_port) {

    if (!udppayload) {
        return 0;
    }

    if (source_port != 137 || dest_port != 137) {
        return 0;
    }

    if (ntohs(ip->ip_len) <= 48) {
        return 0;
    }

    if (payloadlen < 20) {
        return 0;
    }

    if (udppayload[6] != htons(0x2043)) {
        return 0;
    }

    if (udppayload[7] != htons(0x4b41)) {
        return 0;
    }

    if (udppayload[8] != htons(0x4141)) {
        return 0;
    }

    if (udppayload[9] != htons(0x4141)) {
        return 0;
    }

    return 1;
}

static inline int _apply_backscatter_filter(corsaro_logger_t *logger,
        libtrace_tcp_t *tcp, libtrace_udp_t *udp, libtrace_icmp_t *icmp,
        uint16_t source_port, uint8_t *tcppayload) {

    /* TODO return different positive values for filter quality analysis */

    /* UDP backscatter -- just DNS for now */
    if (udp) {
        if (source_port == 53) {
            return 1;
        }
    } else if (icmp) {
        switch(icmp->type) {       
            case 0:     // echo reply
            case 3:     // dest unreachable
            case 4:     // source quench
            case 5:     // redirect
            case 11:    // time exceeded
            case 12:    // parameter problem
            case 14:    // timestamp reply
            case 16:    // info reply
            case 18:    // address mask reply
                return 1;
        }
    } else if (tcp && tcppayload) {
        /* No SYN-ACKs and no RSTs */
        if ((tcp->syn && tcp->ack) || tcp->rst) {
            return 1;
        }
    }
    return 0;
}

static inline int _apply_rfc5735_filter(corsaro_logger_t *logger,
        libtrace_ip_t *ip) {

    uint32_t srcip;

    if (!ip) {
        return -1;
    }

    srcip = ntohl(ip->ip_src.s_addr);

    /* TODO return different positive values for filter quality analysis */

    /* 0.0.0.0/8 */
    if ((srcip & 0xff000000) == 0x00000000) {
        return 1;
    }

    /* 10.0.0.0/8 */
    if ((srcip & 0xff000000) == 0x0a000000) {
        return 1;
    }

    /* 127.0.0.0/8 */
    if ((srcip & 0xff000000) == 0x7f000000) {
        return 1;
    }

    /* 169.254.0.0/16 */
    if ((srcip & 0xffff0000) == 0xa9fe0000) {
        return 1;
    }

    /* 172.16.0.0/12 */
    if ((srcip & 0xfff00000) == 0xac100000) {
        return 1;
    }

    /* 192.0.0.0/24 */
    if ((srcip & 0xffffff00) == 0xc0000000) {
        return 1;
    }

    /* 192.0.2.0/24 */
    if ((srcip & 0xffffff00) == 0xc0000200) {
        return 1;
    }

    /* 192.88.99.0/24 */
    if ((srcip & 0xffffff00) == 0xc0586300) {
        return 1;
    }

    /* 192.168.0.0/16 */
    if ((srcip & 0xffff0000) == 0xc0a80000) {
        return 1;
    }

    /* 198.18.0.0/15 */
    if ((srcip & 0xfffe0000) == 0xc6120000) {
        return 1;
    }

    /* 198.51.100.0/24 */
    if ((srcip & 0xffffff00) == 0xc6336400) {
        return 1;
    }

    /* 203.0.113.0/24 */
    if ((srcip & 0xffffff00) == 0xcb007100) {
        return 1;
    }

    /* 224.0.0.0/4 */
    if ((srcip & 0xf0000000) == 0xe0000000) {
        return 1;
    }

    /* 240.0.0.0/4 */
    if ((srcip & 0xf0000000) == 0xf0000000) {
        return 1;
    }

    return 0;
}

static inline int _apply_abnormal_protocol_filter(corsaro_logger_t *logger,
        libtrace_ip_t *ip, libtrace_tcp_t *tcp, uint8_t *tcppayload) {

    if (!ip) {
        return -1;
    }

    if (ip->ip_p == TRACE_IPPROTO_ICMP || ip->ip_p == TRACE_IPPROTO_UDP) {
        return 0;
    }

    if (ip->ip_p == TRACE_IPPROTO_IPV6) {
        return 0;
    }

    if (ip->ip_p != TRACE_IPPROTO_TCP) {
        return 1;
    }

    if (!tcppayload) {
        return -1;       // filter it?
    }

    /* Allow normal TCP flag combos */
    /* XXX this is a bit silly looking, can we optimise somehow? */

    /* TODO return different positive values for filter quality analysis */
    /* SYN */
    if (tcp->syn && !tcp->ack && !tcp->fin && !tcp->psh && !tcp->rst &&
            !tcp->urg) {
        return 0;
    }

    /* ACK */
    if (tcp->ack && !tcp->syn && !tcp->fin && !tcp->psh && !tcp->rst &&
            !tcp->urg) {
        return 0;
    }

    /* RST */
    if (tcp->rst && !tcp->syn && !tcp->ack && !tcp->fin && !tcp->psh &&
            !tcp->urg) {
        return 0;
    }

    /* FIN */
    if (tcp->fin && !tcp->syn && !tcp->ack && !tcp->rst && !tcp->psh &&
            !tcp->urg) {
        return 0;
    }

    /* SYN-FIN */
    if (tcp->fin && tcp->syn && !tcp->ack && !tcp->rst && !tcp->psh &&
            !tcp->urg) {
        return 0;
    }

    /* SYN-ACK */
    if (tcp->syn && tcp->ack && !tcp->fin && !tcp->rst && !tcp->psh &&
            !tcp->urg) {
        return 0;
    }

    /* FIN-ACK */
    if (tcp->fin && tcp->ack && !tcp->syn && !tcp->rst && !tcp->psh &&
            !tcp->urg) {
        return 0;
    }

    /* ACK-PSH */
    if (tcp->ack && tcp->psh && !tcp->syn && !tcp->rst && !tcp->fin &&
            !tcp->urg) {
        return 0;
    }

    /* FIN-ACK-PSH */
    if (tcp->fin && tcp->ack && tcp->psh && !tcp->syn && !tcp->rst &&
            !tcp->urg) {
        return 0;
    }

    /* Every other flag combo is "abnormal" */
    return 1;
}

static inline int _apply_bittorrent_filter(corsaro_logger_t *logger,
        libtrace_ip_t *ip, libtrace_udp_t *udp, uint16_t *udppayload,
        uint32_t payloadlen) {

    uint32_t *ptr32;
    uint16_t udplen;
    uint16_t iplen;
    uint8_t last10pat[10] = {0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00};

    if (!udp) {
        return 0;
    }
    ptr32 = (uint32_t *)(udppayload);
    udplen = ntohs(udp->len);
    iplen = ntohs(ip->ip_len);

    /* XXX This filter is frightening and should definitely be double
     * checked. */

    /* TODO return different positive values for filter quality analysis */
    if (udplen >= 20 && payloadlen >= 12) {
        if (ntohl(ptr32[0]) == 0x64313a61 || ntohl(ptr32[0]) == 0x64313a72) {
            if (ntohl(ptr32[1]) == 0x64323a69 && ntohl(ptr32[2]) == 0x6432303a)
            {
                return 1;
            }
        }
    }
    if (udplen >= 48 && payloadlen >= 40) {
        if (ntohl(ptr32[5]) == 0x13426974 && ntohl(ptr32[6]) == 0x546f7272 &&
                ntohl(ptr32[7]) == 0x656e7420 &&
                ntohl(ptr32[8]) == 0x70726f74 &&
                ntohl(ptr32[9]) == 0x6f636f6c) {
            return 1;
        }
    }
    if (iplen >= 0x3a) {
        if (ntohs(udppayload[0]) == 0x4102 || ntohs(udppayload[0]) == 0x2102
                || ntohs(udppayload[0]) == 0x3102
                || ntohs(udppayload[0]) == 0x1102) {

            if (payloadlen >= udplen - sizeof(libtrace_udp_t)) {
                uint8_t *ptr8 = (uint8_t *)udppayload;
                ptr8 += (payloadlen - 10);
                if (memcmp(ptr8, last10pat, 10) == 0) {
                    return 1;
                }
            }
        }
    }
    if (iplen == 0x30) {
        if (ntohs(udppayload[0]) == 0x4100 || ntohs(udppayload[0]) == 0x2100
                || ntohs(udppayload[0]) == 0x3102
                || ntohs(udppayload[0]) == 0x1100) {

            return 1;
        }
    }
    if (iplen == 61) {
        if (ntohl(ptr32[3]) == 0x7fffffff && ntohl(ptr32[4]) == 0xab020400 &&
                ntohl(ptr32[5]) == 0x01000000 &&
                ntohl(ptr32[6]) == 0x08000000 && ptr32[7] == 0) {
            return 1;
        }
    }
    return 0;
}

#define PREPROCESS_PACKET            \
    libtrace_ip_t *ip = NULL;       \
    libtrace_tcp_t *tcp = NULL;     \
    libtrace_udp_t *udp = NULL;     \
    libtrace_icmp_t *icmp = NULL;     \
    uint8_t *udppayload = NULL;     \
    uint8_t *tcppayload = NULL;     \
    uint32_t payloadlen = 0;        \
    uint32_t translen = 0;          \
    uint16_t source_port = 0;       \
    uint16_t dest_port = 0;         \
                                    \
    ip = trace_get_ip(packet);      \
                                    \
    if (ip) {                       \
        uint32_t rem;               \
        uint8_t proto;              \
        void *transport = trace_get_transport(packet, &proto, &rem);    \
        translen = rem;             \
                                    \
        if (proto == TRACE_IPPROTO_UDP) {           \
            udp = (libtrace_udp_t *)transport;      \
            if (rem >= 4) {                         \
                source_port = ntohs(udp->source);   \
                dest_port = ntohs(udp->dest);       \
            }                                       \
            udppayload = (uint8_t *)trace_get_payload_from_udp(udp, &rem);  \
            payloadlen = rem;                       \
        }                                           \
        else if (proto == TRACE_IPPROTO_TCP) {      \
            tcp = (libtrace_tcp_t *)transport;      \
            if (rem >= 4) {                         \
                source_port = ntohs(tcp->source);   \
                dest_port = ntohs(tcp->dest);       \
            }                                       \
            tcppayload = (uint8_t *)trace_get_payload_from_tcp(tcp, &rem);  \
            payloadlen = rem;                       \
        } else if (proto == TRACE_IPPROTO_ICMP) {   \
            icmp = (libtrace_icmp_t *)transport;    \
            if (rem >= 2) {                         \
                source_port = icmp->type;           \
                dest_port = icmp->code;             \
            }                                       \
        }                                           \
    }                               \


static int _apply_spoofing_filter(corsaro_logger_t *logger,
        libtrace_ip_t *ip, libtrace_tcp_t *tcp, libtrace_udp_t *udp,
        uint32_t translen, uint16_t source_port, uint16_t dest_port,
        uint8_t *tcppayload) {

    if (_apply_abnormal_protocol_filter(logger, ip, tcp, tcppayload) > 0) {
        return 1;
    }

    if (_apply_ttl200_filter(logger, ip) > 0) {
        return 1;
    }

    if (_apply_fragment_filter(logger, ip) > 0) {
        return 1;
    }

    if (_apply_last_src_byte0_filter(logger, ip) > 0) {
        return 1;
    }

    if (_apply_last_src_byte255_filter(logger, ip) > 0) {
        return 1;
    }

    if (_apply_same_src_dest_filter(logger, ip) > 0) {
        return 1;
    }

    if (_apply_udp_port_zero_filter(logger, udp, translen, source_port,
                dest_port) > 0) {
        return 1;
    }

    if (_apply_tcp_port_zero_filter(logger, tcp, translen, source_port,
                dest_port) > 0) {
        return 1;
    }
    return 0;
}

static int _apply_erratic_filter(corsaro_logger_t *logger,
        libtrace_ip_t *ip, libtrace_tcp_t *tcp, libtrace_udp_t *udp,
        libtrace_icmp_t *icmp,
        uint32_t payloadlen, uint16_t source_port, uint16_t dest_port,
        uint8_t *tcppayload, uint8_t *udppayload) {

    if (udppayload && _apply_udp_0x31_filter(logger, ip, udp, udppayload,
            payloadlen) > 0) {
        return 1;
    }

    if (ip && _apply_udp_iplen_96_filter(logger, ip) > 0) {
        return 1;
    }

    if (_apply_port_53_filter(logger, source_port, dest_port) > 0) {
        return 1;
    }

    if (_apply_port_tcp23_filter(logger, tcp, source_port, dest_port) > 0) {
        return 1;
    }

    if (_apply_port_tcp80_filter(logger, tcp, source_port, dest_port) > 0) {
        return 1;
    }

    if (_apply_port_tcp5000_filter(logger, tcp, source_port, dest_port) > 0) {
        return 1;
    }

    if (udppayload && _apply_dns_resp_oddport_filter(logger, ip, 
            (uint16_t *)udppayload, payloadlen) > 0) {
        return 1;
    }

    if (_apply_netbios_name_filter(logger, ip, (uint16_t *)udppayload,
                payloadlen, source_port, dest_port) > 0) {
        return 1;
    }

    if (_apply_backscatter_filter(logger, tcp, udp, icmp, source_port,
                tcppayload) > 0) {
        return 1;
    }

    if (_apply_bittorrent_filter(logger, ip, udp, (uint16_t *)udppayload,
                payloadlen) > 0) {
        return 1;
    }

    return 0;
}

static inline int _apply_routable_filter(corsaro_logger_t *logger,
        libtrace_ip_t *ip) {
    return _apply_rfc5735_filter(logger, ip);
}

int corsaro_apply_erratic_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {
    PREPROCESS_PACKET
    return _apply_erratic_filter(logger, ip, tcp, udp, icmp, payloadlen,
            source_port, dest_port, tcppayload, udppayload);
}

int corsaro_apply_spoofing_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {
    PREPROCESS_PACKET
    return _apply_spoofing_filter(logger, ip, tcp, udp, translen, source_port,
            dest_port, tcppayload);
}

int corsaro_apply_routable_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {

    PREPROCESS_PACKET
    return _apply_routable_filter(logger, ip);
}

int corsaro_apply_abnormal_protocol_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {
    PREPROCESS_PACKET
    return _apply_abnormal_protocol_filter(logger, ip, tcp, tcppayload);
}

int corsaro_apply_ttl200_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {

    PREPROCESS_PACKET
    return _apply_ttl200_filter(logger, ip);
}

int corsaro_apply_fragment_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {

    PREPROCESS_PACKET
    return _apply_fragment_filter(logger, ip);
}

int corsaro_apply_last_src_byte0_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {

    PREPROCESS_PACKET
    return _apply_last_src_byte0_filter(logger, ip);
}

int corsaro_apply_last_src_byte255_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {
    PREPROCESS_PACKET
    return _apply_last_src_byte255_filter(logger, ip);
}

int corsaro_apply_same_src_dest_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {

    PREPROCESS_PACKET
    return _apply_same_src_dest_filter(logger, ip);
}

int corsaro_apply_udp_port_zero_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {
    PREPROCESS_PACKET
    return _apply_udp_port_zero_filter(logger, udp, translen, source_port,
            dest_port);
}

int corsaro_apply_tcp_port_zero_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {

    PREPROCESS_PACKET
    return _apply_tcp_port_zero_filter(logger, tcp, translen, source_port,
            dest_port);
}

int corsaro_apply_rfc5735_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {
    PREPROCESS_PACKET
    return _apply_rfc5735_filter(logger, ip);
}

int corsaro_apply_backscatter_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {

    PREPROCESS_PACKET
    return _apply_backscatter_filter(logger, tcp, udp, icmp, source_port,
            tcppayload);
}

int corsaro_apply_bittorrent_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {

    PREPROCESS_PACKET
    return _apply_bittorrent_filter(logger, ip, udp, (uint16_t *)udppayload,
            payloadlen);
}

int corsaro_apply_udp_0x31_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {

    PREPROCESS_PACKET
    return _apply_udp_0x31_filter(logger, ip, udp, udppayload, payloadlen);
}

int corsaro_apply_udp_iplen_96_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {

    PREPROCESS_PACKET
    return _apply_udp_iplen_96_filter(logger, ip);
}

int corsaro_apply_port_53_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {

    PREPROCESS_PACKET
    return _apply_port_53_filter(logger, source_port, dest_port);
}

int corsaro_apply_port_tcp23_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {

    PREPROCESS_PACKET
    return _apply_port_tcp23_filter(logger, tcp, source_port, dest_port);
}

int corsaro_apply_port_tcp80_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {

    PREPROCESS_PACKET
    return _apply_port_tcp80_filter(logger, tcp, source_port, dest_port);
}

int corsaro_apply_port_tcp5000_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {

    PREPROCESS_PACKET
    return _apply_port_tcp5000_filter(logger, tcp, source_port, dest_port);
}

int corsaro_apply_dns_resp_oddport_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {
    PREPROCESS_PACKET
    return _apply_dns_resp_oddport_filter(logger, ip,
            (uint16_t *)udppayload, payloadlen);
}

int corsaro_apply_netbios_name_filter(corsaro_logger_t *logger,
        libtrace_packet_t *packet) {

    PREPROCESS_PACKET
    return _apply_netbios_name_filter(logger, ip, (uint16_t *)udppayload,
            payloadlen, source_port, dest_port);
}


const char *corsaro_get_builtin_filter_name(corsaro_logger_t *logger,
        corsaro_builtin_filter_id_t filtid) {

    char unknown[2048];

    if (filtid < 0 || filtid >= CORSARO_FILTERID_MAX) {
        corsaro_log(logger, "Attempted to get name for invalid filter using id %d",
                filtid);
        return NULL;
    }

    switch(filtid) {
        case CORSARO_FILTERID_SPOOFED:
            return "spoofed";
        case CORSARO_FILTERID_ERRATIC:
            return "erratic";
        case CORSARO_FILTERID_ROUTED:
            return "routed";
        case CORSARO_FILTERID_ABNORMAL_PROTOCOL:
            return "abnormal-protocol";
        case CORSARO_FILTERID_TTL_200:
            return "ttl-200";
        case CORSARO_FILTERID_FRAGMENT:
            return "fragmented";
        case CORSARO_FILTERID_LAST_SRC_IP_0:
            return "last-byte-src-0";
        case CORSARO_FILTERID_LAST_SRC_IP_255:
            return "last-byte-src-255";
        case CORSARO_FILTERID_SAME_SRC_DEST_IP:
            return "same-src-dst";
        case CORSARO_FILTERID_UDP_PORT_0:
            return "udp-port-0";
        case CORSARO_FILTERID_TCP_PORT_0:
            return "tcp-port-0";
        case CORSARO_FILTERID_RFC5735:
            return "rfc5735";
        case CORSARO_FILTERID_BACKSCATTER:
            return "backscatter";
        case CORSARO_FILTERID_BITTORRENT:
            return "bittorrent";
        case CORSARO_FILTERID_UDP_0X31:
            return "udp-0x31";
        case CORSARO_FILTERID_UDP_IPLEN_96:
            return "udp-ip-len-96";
        case CORSARO_FILTERID_PORT_53:
            return "port-53";
        case CORSARO_FILTERID_TCP_PORT_23:
            return "tcp-port-23";
        case CORSARO_FILTERID_TCP_PORT_80:
            return "tcp-port-80";
        case CORSARO_FILTERID_TCP_PORT_5000:
            return "tcp-port-5000";
        case CORSARO_FILTERID_DNS_RESP_NONSTANDARD:
            return "dns-resp-non-standard";
        case CORSARO_FILTERID_NETBIOS_QUERY_NAME:
            return "netbios-query-name";
        default:
            corsaro_log(logger, "Warning: no filter name for id %d -- please add one to corsaro_get_builtin_filter_name()", filtid);
            snprintf(unknown, 2048, "unknown-%d", filtid);
            /* Naughty, returning a local variable address */
            return (const char *)unknown;
    }
    return NULL;
}

int corsaro_apply_multiple_filters(corsaro_logger_t *logger,
        libtrace_packet_t *packet, corsaro_filter_torun_t *torun,
        int torun_count) {
    int i;

    PREPROCESS_PACKET

    for (i = 0; i < torun_count; i++) {
        switch(torun[i].filterid) {
            case CORSARO_FILTERID_SPOOFED:
                torun[i].result = _apply_spoofing_filter(logger, ip, tcp,
                        udp, translen, source_port, dest_port, tcppayload);
                break;
            case CORSARO_FILTERID_ERRATIC:
                torun[i].result = _apply_erratic_filter(logger, ip, tcp,
                        udp, icmp, payloadlen, source_port, dest_port,
                        tcppayload, udppayload);
                break;
            case CORSARO_FILTERID_ROUTED:
                torun[i].result = _apply_routable_filter(logger, ip);
                break;
            case CORSARO_FILTERID_ABNORMAL_PROTOCOL:
                torun[i].result = _apply_abnormal_protocol_filter(logger, ip,
                        tcp, tcppayload);
                break;
            case CORSARO_FILTERID_TTL_200:
                torun[i].result =_apply_ttl200_filter(logger, ip);
                break;
            case CORSARO_FILTERID_FRAGMENT:
                torun[i].result =_apply_fragment_filter(logger, ip);
                break;
            case CORSARO_FILTERID_LAST_SRC_IP_0:
                torun[i].result =_apply_last_src_byte0_filter(logger, ip);
                break;
            case CORSARO_FILTERID_LAST_SRC_IP_255:
                torun[i].result =_apply_last_src_byte255_filter(logger, ip);
                break;
            case CORSARO_FILTERID_SAME_SRC_DEST_IP:
                torun[i].result =_apply_same_src_dest_filter(logger, ip);
                break;
            case CORSARO_FILTERID_UDP_PORT_0:
                torun[i].result =_apply_udp_port_zero_filter(logger, udp,
                        translen, source_port, dest_port);
                break;
            case CORSARO_FILTERID_TCP_PORT_0:
                torun[i].result =_apply_tcp_port_zero_filter(logger, tcp,
                        translen, source_port, dest_port);
                break;
            case CORSARO_FILTERID_RFC5735:
                torun[i].result =_apply_rfc5735_filter(logger, ip);
                break;
            case CORSARO_FILTERID_BACKSCATTER:
                torun[i].result =_apply_backscatter_filter(logger, tcp, udp,
                        icmp, source_port, tcppayload);
                break;
            case CORSARO_FILTERID_BITTORRENT:
                torun[i].result =_apply_bittorrent_filter(logger, ip, udp,
                        (uint16_t *)udppayload, payloadlen);
                break;
            case CORSARO_FILTERID_UDP_0X31:
                torun[i].result =_apply_udp_0x31_filter(logger, ip, udp,
                        udppayload, payloadlen);
                break;
            case CORSARO_FILTERID_UDP_IPLEN_96:
                torun[i].result =_apply_udp_iplen_96_filter(logger, ip);
                break;
            case CORSARO_FILTERID_PORT_53:
                torun[i].result =_apply_port_53_filter(logger, source_port,
                        dest_port);
                break;
            case CORSARO_FILTERID_TCP_PORT_23:
                torun[i].result =_apply_port_tcp23_filter(logger, tcp,
                        source_port, dest_port);
                break;
            case CORSARO_FILTERID_TCP_PORT_80:
                torun[i].result =_apply_port_tcp80_filter(logger, tcp,
                        source_port, dest_port);
                break;
            case CORSARO_FILTERID_TCP_PORT_5000:
                torun[i].result =_apply_port_tcp5000_filter(logger, tcp,
                        source_port, dest_port);
                break;
            case CORSARO_FILTERID_DNS_RESP_NONSTANDARD:
                torun[i].result =_apply_dns_resp_oddport_filter(logger, ip,
                        (uint16_t *)udppayload, payloadlen);
                break;
            case CORSARO_FILTERID_NETBIOS_QUERY_NAME:
                torun[i].result =_apply_netbios_name_filter(logger, ip,
                        (uint16_t *)udppayload, payloadlen, source_port,
                        dest_port);
                break;
            default:
                corsaro_log(logger, "Warning: no filter callback for id %d -- please add one to corsaro_apply_multiple_filters()", torun[i].filterid);
                return -1;
        }
    }
    return 0;
}

int corsaro_apply_filter_by_id(corsaro_logger_t *logger,
        corsaro_builtin_filter_id_t filtid, libtrace_packet_t *packet) {

    PREPROCESS_PACKET
    if (filtid < 0 || filtid >= CORSARO_FILTERID_MAX) {
        corsaro_log(logger, "Attempted to apply invalid filter using id %d",
                filtid);
        return -1;
    }

    switch(filtid) {
        case CORSARO_FILTERID_SPOOFED:
            return _apply_spoofing_filter(logger, ip, tcp,
                        udp, translen, source_port, dest_port, tcppayload);
        case CORSARO_FILTERID_ERRATIC:
            return _apply_erratic_filter(logger, ip, tcp,
                    udp, icmp, payloadlen, source_port, dest_port,
                    tcppayload, udppayload);
        case CORSARO_FILTERID_ROUTED:
            return _apply_routable_filter(logger, ip);
        case CORSARO_FILTERID_ABNORMAL_PROTOCOL:
            return _apply_abnormal_protocol_filter(logger, ip, tcp, tcppayload);
        case CORSARO_FILTERID_TTL_200:
            return _apply_ttl200_filter(logger, ip);
        case CORSARO_FILTERID_FRAGMENT:
            return _apply_fragment_filter(logger, ip);
        case CORSARO_FILTERID_LAST_SRC_IP_0:
            return _apply_last_src_byte0_filter(logger, ip);
        case CORSARO_FILTERID_LAST_SRC_IP_255:
            return _apply_last_src_byte255_filter(logger, ip);
        case CORSARO_FILTERID_SAME_SRC_DEST_IP:
            return _apply_same_src_dest_filter(logger, ip);
        case CORSARO_FILTERID_UDP_PORT_0:
            return _apply_udp_port_zero_filter(logger, udp, translen,
                    source_port, dest_port);
        case CORSARO_FILTERID_TCP_PORT_0:
            return _apply_tcp_port_zero_filter(logger, tcp, translen,
                    source_port, dest_port);
        case CORSARO_FILTERID_RFC5735:
            return _apply_rfc5735_filter(logger, ip);
        case CORSARO_FILTERID_BACKSCATTER:
            return _apply_backscatter_filter(logger, tcp, udp, icmp,
                    source_port, tcppayload);
        case CORSARO_FILTERID_BITTORRENT:
            return _apply_bittorrent_filter(logger, ip, udp,
                    (uint16_t *)udppayload, payloadlen);
        case CORSARO_FILTERID_UDP_0X31:
            return _apply_udp_0x31_filter(logger, ip, udp, udppayload,
                    payloadlen);
        case CORSARO_FILTERID_UDP_IPLEN_96:
            return _apply_udp_iplen_96_filter(logger, ip);
        case CORSARO_FILTERID_PORT_53:
            return _apply_port_53_filter(logger, source_port, dest_port);
        case CORSARO_FILTERID_TCP_PORT_23:
            return _apply_port_tcp23_filter(logger, tcp, source_port,
                    dest_port);
        case CORSARO_FILTERID_TCP_PORT_80:
            return _apply_port_tcp80_filter(logger, tcp, source_port,
                    dest_port);
        case CORSARO_FILTERID_TCP_PORT_5000:
            return _apply_port_tcp5000_filter(logger, tcp, source_port,
                    dest_port);
        case CORSARO_FILTERID_DNS_RESP_NONSTANDARD:
            return _apply_dns_resp_oddport_filter(logger, ip,
                    (uint16_t *)udppayload, payloadlen);
        case CORSARO_FILTERID_NETBIOS_QUERY_NAME:
            return _apply_netbios_name_filter(logger, ip,
                    (uint16_t *)udppayload, payloadlen, source_port, dest_port);
        default:
            corsaro_log(logger, "Warning: no filter callback for id %d -- please add one to corsaro_apply_filter_by_id()", filtid);
    }
    return -1;
}

int corsaro_apply_single_custom_filter(corsaro_logger_t *logger,
        corsaro_filter_t *filter, libtrace_packet_t *packet) {

    libtrace_filter_t *ltfilter = NULL;

    ltfilter = trace_create_filter(filter->filterstring);
    if (ltfilter && trace_apply_filter(ltfilter, packet) == 0) {
        /* Filter did not match */
        trace_destroy_filter(ltfilter);
        return 1;
    }
    trace_destroy_filter(ltfilter);
    /* Filter matched */
    return 0;
}

int corsaro_apply_custom_filters_AND(corsaro_logger_t *logger,
        libtrace_list_t *filtlist, libtrace_packet_t *packet) {

    libtrace_list_node_t *n;
    corsaro_filter_t *f;
    libtrace_filter_t *ltfilter = NULL;

    if (filtlist == NULL || filtlist->head == NULL) {
        return 1;
    }

    n = filtlist->head;
    while (n) {
        f = (corsaro_filter_t *)(n->data);
        n = n->next;

        ltfilter = trace_create_filter(f->filterstring);
        if (ltfilter && trace_apply_filter(ltfilter, packet) == 0) {
            trace_destroy_filter(ltfilter);
            return 1;
        }
        trace_destroy_filter(ltfilter);
    }

    /* All filters matched, packet is OK */
    return 0;
}

int corsaro_apply_custom_filters_OR(corsaro_logger_t *logger,
        libtrace_list_t *filtlist, libtrace_packet_t *packet) {

    libtrace_list_node_t *n;
    corsaro_filter_t *f;
    libtrace_filter_t *ltfilter = NULL;
    int matched = 0;

    if (filtlist == NULL || filtlist->head == NULL) {
        return 1;
    }

    n = filtlist->head;
    while (n) {
        f = (corsaro_filter_t *)(n->data);
        n = n->next;

        ltfilter = trace_create_filter(f->filterstring);
        if (ltfilter && trace_apply_filter(ltfilter, packet) > 0) {
            matched = 1;
            trace_destroy_filter(ltfilter);
            break;
        }
        trace_destroy_filter(ltfilter);
    }

    if (matched > 0) {
        /* At least one filter matched, so packet is OK */
        return 0;
    }

    /* No filters in the list matched, discard packet */
    return 1;
}

libtrace_list_t *corsaro_create_filters(corsaro_logger_t *logger,
        char *fname) {

    /* TODO */
    return NULL;
}

void corsaro_destroy_filters(libtrace_list_t *filtlist) {

    libtrace_list_node_t *n;
    corsaro_filter_t *f;

    if (filtlist == NULL) {
        return;
    }

    n = filtlist->head;
    while (n) {
        f = (corsaro_filter_t *)(n->data);
        if (f->filtername) {
            free(f->filtername);
        }
        if (f->filterstring) {
            free(f->filterstring);
        }
        n = n->next;
    }

    libtrace_list_deinit(filtlist);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
