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
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,  * EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED
 * HEREUNDER IS ON AN “AS IS” BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO
 * OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <libipmeta.h>
#include "libcorsaro_filtering.h"
#include "libcorsaro_common.h"
#include "libcorsaro_tagging.h"
#include "libcorsaro_log.h"

typedef struct hash_fields {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t ip_len;
    uint8_t ttl;
    uint8_t tcpflags;
    uint8_t protocol;
} hash_fields_t;

#define CORSARO_TAG_SHIFT_AND_XOR(value) \
  h ^= (h << 5) + (h >> 27) + (value)

static inline uint32_t calc_flow_hash(hash_fields_t *hf) {
    uint32_t h = hf->src_ip * 59;
    CORSARO_TAG_SHIFT_AND_XOR(hf->dst_ip);
    CORSARO_TAG_SHIFT_AND_XOR(((uint32_t)hf->src_port) << 16);
    CORSARO_TAG_SHIFT_AND_XOR((uint32_t)hf->dst_port);
    CORSARO_TAG_SHIFT_AND_XOR((((uint32_t)hf->ttl) << 24) |
            (((uint32_t)hf->tcpflags) << 16));
    CORSARO_TAG_SHIFT_AND_XOR((((uint32_t)hf->protocol) << 8) |
            (((uint32_t)hf->ip_len)));
    return h;
}

corsaro_packet_tagger_t *corsaro_create_packet_tagger(corsaro_logger_t *logger,
        corsaro_ipmeta_state_t *ipmeta) {

    corsaro_packet_tagger_t *tagger = NULL;

    tagger = (corsaro_packet_tagger_t *)calloc(1,
            sizeof(corsaro_packet_tagger_t));
    if (!tagger) {
        return NULL;
    }

    /* TODO
     * In theory, we could allocate and init ipmeta ourselves rather than
     * making the caller do it for us -- corsaro_init_ipmeta_provider()
     * would need to take a tagger instead of an ipmeta as a parameter,
     * but that's probably not a big deal.
     */
    tagger->logger = logger;
    tagger->ipmeta_state = ipmeta;

    if (ipmeta->pfxipmeta) {
        tagger->providers ++;
    }
    if (ipmeta->maxmindipmeta) {
        tagger->providers ++;
    }
    if (ipmeta->netacqipmeta) {
        tagger->providers ++;
    }

    pthread_mutex_lock(&(ipmeta->mutex));
    assert(ipmeta->ending == 0);
    ipmeta->refcount ++;
    pthread_mutex_unlock(&(ipmeta->mutex));
    tagger->records = ipmeta_record_set_init();
    return tagger;
}

#define MAXSPACE (4096)
#define FRAGSPACE (512)

#define COPY_STRING(space, maxspace, used, toadd, errname) \
    if (used + strlen(toadd) >= maxspace) { \
        corsaro_log(logger, "%s option string is too long?", errname); \
        return NULL; \
    } \
    memcpy(nxt, toadd, strlen(toadd)); \
    nxt += strlen(toadd); \
    used += strlen(toadd); \
    space[used] = '\0';


/* One day, someone might update libipmeta to not take horrible getopt
 * style configuration and then these nasty functions could go away. */
static inline char *create_maxmind_option_string(corsaro_logger_t *logger,
        maxmind_opts_t *maxopts) {

    char space[MAXSPACE];
    char fragment[FRAGSPACE];
    char *nxt = space;
    int used = 0;
    int towrite = 0;

    if (maxopts->directory) {
        snprintf(fragment, FRAGSPACE, "-d %s ", maxopts->directory);
        COPY_STRING(space, MAXSPACE, used, fragment, "maxmind");
    }

    if (maxopts->ds_name) {
        snprintf(fragment, FRAGSPACE, "-D %s ", maxopts->ds_name);
        COPY_STRING(space, MAXSPACE, used, fragment, "maxmind");
    }

    if (maxopts->blocks_file) {
        snprintf(fragment, FRAGSPACE, "-b %s ", maxopts->blocks_file);
        COPY_STRING(space, MAXSPACE, used, fragment, "maxmind");
    }

    if (maxopts->locations_file) {
        snprintf(fragment, FRAGSPACE, "-l %s ", maxopts->locations_file);
        COPY_STRING(space, MAXSPACE, used, fragment, "maxmind");
    }

    if (used > 0) {
        return strdup(space);
    }
    return NULL;
}

static inline char *create_prefix2asn_option_string(corsaro_logger_t *logger,
        pfx2asn_opts_t *pfxopts) {

    char space[MAXSPACE];
    char fragment[FRAGSPACE];
    char *nxt = space;
    int used = 0;
    int towrite = 0;

    if (pfxopts->pfx2as_file) {
        snprintf(fragment, FRAGSPACE, "-f %s ", pfxopts->pfx2as_file);
        COPY_STRING(space, MAXSPACE, used, fragment, "prefix2asn");
    }

    if (pfxopts->ds_name) {
        snprintf(fragment, FRAGSPACE, "-D %s ", pfxopts->ds_name);
        COPY_STRING(space, MAXSPACE, used, fragment, "prefix2asn");
    }

    if (used > 0) {
        return strdup(space);
    }
    return NULL;
}

static inline char *create_netacq_option_string(corsaro_logger_t *logger,
        netacq_opts_t *acqopts) {

    char space[MAXSPACE];
    char fragment[FRAGSPACE];
    char *nxt = space;
    int used = 0;
    int towrite = 0;
    libtrace_list_node_t *n;

    if (acqopts->blocks_file) {
        snprintf(fragment, FRAGSPACE, "-b %s ", acqopts->blocks_file);
        COPY_STRING(space, MAXSPACE, used, fragment, "netacq-edge");
    }

    if (acqopts->ds_name) {
        snprintf(fragment, FRAGSPACE, "-D %s ", acqopts->ds_name);
        COPY_STRING(space, MAXSPACE, used, fragment, "netacq-edge");
    }

    if (acqopts->country_file) {
        snprintf(fragment, FRAGSPACE, "-c %s ", acqopts->country_file);
        COPY_STRING(space, MAXSPACE, used, fragment, "netacq-edge");
    }

    if (acqopts->locations_file) {
        snprintf(fragment, FRAGSPACE, "-l %s ", acqopts->locations_file);
        COPY_STRING(space, MAXSPACE, used, fragment, "netacq-edge");
    }

    if (acqopts->region_file) {
        snprintf(fragment, FRAGSPACE, "-r %s ", acqopts->region_file);
        COPY_STRING(space, MAXSPACE, used, fragment, "netacq-edge");
    }

    if (acqopts->polygon_map_file) {
        snprintf(fragment, FRAGSPACE, "-p %s ", acqopts->polygon_map_file);
        COPY_STRING(space, MAXSPACE, used, fragment, "netacq-edge");
    }

    if (acqopts->polygon_table_files) {
        n = acqopts->polygon_table_files->head;
        while (n) {
            char *fname = *((char **)(n->data));
            snprintf(fragment, FRAGSPACE, "-t %s ", fname);
            COPY_STRING(space, MAXSPACE, used, fragment, "netacq-edge");
            n = n->next;
        }
    }

    if (used > 0) {
        return strdup(space);
    }
    return NULL;
}

static char *create_ipmeta_options(corsaro_logger_t *logger,
        ipmeta_provider_id_t provid, void *options) {

    char *opts = NULL;

    switch(provid) {
        case IPMETA_PROVIDER_MAXMIND:
            opts = create_maxmind_option_string(logger,
                    (maxmind_opts_t *)options);
            break;
        case IPMETA_PROVIDER_NETACQ_EDGE:
            opts = create_netacq_option_string(logger,
                    (netacq_opts_t *)options);
            break;
        case IPMETA_PROVIDER_PFX2AS:
            opts = create_prefix2asn_option_string(logger,
                    (pfx2asn_opts_t *)options);
            break;
    }

    return opts;

}

ipmeta_provider_t *corsaro_init_ipmeta_provider(ipmeta_t *ipmeta,
        ipmeta_provider_id_t provid, void *options, corsaro_logger_t *logger) {

    char *optstring = NULL;
    ipmeta_provider_t *prov;

    if (ipmeta == NULL) {
        corsaro_log(logger,
                "Cannot create IPMeta provider: IPMeta instance is NULL.");
        return NULL;
    }

    prov = ipmeta_get_provider_by_id(ipmeta, provid);
    if (prov == NULL) {
        corsaro_log(logger,
                "Cannot create IPMeta provider: %u is an invalid provider ID.",
                provid);
        return NULL;
    }

    optstring = create_ipmeta_options(logger, provid, options);
    if (!optstring) {
        corsaro_log(logger,
                "Cannot create IPMeta provider %u: error parsing options.",
                provid);
        return NULL;
    }

    if (ipmeta_enable_provider(ipmeta, prov, (const char *)optstring) != 0) {
        corsaro_log(logger,
                "Cannot create IPMeta provider %u: libipmeta internal error.",
                provid);
        free(optstring);
        return NULL;
    }

    if (optstring) {
        free(optstring);
    }
    return prov;
}

#define FREE_LABEL_MAP(map, index, rc_int, pval, dofree) \
    index = 0; \
    if (dofree) {  \
        JLF(pval, map, index); \
        while (pval) { \
            free((char *)(*pval)); \
            JLN(pval, map, index); \
        } \
    } \
    JLFA(rc_int, map);

void corsaro_free_ipmeta_state(corsaro_ipmeta_state_t *state) {

    Word_t index = 0;
    int rc_int;
    PWord_t pval;

    if (state->ipmeta) {
        ipmeta_free(state->ipmeta);
    }

    FREE_LABEL_MAP(state->country_labels, index, rc_int, pval, 1);
    FREE_LABEL_MAP(state->recently_added_country_labels, index, rc_int,
            pval, 0);
    FREE_LABEL_MAP(state->region_labels, index, rc_int, pval, 1);
    FREE_LABEL_MAP(state->recently_added_region_labels, index, rc_int, pval, 0);
    FREE_LABEL_MAP(state->polygon_labels, index, rc_int, pval, 1);
    FREE_LABEL_MAP(state->recently_added_polygon_labels, index, rc_int, pval, 0);

    pthread_mutex_destroy(&(state->mutex));
    free(state);
}

void corsaro_free_ipmeta_label_map(Pvoid_t labelmap, int dofree) {
    Word_t index = 0;
    int rc_int;
    PWord_t pval;

    FREE_LABEL_MAP(labelmap, index, rc_int, pval, dofree);
}

void corsaro_replace_tagger_ipmeta(corsaro_packet_tagger_t *tagger,
        corsaro_ipmeta_state_t *replace) {

    pthread_mutex_lock(&(tagger->ipmeta_state->mutex));
    tagger->ipmeta_state->refcount --;
    if (tagger->ipmeta_state->refcount == 0) {
        tagger->ipmeta_state->ending = 1;
        pthread_mutex_unlock(&(tagger->ipmeta_state->mutex));
        corsaro_free_ipmeta_state(tagger->ipmeta_state);
    } else {
        pthread_mutex_unlock(&(tagger->ipmeta_state->mutex));
    }

    pthread_mutex_lock(&(replace->mutex));
    assert(replace->ending == 0);
    replace->refcount ++;
    pthread_mutex_unlock(&(replace->mutex));

    tagger->ipmeta_state = replace;
}

void corsaro_destroy_packet_tagger(corsaro_packet_tagger_t *tagger) {

    if (tagger) {
        if (tagger->records) {
            ipmeta_record_set_free(&tagger->records);
        }

        if (tagger->ipmeta_state) {
            pthread_mutex_lock(&(tagger->ipmeta_state->mutex));
            tagger->ipmeta_state->refcount --;
            if (tagger->ipmeta_state->refcount == 0) {
                tagger->ipmeta_state->ending = 1;
                pthread_mutex_unlock(&(tagger->ipmeta_state->mutex));
                corsaro_free_ipmeta_state(tagger->ipmeta_state);
            } else {
                pthread_mutex_unlock(&(tagger->ipmeta_state->mutex));
            }
        }
        free(tagger);
    }
}

static int update_maxmind_tags(corsaro_logger_t *logger,
        ipmeta_record_t *rec, corsaro_packet_tags_t *tags) {

    if (rec == NULL) {
        return 0;
    }

    tags->maxmind_continent = *((uint16_t *)(rec->continent_code));
    tags->maxmind_country = *((uint16_t *)(rec->country_code));

    tags->providers_used |= (1 << IPMETA_PROVIDER_MAXMIND);

    return 0;
}

static int update_netacq_tags(corsaro_logger_t *logger,
        ipmeta_record_t *rec, corsaro_packet_tags_t *tags,
        corsaro_ipmeta_state_t *ipmeta_state) {

    int polygondetail = 0, i;
    char *polygonfqid;

    if (rec == NULL) {
        return 0;
    }

    tags->netacq_continent = *((uint16_t *)(rec->continent_code));
    tags->netacq_country = *((uint16_t *)(rec->country_code));
    tags->netacq_region = rec->region_code;

    memset(tags->netacq_polygon, 0, sizeof(uint32_t) * MAX_NETACQ_POLYGONS);
    for (i = 0; i < rec->polygon_ids_cnt && i < MAX_NETACQ_POLYGONS; i++) {
        tags->netacq_polygon[i] = (rec->polygon_ids[i] & 0xFFFFFF) \
                                  + (((uint32_t)i) << 24);
    }

    tags->providers_used |= (1 << IPMETA_PROVIDER_NETACQ_EDGE);

    return 0;
}

static int update_pfx2as_tags(corsaro_logger_t *logger,
        ipmeta_record_t *rec, corsaro_packet_tags_t *tags) {

    if (rec == NULL) {
        return 0;
    }

    /* Original corsaro tagging ignored all "group" ASNs so I'm going
     * to do the same for now.
     */
    if (rec->asn_cnt != 1) {
        return 0;
    }

    tags->prefixasn = rec->asn[0];
    tags->providers_used |= (1 << IPMETA_PROVIDER_PFX2AS);
    return 0;
}

static void update_basic_tags(corsaro_logger_t *logger,
        corsaro_packet_tags_t *tags, libtrace_ip_t *ip, uint32_t *rem) {

    void *transport;
    uint8_t proto;
    libtrace_icmp_t *icmp;
    libtrace_tcp_t *tcp;
    hash_fields_t hashdata;

    /* Basic tags refer to those that do not require any libipmeta providers
     * to derive, e.g. port numbers, transport protocols etc.
     */

    tags->protocol = 0;
    tags->src_port = 0;
    tags->dest_port = 0;

    transport = trace_get_payload_from_ip(ip, &proto, rem);

    if (transport == NULL) {
        /* transport header is missing or this is an non-initial IP fragment */
        return;
    }

    memset(&hashdata, 0, sizeof(hashdata));
    hashdata.src_ip = ntohl(ip->ip_src.s_addr);
    hashdata.dst_ip = ntohl(ip->ip_dst.s_addr);
    hashdata.protocol = ip->ip_p;
    hashdata.ttl = ip->ip_ttl;
    hashdata.ip_len = ntohs(ip->ip_len);

    tags->protocol = proto;
    if (proto == TRACE_IPPROTO_ICMP && *rem >= 2) {
        /* ICMP doesn't have ports, but we are interested in the type and
         * code, so why not reuse the space in the tag structure :) */
        icmp = (libtrace_icmp_t *)transport;
        tags->src_port = icmp->type;
        tags->dest_port = icmp->code;
    } else if ((proto == TRACE_IPPROTO_TCP || proto == TRACE_IPPROTO_UDP) &&
            *rem >= 4) {
        tags->src_port = ntohs(*((uint16_t *)transport));
        tags->dest_port = ntohs(*(((uint16_t *)transport) + 1));

        if (proto == TRACE_IPPROTO_TCP && *rem >= sizeof(libtrace_tcp_t)) {
            /* Quicker to just read the whole byte direct from the packet,
             * rather than dealing with the individual flags.
             */
	    uint8_t *tcpf = ((uint8_t *)transport) + 13;
            hashdata.tcpflags = *tcpf;
        }
    }

    hashdata.src_port = tags->src_port;
    hashdata.dst_port = tags->dest_port;

    tags->ft_hash = calc_flow_hash(&hashdata);
    tags->providers_used |= 1;
}

static inline void update_filter_tags(corsaro_logger_t *logger,
        libtrace_ip_t *ip, uint32_t iprem, corsaro_packet_tags_t *tags) {


    corsaro_filter_torun_t torun[CORSARO_FILTERID_MAX];
    int i;

    if (ip == NULL) {
        tags->filterbits = (1 << CORSARO_FILTERID_NOTIP);
        return;
    }

    /* Filtering results are either 0 or 1 (didn't match and
     * matched, respectively) so we use 255 here as an initial
     * value to avoid confusion.
     */
    for (i = 0; i < CORSARO_FILTERID_MAX; i++) {
        torun[i].filterid = i;
        torun[i].result = 255;
    }

    corsaro_apply_multiple_filters(logger, ip, iprem, torun,
            CORSARO_FILTERID_MAX);

    for (i = 0; i < CORSARO_FILTERID_MAX; i++) {
        if (torun[i].result == 1) {
            tags->filterbits |= (1 << i);
        }
    }

}

static inline int _corsaro_tag_ip_packet(corsaro_packet_tagger_t *tagger,
        corsaro_packet_tags_t *tags, libtrace_ip_t *ip, uint32_t rem) {

    uint32_t numips = 0;
    ipmeta_record_t *rec;

    update_filter_tags(tagger->logger, ip, rem, tags);
    if (ip == NULL) {
        return 0;
    }

    update_basic_tags(tagger->logger, tags, ip, &rem);

    if (tagger->providers == 0) {
        return 0;
    }

    /* We only care about the source address on the telescope.
     *
     * If we want to tag bidirectional traffic in the future then we will
     * have to expand our tag structure and run the providers against the
     * dest address too.
     */
    ipmeta_record_set_clear(tagger->records);
    if (ipmeta_lookup_single(tagger->ipmeta_state->ipmeta, ip->ip_src.s_addr,
            0, tagger->records) < 0) {
        corsaro_log(tagger->logger, "error while performing ipmeta lookup");
        return -1;
    }

    while ((rec = ipmeta_record_set_next(tagger->records, &numips)) != NULL) {
        switch(rec->source) {
            case IPMETA_PROVIDER_MAXMIND:
                if (update_maxmind_tags(tagger->logger, rec, tags) != 0) {
                    return -1;
                }
                break;
            case IPMETA_PROVIDER_NETACQ_EDGE:
                if (update_netacq_tags(tagger->logger, rec, tags,
                        tagger->ipmeta_state) != 0) {
                    return -1;
                }
                break;
            case IPMETA_PROVIDER_PFX2AS:
                if (update_pfx2as_tags(tagger->logger, rec, tags) != 0) {
                    return -1;
                }
                break;
            /* TODO other provider methods */
            default:
                printf("???: %u\n", rec->source);
        }
    }
    return 0;
}

int corsaro_tag_packet(corsaro_packet_tagger_t *tagger,
        corsaro_packet_tags_t *tags, libtrace_packet_t *packet) {

    libtrace_ip_t *ip = NULL;
    uint32_t rem;
    uint16_t ethertype;

    memset(tags, 0, sizeof(corsaro_packet_tags_t));
    tags->providers_used = 0;

    if (packet == NULL) {
        return 0;
    }

    ip = (libtrace_ip_t *)trace_get_layer3(packet, &ethertype, &rem);
    if (rem < sizeof(libtrace_ip_t) || ip == NULL) {
        return 0;
    }
    if (ethertype != TRACE_ETHERTYPE_IP) {
        return 0;
    }

    return _corsaro_tag_ip_packet(tagger, tags, ip, rem);

}

int corsaro_tag_ippayload(corsaro_packet_tagger_t *tagger,
        corsaro_packet_tags_t *tags, libtrace_ip_t *ip, uint32_t rem) {

    return _corsaro_tag_ip_packet(tagger, tags, ip, rem);
}

corsaro_tagged_loss_tracker_t *corsaro_create_tagged_loss_tracker(
        uint8_t maxhashbins) {

    corsaro_tagged_loss_tracker_t *tracker;

    tracker = calloc(1, sizeof(corsaro_tagged_loss_tracker_t));
    if (tracker == NULL) {
        return NULL;
    }

    tracker->max_hashbins = maxhashbins;
    tracker->nextseq = calloc(maxhashbins, sizeof(uint64_t));

    if (!tracker->nextseq) {
        free(tracker);
        return NULL;
    }
    return tracker;
}

void corsaro_free_tagged_loss_tracker(corsaro_tagged_loss_tracker_t *tracker) {

    if (!tracker) {
        return;
    }

    if (tracker->nextseq) {
        free(tracker->nextseq);
    }
    free(tracker);
}

void corsaro_reset_tagged_loss_tracker(corsaro_tagged_loss_tracker_t *tracker)
{
    tracker->lostpackets = 0;
    tracker->lossinstances = 0;
    tracker->bytesreceived = 0;
    tracker->packetsreceived = 0;
}

int corsaro_update_tagged_loss_tracker(corsaro_tagged_loss_tracker_t *tracker,
        corsaro_tagged_packet_header_t *taghdr) {

    int seqindex;
    uint64_t thisseq;
    uint32_t tagid;

    if (tracker == NULL || taghdr == NULL) {
        return -1;
    }

	tagid = ntohl(taghdr->tagger_id);
	thisseq = bswap_be_to_host64(taghdr->seqno);

	if (taghdr->hashbin <= 'Z') {
		seqindex = taghdr->hashbin - 'A';
	} else {
		seqindex = taghdr->hashbin - 'a';
	}

	if (tagid != tracker->taggerid) {
		/* tagger has restarted -- reset our sequence numbers */
		tracker->taggerid = tagid;
		memset(tracker->nextseq, 0, sizeof(uint64_t) * tracker->max_hashbins);
	}

	/* seqno of 0 is a reserved value -- we will never receive a seqno
	 * of 0, so we can use it to mark the next expected sequence number
	 * as "unknown".
	 */
	if (tracker->nextseq[seqindex] != 0 &&
			thisseq != tracker->nextseq[seqindex]) {
		tracker->lostpackets += (thisseq - tracker->nextseq[seqindex]);
		tracker->lossinstances ++;
	}
    tracker->packetsreceived ++;
    tracker->bytesreceived += (taghdr->pktlen);

	tracker->nextseq[seqindex] = thisseq + 1;
	if (tracker->nextseq[seqindex] == 0) {
		tracker->nextseq[seqindex] = 1;
	}

	return 0;
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
