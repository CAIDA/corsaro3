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

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <yaml.h>
#include <libipmeta.h>
#include <libtrace/message_queue.h>
#include <errno.h>
#include <math.h>

#ifdef __linux__
#include <sys/epoll.h>
#else
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#endif

#include <uthash.h>
#include "libcorsaro3.h"
#include "libcorsaro3_memhandler.h"
#include "libcorsaro3_plugin.h"
#include "libcorsaro3_avro.h"
#include "corsaro_report.h"
#include "utils.h"

#define CORSARO_REPORT_MAGIC 0x52455054
#define PLUGIN_NAME "report"

#define METRIC_MAXMIND_2CHAR_MAX (65536)
#define METRIC_PORT_MAX (65536)
#define METRIC_ICMP_MAX (256)
#define METRIC_IPPROTOS_MAX (256)

static corsaro_plugin_t corsaro_report_plugin = {
    PLUGIN_NAME,
    CORSARO_PLUGIN_ID_REPORT,
    CORSARO_REPORT_MAGIC,
    CORSARO_PLUGIN_GENERATE_BASE_PTRS(corsaro_report),
    CORSARO_PLUGIN_GENERATE_TRACE_PTRS(corsaro_report),
    CORSARO_PLUGIN_GENERATE_MERGE_PTRS(corsaro_report),
    CORSARO_PLUGIN_GENERATE_TAIL
};

typedef struct corsaro_report_config {
    /** Standard options, e.g. template */
    corsaro_plugin_proc_options_t basic;
    /** Additional labelling to attach to every avro record -- useful for
     *  distinguishing between different inputs, for instance */
    char *outlabel;
} corsaro_report_config_t;

typedef enum {
    CORSARO_METRIC_CLASS_MAXMIND_CONTINENT,
    CORSARO_METRIC_CLASS_MAXMIND_COUNTRY,
    CORSARO_METRIC_CLASS_TCP_SOURCE_PORT,
    CORSARO_METRIC_CLASS_TCP_DEST_PORT,
    CORSARO_METRIC_CLASS_UDP_SOURCE_PORT,
    CORSARO_METRIC_CLASS_UDP_DEST_PORT,
    CORSARO_METRIC_CLASS_IP_PROTOCOL,
    CORSARO_METRIC_CLASS_ICMP_CODE,
    CORSARO_METRIC_CLASS_ICMP_TYPE,
    CORSARO_METRIC_CLASS_COMBINED,
} corsaro_report_metric_class_t;

enum {
    CORSARO_REPORT_MERGE_JOB,
    CORSARO_REPORT_MERGE_JOB_HALT,
    CORSARO_REPORT_MERGE_JOB_REFLECT,
};

enum {
    CORSARO_REPORT_IPSEEN_SOURCE = 1,
    CORSARO_REPORT_IPSEEN_DEST = 2,
};

typedef struct report_metric_identifier {
    corsaro_report_metric_class_t class;
    uint32_t metricval;
} corsaro_report_metric_id_t;

typedef struct metric_per_ip {
    corsaro_report_metric_id_t metid;
    corsaro_memsource_t *source;
    uint64_t pkt_cnt;
    uint64_t ip_len;
    uint8_t seenas;
    UT_hash_handle hh;
} PACKED corsaro_report_ip_metric_t;

typedef struct corsaro_report_uniq_ip {
    uint32_t ipaddr;
    corsaro_memsource_t *source;
    corsaro_memhandler_t *handler;
    UT_hash_handle hh;
} PACKED corsaro_report_uniq_ip_t;

typedef struct corsaro_report_interim_merge_result {
    corsaro_report_metric_id_t metid;

    uint64_t pkt_cnt;
    uint64_t ip_len;

    corsaro_report_uniq_ip_t *uniq_src_map;
    corsaro_report_uniq_ip_t *uniq_dst_map;

    corsaro_memhandler_t *handler;
    corsaro_memsource_t *memsource;
    UT_hash_handle hh;
} PACKED corsaro_report_interim_merge_result_t;

typedef struct report_result {
    corsaro_report_metric_id_t metid;

    uint64_t pkt_cnt;
    uint64_t ip_len;
    uint32_t uniq_src_ips;
    uint32_t uniq_dst_ips;
    uint32_t attimestamp;

    char *label;
    char *metrictype;
    char *metricval;

    corsaro_memhandler_t *handler;
    corsaro_memsource_t *memsource;
    UT_hash_handle hh;

} PACKED corsaro_report_result_t;

typedef struct known_ip {
    corsaro_report_ip_metric_t *assocmetrics;
    corsaro_memsource_t *source;
    uint32_t ipaddr;
    UT_hash_handle hh;
} PACKED corsaro_report_ip_t;

typedef struct ipblock {
    corsaro_report_ip_t *memberips;
    corsaro_memsource_t *source;
    uint32_t blockid;
    UT_hash_handle hh;
} PACKED corsaro_report_ipblock_t;

typedef struct metric_set {
    corsaro_report_ipblock_t *knownips;
    corsaro_memhandler_t *ipreport_handler;
    corsaro_memhandler_t *ip_handler;
    corsaro_memhandler_t *ipblock_handler;
} corsaro_metric_set_t;


typedef struct report_state {
    corsaro_metric_set_t *metrics;
} corsaro_report_state_t;

typedef struct corsaro_report_merge_job {

    uint8_t jobtype;
    corsaro_report_ipblock_t **ipblocks;
    corsaro_metric_set_t **parents;
    int blockcount;

} corsaro_report_merge_job_t;

typedef struct corsaro_report_merge_result {
    corsaro_report_result_t *res;
} corsaro_report_merge_result_t;

typedef struct corsaro_report_worker {

    pthread_t threadid;
    int tnum;
    libtrace_message_queue_t jobqueue;
    libtrace_message_queue_t resultqueue;
    corsaro_memhandler_t *intres_handler;
    corsaro_memhandler_t *res_handler;
    corsaro_memhandler_t *ip_handler;

} corsaro_report_worker_t;

typedef struct report_merge_state {
    corsaro_avro_writer_t *writer;

    int workerthreadcount;
#ifdef __linux__
    int epoll_fd;
#else
    int kqueue_fd;
#endif

    corsaro_report_worker_t *workthreads;

} corsaro_report_merge_state_t;

static const char REPORT_RESULT_SCHEMA[] =
"{\"type\": \"record\",\
  \"namespace\": \"org.caida.corsaro\",\
  \"name\": \"report\",\
  \"doc\":  \"A Corsaro report result containing statistics describing the \
              range of traffic that was assigned to each supported tag by \
              corsarotrace.\",\
  \"fields\": [\
        {\"name\": \"bin_timestamp\", \"type\": \"long\"}, \
        {\"name\": \"source_label\", \"type\": \"string\"}, \
        {\"name\": \"metric_name\", \"type\": \"string\"}, \
        {\"name\": \"metric_value\", \"type\": \"string\"}, \
        {\"name\": \"src_ip_cnt\", \"type\": \"long\"}, \
        {\"name\": \"dest_ip_cnt\", \"type\": \"long\"}, \
        {\"name\": \"pkt_cnt\", \"type\": \"long\"}, \
        {\"name\": \"byte_cnt\", \"type\": \"long\"} \
        ]}";

corsaro_plugin_t *corsaro_report_alloc(void) {
    return &(corsaro_report_plugin);
}

static inline int report_result_to_avro(corsaro_logger_t *logger,
        avro_value_t *av, void *repres) {

    avro_value_t field;
    corsaro_report_result_t *res = (corsaro_report_result_t *)repres;

    CORSARO_AVRO_SET_FIELD(long, av, field, 0, "bin_timestamp", "report",
            res->attimestamp);
    CORSARO_AVRO_SET_FIELD(string, av, field, 1, "source_label", "report",
            res->label);
    CORSARO_AVRO_SET_FIELD(string, av, field, 2, "metric_name", "report",
            res->metrictype);
    CORSARO_AVRO_SET_FIELD(string, av, field, 3, "metric_value", "report",
            res->metricval);
    CORSARO_AVRO_SET_FIELD(long, av, field, 4, "src_ip_cnt", "report",
            res->uniq_src_ips);
    CORSARO_AVRO_SET_FIELD(long, av, field, 5, "dest_ip_cnt", "report",
            res->uniq_dst_ips);
    CORSARO_AVRO_SET_FIELD(long, av, field, 6, "pkt_cnt", "report",
            res->pkt_cnt);
    CORSARO_AVRO_SET_FIELD(long, av, field, 7, "byte_cnt", "report",
            res->ip_len);
    return 0;
}

int corsaro_report_parse_config(corsaro_plugin_t *p, yaml_document_t *doc,
        yaml_node_t *options) {

    corsaro_report_config_t *conf;
    yaml_node_t *key, *value;
    yaml_node_pair_t *pair;

    conf = (corsaro_report_config_t *)malloc(sizeof(corsaro_report_config_t));
    if (conf == NULL) {
        corsaro_log(p->logger,
                "unable to allocate memory to store report plugin config.");
        return -1;
    }

    CORSARO_INIT_PLUGIN_PROC_OPTS(conf->basic);
    conf->outlabel = NULL;

    if (options->type != YAML_MAPPING_NODE) {
        corsaro_log(p->logger,
                "report plugin config should be a map.");
        free(conf);
        return -1;
    }

    for (pair = options->data.mapping.pairs.start;
            pair < options->data.mapping.pairs.top; pair ++) {

        char *val;
        key = yaml_document_get_node(doc, pair->key);
        value = yaml_document_get_node(doc, pair->value);
        val = (char *)value->data.scalar.value;

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value,
                    "output_row_label") == 0) {
            if (conf->outlabel) {
                corsaro_log(p->logger,
                        "duplicate definition of 'output_row_label' in report config -- using latter.");
                free(conf->outlabel);
            }
            conf->outlabel = strdup(val);
        }
    }

    p->config = conf;

    return 0;
}

int corsaro_report_finalise_config(corsaro_plugin_t *p,
        corsaro_plugin_proc_options_t *stdopts) {

    corsaro_report_config_t *conf;

    conf = (corsaro_report_config_t *)(p->config);
    conf->basic.template = stdopts->template;
    conf->basic.monitorid = stdopts->monitorid;

    if (conf->outlabel == NULL) {
        conf->outlabel = strdup("unlabeled");
    }

    corsaro_log(p->logger,
            "report plugin: labeling all output rows with '%s'",
            conf->outlabel);

    return 0;
}

void corsaro_report_destroy_self(corsaro_plugin_t *p) {
    if (p->config) {
        corsaro_report_config_t *conf;
        conf = (corsaro_report_config_t *)(p->config);
        if (conf->outlabel) {
            free(conf->outlabel);
        }

        free(p->config);
    }
    p->config = NULL;
}

static inline corsaro_metric_set_t *init_metric_set(corsaro_logger_t *logger,
        uint8_t newhandlers) {

    corsaro_metric_set_t *mset = (corsaro_metric_set_t *)malloc(
            sizeof(corsaro_metric_set_t));

    mset->knownips = NULL;

    if (newhandlers) {
        mset->ipreport_handler = (corsaro_memhandler_t *)malloc(
                sizeof(corsaro_memhandler_t));
        mset->ip_handler = (corsaro_memhandler_t *)malloc(
                sizeof(corsaro_memhandler_t));
        mset->ipblock_handler = (corsaro_memhandler_t *)malloc(
                sizeof(corsaro_memhandler_t));
        init_corsaro_memhandler(logger, mset->ipreport_handler,
                sizeof(corsaro_report_ip_metric_t), 100000);
        init_corsaro_memhandler(logger, mset->ip_handler,
                sizeof(corsaro_report_ip_t), 50000);
        init_corsaro_memhandler(logger, mset->ipblock_handler,
                sizeof(corsaro_report_ipblock_t), 2000);
    }
    return mset;
}

void *corsaro_report_init_processing(corsaro_plugin_t *p, int threadid) {

    corsaro_report_state_t *state;

    state = (corsaro_report_state_t *)malloc(sizeof(corsaro_report_state_t));
    state->metrics = init_metric_set(p->logger, 1);
    return state;
}

static inline void destroy_ip_block(corsaro_report_ipblock_t *ipblock,
        corsaro_report_ipblock_t **ipblock_list,
        corsaro_metric_set_t *parent) {

    corsaro_report_ip_t *ip, *tmp;
    corsaro_report_ip_metric_t *ipmet, *tmp3;

    HASH_ITER(hh, ipblock->memberips, ip, tmp) {
        HASH_ITER(hh, ip->assocmetrics, ipmet, tmp3) {
            HASH_DELETE(hh, (ip->assocmetrics), ipmet);
            release_corsaro_memhandler_item(parent->ipreport_handler,
                    ipmet->source);
        }
        HASH_DELETE(hh, ipblock->memberips, ip);
        release_corsaro_memhandler_item(parent->ip_handler, ip->source);
    }

    HASH_DELETE(hh, *ipblock_list, ipblock);
    release_corsaro_memhandler_item(parent->ipblock_handler,
            ipblock->source);
}

static inline void destroy_metric_set(corsaro_metric_set_t *mset) {

    corsaro_report_ipblock_t *ipblock, *tmpblock;

    HASH_ITER(hh, mset->knownips, ipblock, tmpblock) {
        destroy_ip_block(ipblock, &(mset->knownips), mset);
    }

    destroy_corsaro_memhandler(mset->ipreport_handler);
    destroy_corsaro_memhandler(mset->ip_handler);
    destroy_corsaro_memhandler(mset->ipblock_handler);
}

int corsaro_report_halt_processing(corsaro_plugin_t *p, void *local) {

    corsaro_report_state_t *state;

    state = (corsaro_report_state_t *)local;

    if (state == NULL) {
        return 0;
    }
    destroy_metric_set(state->metrics);
    free(state->metrics);
    free(state);

    return 0;
}

char *corsaro_report_derive_output_name(corsaro_plugin_t *p,
        void *local, uint32_t timestamp, int threadid) {

    corsaro_report_config_t *conf;
    char *outname = NULL;

    conf = (corsaro_report_config_t *)(p->config);

    outname = corsaro_generate_avro_file_name(conf->basic.template, p->name,
            conf->basic.monitorid, timestamp, threadid);
    if (outname == NULL) {
        corsaro_log(p->logger,
                "failed to generate suitable filename for report output");
        return NULL;
    }

    return outname;
}

int corsaro_report_start_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_start) {
    return 0;
}

void *corsaro_report_end_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_end) {

    corsaro_report_config_t *conf;
    corsaro_report_state_t *state;
    corsaro_metric_set_t *mset;

    conf = (corsaro_report_config_t *)(p->config);
    state = (corsaro_report_state_t *)local;

    if (state == NULL) {
        corsaro_log(p->logger,
                "corsaro_report_end_interval: report thread-local state is NULL!");
        return NULL;
    }

    mset = state->metrics;
    state->metrics = init_metric_set(p->logger, 0);

    state->metrics->ipreport_handler = mset->ipreport_handler;
    state->metrics->ip_handler = mset->ip_handler;
    state->metrics->ipblock_handler = mset->ipblock_handler;
    add_corsaro_memhandler_user(mset->ipreport_handler);
    add_corsaro_memhandler_user(mset->ip_handler);
    add_corsaro_memhandler_user(mset->ipblock_handler);
    return mset;
}

static inline void update_metric(corsaro_metric_set_t *metrics,
        corsaro_report_metric_class_t metclass, uint32_t metval,
        corsaro_report_ip_t *srcip, corsaro_report_ip_t *dstip,
        uint16_t iplen, corsaro_report_state_t *state) {

    corsaro_report_metric_id_t lookup;
    corsaro_report_ip_metric_t *find;

    memset(&lookup, 0, sizeof(corsaro_report_metric_id_t));
    lookup.class = metclass;
    lookup.metricval = metval;

    HASH_FIND(hh, srcip->assocmetrics, &lookup,
            sizeof(corsaro_report_metric_id_t), find);
    if (!find) {
        corsaro_report_ip_metric_t *ipmet;
        corsaro_memsource_t *memsrc;

        ipmet = (corsaro_report_ip_metric_t *)
                get_corsaro_memhandler_item(
                        state->metrics->ipreport_handler,
                        &memsrc);

        memset(&ipmet->metid, 0, sizeof(corsaro_report_metric_id_t));
        ipmet->metid.class = metclass;
        ipmet->metid.metricval = metval;
        ipmet->source = memsrc;
        ipmet->pkt_cnt = 0;
        ipmet->ip_len = 0;
        ipmet->seenas = 0;

        HASH_ADD_KEYPTR(hh, srcip->assocmetrics, &(ipmet->metid),
                    sizeof(corsaro_report_metric_id_t), ipmet);
        find = ipmet;
    }

    find->pkt_cnt ++;
    find->ip_len += iplen;
    find->seenas |= CORSARO_REPORT_IPSEEN_SOURCE;

    HASH_FIND(hh, dstip->assocmetrics, &lookup,
            sizeof(corsaro_report_metric_id_t), find);
    if (!find) {
        corsaro_report_ip_metric_t *ipmet;
        corsaro_memsource_t *memsrc;

        ipmet = (corsaro_report_ip_metric_t *)
                get_corsaro_memhandler_item(
                        state->metrics->ipreport_handler,
                        &memsrc);
        memset(&ipmet->metid, 0, sizeof(corsaro_report_metric_id_t));
        ipmet->metid.class = metclass;
        ipmet->metid.metricval = metval;
        ipmet->source = memsrc;
        ipmet->pkt_cnt = 0;
        ipmet->ip_len = 0;
        ipmet->seenas = 0;

        HASH_ADD_KEYPTR(hh, dstip->assocmetrics, &(ipmet->metid),
                    sizeof(corsaro_report_metric_id_t), ipmet);
        find = ipmet;
    }
    /* DON'T increment pkt_cnt and ip_len here, otherwise our merge will
     * count everything twice! */
    find->seenas |= CORSARO_REPORT_IPSEEN_DEST;

}

static void update_basic_tag_metrics(corsaro_logger_t *logger,
        corsaro_metric_set_t *metrics, corsaro_packet_tags_t *tags,
        corsaro_report_ip_t *src, corsaro_report_ip_t *dst, uint16_t iplen,
        corsaro_report_state_t *state) {

    /* Sanity checks before incrementing */

    if (tags->protocol >= METRIC_IPPROTOS_MAX) {
        corsaro_log(logger, "Invalid IP protocol tag %u", tags->protocol);
        return;
    }

    if (tags->protocol == TRACE_IPPROTO_ICMP) {
        if (tags->src_port >= METRIC_ICMP_MAX) {
            corsaro_log(logger, "Invalid ICMP Type tag: %u", tags->src_port);
            return;
        }

        if (tags->dest_port >= METRIC_ICMP_MAX) {
            corsaro_log(logger, "Invalid ICMP Code tag: %u", tags->dest_port);
            return;
        }
        update_metric(metrics, CORSARO_METRIC_CLASS_ICMP_TYPE,
                tags->src_port, src, dst, iplen, state);
        update_metric(metrics, CORSARO_METRIC_CLASS_ICMP_CODE,
                tags->dest_port, src, dst, iplen, state);

    } else if (tags->protocol == TRACE_IPPROTO_TCP) {
        if (tags->src_port >= METRIC_PORT_MAX) {
            corsaro_log(logger, "Invalid TCP source port tag: %u",
                    tags->src_port);
            return;
        }

        if (tags->dest_port >= METRIC_PORT_MAX) {
            corsaro_log(logger, "Invalid TCP dest port tag: %u",
                    tags->dest_port);
            return;
        }
        update_metric(metrics, CORSARO_METRIC_CLASS_TCP_SOURCE_PORT,
                tags->src_port, src, dst, iplen, state);
        update_metric(metrics, CORSARO_METRIC_CLASS_TCP_DEST_PORT,
                tags->dest_port, src, dst, iplen, state);
    } else if (tags->protocol == TRACE_IPPROTO_UDP) {

        if (tags->src_port >= METRIC_PORT_MAX) {
            corsaro_log(logger, "Invalid UDP source port tag: %u",
                    tags->src_port);
            return;
        }

        if (tags->dest_port >= METRIC_PORT_MAX) {
            corsaro_log(logger, "Invalid UDP dest port tag: %u",
                    tags->dest_port);
            return;
        }

        update_metric(metrics, CORSARO_METRIC_CLASS_UDP_SOURCE_PORT,
                tags->src_port, src, dst, iplen, state);
        update_metric(metrics, CORSARO_METRIC_CLASS_UDP_DEST_PORT,
                tags->dest_port, src, dst, iplen, state);
    }

    update_metric(metrics, CORSARO_METRIC_CLASS_COMBINED, 0, src, dst,
            iplen, state);
    update_metric(metrics, CORSARO_METRIC_CLASS_IP_PROTOCOL, tags->protocol,
            src, dst, iplen, state);

}

static void update_maxmind_tag_metrics(corsaro_logger_t *logger,
        corsaro_metric_set_t *metrics, corsaro_packet_tags_t *tags,
        corsaro_report_ip_t *srcaddr, corsaro_report_ip_t *dstaddr,
        uint16_t iplen, corsaro_report_state_t *state) {

    update_metric(metrics, CORSARO_METRIC_CLASS_MAXMIND_CONTINENT,
            tags->maxmind_continent, srcaddr, dstaddr, iplen, state);
    update_metric(metrics, CORSARO_METRIC_CLASS_MAXMIND_COUNTRY,
            tags->maxmind_country, srcaddr, dstaddr, iplen, state);

}

static inline int extract_addresses(libtrace_packet_t *packet,
        uint32_t *srcaddr, uint32_t *dstaddr, uint16_t *iplen) {

    libtrace_ip_t *ip;
    void *l3;
    uint16_t ethertype;
    uint32_t rem;

    l3 = trace_get_layer3(packet, &ethertype, &rem);

    if (l3 == NULL || rem == 0) {
        return -1;
    }

    if (ethertype != TRACE_ETHERTYPE_IP) {
        return -1;
    }

    if (rem < sizeof(libtrace_ip_t)) {
        return -1;
    }
    ip = (libtrace_ip_t *)l3;

    *srcaddr = ip->ip_src.s_addr;
    *dstaddr = ip->ip_dst.s_addr;
    *iplen = ntohs(ip->ip_len);
    return 0;
}

static inline int basic_tagged(corsaro_packet_tags_t *tags) {
    if (tags->providers_used & 0x01) {
        return 1;
    }
    return 0;
}

static inline int maxmind_tagged(corsaro_packet_tags_t *tags) {
    if (tags->providers_used & (1 << IPMETA_PROVIDER_MAXMIND)) {
        return 1;
    }
    return 0;
}

int corsaro_report_process_packet(corsaro_plugin_t *p, void *local,
        libtrace_packet_t *packet, corsaro_packet_tags_t *tags) {

    corsaro_report_state_t *state;
    uint16_t iplen;
    uint32_t srcaddr, dstaddr;
    uint32_t srcblock, dstblock;
    corsaro_report_ip_t *srcip, *destip;
    corsaro_report_ipblock_t *ipb;
    corsaro_memsource_t *memsrc;

    state = (corsaro_report_state_t *)local;

    if (state == NULL) {
        corsaro_log(p->logger,
                "corsaro_report_process_packet: report thread-local state is NULL!");
        return -1;
    }

    if (!tags || tags->providers_used == 0) {
        /* Unable to tag packet at all, just skip it */
        return 0;
    }

    if (extract_addresses(packet, &srcaddr, &dstaddr, &iplen) != 0) {
        return 0;
    }


    srcblock = srcaddr & (0x0000ffff);
    dstblock = dstaddr & (0x0000ffff);

    HASH_FIND(hh, state->metrics->knownips, &srcblock, sizeof(srcblock), ipb);
    if (ipb == NULL) {
        ipb = (corsaro_report_ipblock_t *)
                get_corsaro_memhandler_item(state->metrics->ipblock_handler,
                        &memsrc);
        ipb->blockid = srcblock;
        ipb->memberips = NULL;
        ipb->source = memsrc;
        HASH_ADD_KEYPTR(hh, state->metrics->knownips, &(ipb->blockid),
                sizeof(ipb->blockid), ipb);
    }


    HASH_FIND(hh, ipb->memberips, &srcaddr, sizeof(uint32_t), srcip);
    if (srcip == NULL) {
        srcip = (corsaro_report_ip_t *)
                get_corsaro_memhandler_item(state->metrics->ip_handler,
                        &memsrc);
        srcip->ipaddr = srcaddr;
        srcip->assocmetrics = NULL;
        srcip->source = memsrc;

        HASH_ADD_KEYPTR(hh, ipb->memberips, &(srcip->ipaddr),
                sizeof(uint32_t), srcip);
    }

    ipb = NULL;
    HASH_FIND(hh, state->metrics->knownips, &dstblock, sizeof(dstblock), ipb);
    if (ipb == NULL) {
        ipb = (corsaro_report_ipblock_t *)
                get_corsaro_memhandler_item(state->metrics->ipblock_handler,
                        &memsrc);
        ipb->blockid = dstblock;
        ipb->memberips = NULL;
        ipb->source = memsrc;
        HASH_ADD_KEYPTR(hh, state->metrics->knownips, &(ipb->blockid),
                sizeof(ipb->blockid), ipb);
    }

    HASH_FIND(hh, ipb->memberips, &dstaddr, sizeof(uint32_t), destip);
    if (destip == NULL) {
        destip = (corsaro_report_ip_t *)
                get_corsaro_memhandler_item(state->metrics->ip_handler,
                        &memsrc);
        destip->ipaddr = dstaddr;
        destip->assocmetrics = NULL;
        destip->source = memsrc;
        HASH_ADD_KEYPTR(hh, ipb->memberips, &(destip->ipaddr),
                sizeof(uint32_t), destip);
    }

    if (basic_tagged(tags)) {
        update_basic_tag_metrics(p->logger, state->metrics, tags, srcip,
                destip, iplen, state);
    }

    /*
    if (maxmind_tagged(tags)) {
        update_maxmind_tag_metrics(p->logger, state->metrics, tags, srcip,
                destip, iplen, state);
    }
    */

    return 0;
}

/** ------------- MERGING API -------------------- */
static inline void free_uniq_ip_map(corsaro_report_uniq_ip_t **uniqmap) {
    corsaro_report_uniq_ip_t *uniq, *tmpuniq;

    HASH_ITER(hh, *uniqmap, uniq, tmpuniq) {
        HASH_DELETE(hh, *uniqmap, uniq);
        release_corsaro_memhandler_item(uniq->handler, uniq->source);
    }
}


void count_ips_per_metric(corsaro_report_interim_merge_result_t **res,
        corsaro_report_ipblock_t *block, corsaro_metric_set_t *parent,
        uint8_t jobtype, corsaro_memhandler_t *res_handler,
        corsaro_memhandler_t *ip_handler) {

    corsaro_report_ip_t *ip, *tmp;
    corsaro_report_ip_metric_t *ipmet, *tmpmet;
    corsaro_report_interim_merge_result_t *r;
    corsaro_memsource_t *memsrc;
    corsaro_report_uniq_ip_t *existingip, *uniq;

    HASH_ITER(hh, block->memberips, ip, tmp) {
        HASH_DELETE(hh, block->memberips, ip);
        HASH_ITER(hh, ip->assocmetrics, ipmet, tmpmet) {
            HASH_DELETE(hh, ip->assocmetrics, ipmet);
            HASH_FIND(hh, *res, &(ipmet->metid),
                    sizeof(corsaro_report_metric_id_t), r);

            if (!r) {
                r = (corsaro_report_interim_merge_result_t *)
                        get_corsaro_memhandler_item(res_handler, &memsrc);
                memset(&(r->metid), 0, sizeof(corsaro_report_metric_id_t));

                r->metid.class = ipmet->metid.class;
                r->metid.metricval = ipmet->metid.metricval;

                r->pkt_cnt = 0;
                r->ip_len = 0;
                r->uniq_src_map = NULL;
                r->uniq_dst_map = NULL;

                r->memsource = memsrc;
                r->handler = res_handler;

                HASH_ADD_KEYPTR(hh, *res, &(r->metid),
                        sizeof(corsaro_report_metric_id_t), r);
            }

            if (ipmet->seenas & CORSARO_REPORT_IPSEEN_SOURCE) {
                HASH_FIND(hh, r->uniq_src_map, &(ip->ipaddr),
                        sizeof(ip->ipaddr), existingip);
                if (!existingip) {
                    uniq = (corsaro_report_uniq_ip_t *)
                            get_corsaro_memhandler_item(ip_handler, &memsrc);
                    uniq->ipaddr = ip->ipaddr;
                    uniq->handler = ip_handler;
                    uniq->source = memsrc;

                    HASH_ADD_KEYPTR(hh, r->uniq_src_map, &(uniq->ipaddr),
                            sizeof(uniq->ipaddr), uniq);
                }
            }

            if (ipmet->seenas & CORSARO_REPORT_IPSEEN_DEST) {
                HASH_FIND(hh, r->uniq_dst_map, &(ip->ipaddr),
                        sizeof(ip->ipaddr), existingip);
                if (!existingip) {
                    uniq = (corsaro_report_uniq_ip_t *)
                            get_corsaro_memhandler_item(ip_handler, &memsrc);
                    uniq->ipaddr = ip->ipaddr;
                    uniq->handler = ip_handler;
                    uniq->source = memsrc;

                    HASH_ADD_KEYPTR(hh, r->uniq_dst_map, &(uniq->ipaddr),
                            sizeof(uniq->ipaddr), uniq);
                }
            }

            r->pkt_cnt += ipmet->pkt_cnt;
            r->ip_len += ipmet->ip_len;

            release_corsaro_memhandler_item(parent->ipreport_handler,
                    ipmet->source);
        }
        release_corsaro_memhandler_item(parent->ip_handler, ip->source);
    }

    //release_corsaro_memhandler_item(parent->ipblock_handler, block->source);

}

void *start_merge_worker(void *tdata) {

    corsaro_report_worker_t *workstate = (corsaro_report_worker_t *)tdata;
    corsaro_report_merge_job_t nextjob;
    corsaro_report_merge_result_t res;
    corsaro_report_interim_merge_result_t *interims = NULL;
    corsaro_report_interim_merge_result_t *intres, *inttmp;
    int i;

    while (1) {
        if (libtrace_message_queue_try_get(&(workstate->jobqueue), &nextjob)
                == LIBTRACE_MQ_FAILED) {
            usleep(100);
            continue;
        }

        if (nextjob.jobtype == CORSARO_REPORT_MERGE_JOB_HALT) {
            break;
        }

        if (nextjob.jobtype == CORSARO_REPORT_MERGE_JOB_REFLECT) {
            memset(&res, 0, sizeof(res));
            libtrace_message_queue_put(&(workstate->resultqueue),
                    (void *)(&res));
            continue;
        }


        for (i = 0; i < nextjob.blockcount; i++) {
            count_ips_per_metric(&(interims), nextjob.ipblocks[i],
                    nextjob.parents[i], nextjob.jobtype,
                    workstate->intres_handler, workstate->ip_handler);
            if (i > 0) {
                release_corsaro_memhandler_item(
                        nextjob.parents[i]->ipblock_handler,
                        nextjob.ipblocks[i]->source);
            }
        }

        if (interims == NULL) {
            continue;
        }

        memset(&res, 0, sizeof(res));
        res.res = NULL;
        HASH_ITER(hh, interims, intres, inttmp) {
            corsaro_report_result_t *singleres;
            corsaro_memsource_t *memsrc;

            HASH_DELETE(hh, interims, intres);
            HASH_FIND(hh, res.res, &(intres->metid),
                    sizeof(intres->metid), singleres);

            if (!singleres) {
                singleres = (corsaro_report_result_t *)
                        get_corsaro_memhandler_item(workstate->res_handler,
                                &memsrc);
            


                memset(singleres, 0, sizeof(corsaro_report_result_t));
                singleres->metid.class = intres->metid.class;
                singleres->metid.metricval = intres->metid.metricval;
                singleres->pkt_cnt = intres->pkt_cnt;
                singleres->ip_len = intres->ip_len;
                singleres->uniq_src_ips = HASH_CNT(hh, intres->uniq_src_map);
                singleres->uniq_dst_ips = HASH_CNT(hh, intres->uniq_dst_map);
                singleres->attimestamp = 0;
                singleres->label = NULL;
                singleres->metrictype = NULL;
                singleres->metricval = NULL;
                singleres->handler = workstate->res_handler;
                singleres->memsource = memsrc;

                HASH_ADD_KEYPTR(hh, res.res, &(singleres->metid),
                            sizeof(singleres->metid), singleres);
            } else {
                assert(0);
            }

            free_uniq_ip_map(&(intres->uniq_src_map));
            free_uniq_ip_map(&(intres->uniq_dst_map));
            release_corsaro_memhandler_item(intres->handler, intres->memsource);

        }
        libtrace_message_queue_put(&(workstate->resultqueue),
                (void *)(&res));

        free(nextjob.ipblocks);
        free(nextjob.parents);
    }

    pthread_exit(NULL);
}

void *corsaro_report_init_merging(corsaro_plugin_t *p, int sources) {

    corsaro_report_merge_state_t *m;
    int i;
#ifdef __linux__
    struct epoll_event ev;
#else
    struct kevent ev;
#endif

    m = (corsaro_report_merge_state_t *)calloc(1,
            sizeof(corsaro_report_merge_state_t));
    if (m == NULL) {
        corsaro_log(p->logger,
                "corsaro_report_init_merging: out of memory while allocating merge state.");
        return NULL;
    }

    m->writer = corsaro_create_avro_writer(p->logger, REPORT_RESULT_SCHEMA);
    if (m->writer == NULL) {
        corsaro_log(p->logger,
                "error while creating avro writer for report plugin!");
        free(m);
        return NULL;
    }

#ifdef __linux__
    m->epoll_fd = epoll_create1(0);
#else
    m->kqueue_fd = kqueue();
#endif

    m->workerthreadcount = 4;
    m->workthreads = (corsaro_report_worker_t *)calloc(m->workerthreadcount,
            sizeof(corsaro_report_worker_t));

    for (i = 0; i < m->workerthreadcount; i++) {
        m->workthreads[i].tnum = i;
        libtrace_message_queue_init(&(m->workthreads[i].jobqueue),
                sizeof(corsaro_report_merge_job_t));
        libtrace_message_queue_init(&(m->workthreads[i].resultqueue),
                sizeof(corsaro_report_merge_result_t));

#ifdef __linux__
        ev.events = EPOLLIN | EPOLLRDHUP;
        ev.data.ptr = &(m->workthreads[i]);

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD,
                    libtrace_message_queue_get_fd(&(m->workthreads[i].resultqueue)),
                    &ev) != 0) {
            corsaro_log(p->logger, "Error configuring epoll for merging worker thread in report plugin: %s", strerror(errno));
            /* TODO throw some sort of error? */
        }
#else
        EV_SET(&ev, libtrace_message_queue_get_fd(&(m->workthreads[i].resultqueue)), EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, &(m->workthreads[i]));
        if (kevent(m->kqueue_fd, &ev, 1, NULL, 0, NULL) == -1) {
            corsaro_log(p->logger, "Error configuring kqueue for merging worker thread in report plugin: %s", strerror(errno));
            /* TODO throw some sort of error? */
        }
#endif

        m->workthreads[i].intres_handler = (corsaro_memhandler_t *)malloc(
                sizeof(corsaro_memhandler_t));
        init_corsaro_memhandler(p->logger, m->workthreads[i].intres_handler,
                sizeof(corsaro_report_interim_merge_result_t), 30000);
        m->workthreads[i].res_handler = (corsaro_memhandler_t *)malloc(
                sizeof(corsaro_memhandler_t));
        init_corsaro_memhandler(p->logger, m->workthreads[i].res_handler,
                sizeof(corsaro_report_result_t), 20000);
        m->workthreads[i].ip_handler = (corsaro_memhandler_t *)malloc(
                sizeof(corsaro_memhandler_t));
        init_corsaro_memhandler(p->logger, m->workthreads[i].ip_handler,
                sizeof(corsaro_report_uniq_ip_t), 50000);

        pthread_create(&(m->workthreads[i].threadid), NULL,
                start_merge_worker, &(m->workthreads[i]));
    }

    return m;
}

int corsaro_report_halt_merging(corsaro_plugin_t *p, void *local) {
    corsaro_report_merge_state_t *m;
    corsaro_report_merge_job_t endjob;
    int i;

    m = (corsaro_report_merge_state_t *)local;
    if (m == NULL) {
        return 0;
    }

    memset(&endjob, 0, sizeof(corsaro_report_merge_job_t));
    endjob.jobtype = CORSARO_REPORT_MERGE_JOB_HALT;
    endjob.ipblocks = NULL;
    endjob.blockcount = 0;


    for (i = 0; i < m->workerthreadcount; i++) {
        libtrace_message_queue_put(&(m->workthreads[i].jobqueue), &endjob);
    }

    for (i = 0; i < m->workerthreadcount; i++) {
        pthread_join(m->workthreads[i].threadid, NULL);
        destroy_corsaro_memhandler(m->workthreads[i].intres_handler);
        destroy_corsaro_memhandler(m->workthreads[i].res_handler);
        destroy_corsaro_memhandler(m->workthreads[i].ip_handler);
        libtrace_message_queue_destroy(&(m->workthreads[i].jobqueue));
        libtrace_message_queue_destroy(&(m->workthreads[i].resultqueue));
    }

    if (m->workthreads) {
        free(m->workthreads);
    }
#ifdef __linux__
    close(m->epoll_fd);
#else
    close(m->kqueue_fd);
#endif

    if (m->writer) {
        corsaro_destroy_avro_writer(m->writer);
    }
    free(m);
    return 0;
}

static inline int report_do_avro_write(corsaro_logger_t *logger,
        corsaro_avro_writer_t *writer, corsaro_report_result_t *res) {

    avro_value_t *avro;

    avro = corsaro_populate_avro_item(writer, res, report_result_to_avro);
    if (avro == NULL) {
        corsaro_log(logger,
                "could not convert report result to Avro record");
        return -1;
    }

    if (corsaro_append_avro_writer(writer, avro) < 0) {
        corsaro_log(logger,
                "could not write report result to Avro output file");
        return -1;
    }
    return 0;
}

static int write_single_metric(corsaro_logger_t *logger,
        corsaro_avro_writer_t *writer, corsaro_report_result_t *res) {

    corsaro_report_metric_id_t *metricid = &(res->metid);
    char valspace[2048];

    switch(metricid->class) {
        case CORSARO_METRIC_CLASS_COMBINED:
            res->metrictype = "combined";
            res->metricval = "all";
            break;
        case CORSARO_METRIC_CLASS_IP_PROTOCOL:
            res->metrictype = "ipprotocol";
            snprintf(valspace, 2048, "%u", metricid->metricval);
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_ICMP_CODE:
            res->metrictype = "icmp-code";
            snprintf(valspace, 2048, "%u", metricid->metricval);
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_ICMP_TYPE:
            res->metrictype = "icmp-type";
            snprintf(valspace, 2048, "%u", metricid->metricval);
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_TCP_SOURCE_PORT:
            res->metrictype = "tcpsourceport";
            snprintf(valspace, 2048, "%u", metricid->metricval);
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_TCP_DEST_PORT:
            res->metrictype = "tcpdestport";
            snprintf(valspace, 2048, "%u", metricid->metricval);
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_UDP_SOURCE_PORT:
            res->metrictype = "udpsourceport";
            snprintf(valspace, 2048, "%u", metricid->metricval);
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_UDP_DEST_PORT:
            res->metrictype = "udpdestport";
            snprintf(valspace, 2048, "%u", metricid->metricval);
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_MAXMIND_CONTINENT:
            res->metrictype = "maxmind-continent";
            snprintf(valspace, 2048, "%c%c", metricid->metricval & 0xff,
                    (metricid->metricval >> 8) & 0xff);
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_MAXMIND_COUNTRY:
            res->metrictype = "maxmind-country";
            snprintf(valspace, 2048, "%c%c", metricid->metricval & 0xff,
                    (metricid->metricval >> 8) & 0xff);
            res->metricval = valspace;
            break;
    }

    if (report_do_avro_write(logger, writer, res) == -1) {
        return -1;
    }
    return 0;

}

static int write_all_metrics(corsaro_logger_t *logger,
        corsaro_avro_writer_t *writer, corsaro_report_result_t **resultmap) {

    corsaro_report_result_t *r, *tmpres;

    HASH_ITER(hh, *resultmap, r, tmpres) {
        write_single_metric(logger, writer, r);
        HASH_DELETE(hh, *resultmap, r);

        free(r);
    }

    return 0;

}

int create_merge_jobs(corsaro_metric_set_t **msets, int threadindex,
        corsaro_report_worker_t *workthreads, int workthreadcount,
        int sourcethreads, corsaro_report_ipblock_t **ipb,
        int jobsperworker) {

    int i;
    int jobcount = 0, blockcount = 0;
    int nextworker = 0;
    corsaro_report_merge_job_t job;
    corsaro_report_ipblock_t *match, *tmp;

    if (*ipb == NULL) {
        *ipb = msets[threadindex]->knownips;
    }

    for (*ipb; *ipb != NULL; *ipb=(*ipb)->hh.next) {
        if (blockcount >= workthreadcount * jobsperworker) {
            break;
        }

        memset(&job, 0, sizeof(job));
        job.ipblocks = (corsaro_report_ipblock_t **)calloc(sourcethreads,
                sizeof(corsaro_report_ipblock_t *));
        job.parents = (corsaro_metric_set_t **)calloc(sourcethreads,
                sizeof(corsaro_report_ipblock_t *));


        job.ipblocks[0] = *ipb;
        job.parents[0] = msets[threadindex];
        job.jobtype = CORSARO_REPORT_MERGE_JOB;

        job.blockcount = 1;
        for (i = threadindex + 1; i < sourcethreads; i++) {
            HASH_FIND(hh, msets[i]->knownips, &((*ipb)->blockid),
                    sizeof((*ipb)->blockid), match);

            if (!match) {
                continue;
            }
            job.ipblocks[job.blockcount] = match;
            job.parents[job.blockcount] = msets[i];
            job.blockcount ++;

            HASH_DELETE(hh, msets[i]->knownips, match);
        }

        libtrace_message_queue_put(&(workthreads[nextworker].jobqueue),
                (void *)(&job));
        jobcount += job.blockcount;
        blockcount ++;
        nextworker ++;
        if (nextworker == workthreadcount) {
            nextworker = 0;
        }
    }

    if (*ipb == NULL) {
        HASH_ITER(hh, msets[threadindex]->knownips, match, tmp) {
            HASH_DELETE(hh, msets[threadindex]->knownips, match);
            release_corsaro_memhandler_item(msets[threadindex]->ipblock_handler,
                        match->source);
        }
    }

    return blockcount;
}

void update_merge_result(corsaro_report_result_t **combined,
        corsaro_report_merge_result_t *rlist, uint32_t ts,
        corsaro_report_config_t *conf) {

    corsaro_report_result_t *found, *iter, *tmp;

    HASH_ITER(hh, rlist->res, iter, tmp) {
        HASH_DELETE(hh, rlist->res, iter);

        HASH_FIND(hh, *combined, &(iter->metid),
                sizeof(corsaro_report_metric_id_t), found);

        if (!found) {
            found = (corsaro_report_result_t *)malloc(sizeof(corsaro_report_result_t));
            memcpy(found, iter, sizeof(corsaro_report_result_t));
            found->attimestamp = ts;
            found->label = conf->outlabel;
            HASH_ADD_KEYPTR(hh, *combined, &(found->metid),
                        sizeof(corsaro_report_metric_id_t), found);

        } else {
            found->pkt_cnt += iter->pkt_cnt;
            found->ip_len += iter->ip_len;
            found->uniq_src_ips += iter->uniq_src_ips;
            found->uniq_dst_ips += iter->uniq_dst_ips;
        }

        release_corsaro_memhandler_item(iter->handler, iter->memsource);
    }

}

int corsaro_report_merge_interval_results(corsaro_plugin_t *p, void *local,
        void **tomerge, corsaro_fin_interval_t *fin) {

    corsaro_metric_set_t *next;
    corsaro_report_merge_state_t *m;
    corsaro_report_result_t *combined = NULL;
    corsaro_report_merge_result_t res;
    int i, ret;
    char *outname;
    int threadindex, alljobssent;
    corsaro_report_ipblock_t *iter;
    int reflectsreceived;
    corsaro_report_merge_job_t reflectjob;

#ifdef __linux__
    struct epoll_event events[64];
#else
    struct kevent events[64];
    struct timespec timeout;
#endif

    m = (corsaro_report_merge_state_t *)local;
    if (m == NULL) {
        return -1;
    }

    threadindex = 0;
    iter = NULL;
    alljobssent = 0;
    reflectsreceived = 0;


    while (reflectsreceived < fin->threads_ended) {
#ifdef __linux__
        ret = epoll_wait(m->epoll_fd, events, 64, 10);

        for (i = 0; i < ret; i++) {
            corsaro_report_worker_t *wkr = (corsaro_report_worker_t *)
                    (events[i].data.ptr);
            if (libtrace_message_queue_try_get(&(wkr->resultqueue), &res) ==
                        LIBTRACE_MQ_FAILED) {
                continue;
            }

            if (res.res != NULL) {
                update_merge_result(&combined, &res, fin->timestamp,
                        (corsaro_report_config_t *)(p->config));
            } else {
                reflectsreceived ++;
            }
        }
#else
        timeout.tv_sec = 0;
        timeout.tv_nsec = 10000000;

        ret = kevent(m->kqueue_fd, NULL, 0, events, 64, &timeout);

        for (i = 0; i < ret; i++) {
            corsaro_report_worker_t *wkr = (corsaro_report_worker_t *)
                    (events[i].udata);

            while (libtrace_message_queue_try_get(&(wkr->resultqueue), &res) !=
                        LIBTRACE_MQ_FAILED) {
                if (res.res != NULL) {
                    update_merge_result(&combined, &res, fin->timestamp,
                            (corsaro_report_config_t *)(p->config));
                } else {
                    reflectsreceived ++;
                    break;
                }
            }
        }
#endif

        if (ret != 0 || alljobssent) {
            continue;
        }

        ret = create_merge_jobs((corsaro_metric_set_t **)(tomerge),
                threadindex, m->workthreads, m->workerthreadcount,
                fin->threads_ended, &iter, 100);
        if (iter == NULL) {
            threadindex ++;
        }

        if (threadindex >= fin->threads_ended) {
            memset(&reflectjob, 0, sizeof(corsaro_report_merge_job_t));
            reflectjob.jobtype = CORSARO_REPORT_MERGE_JOB_REFLECT;
            reflectjob.ipblocks = NULL;
            reflectjob.blockcount = 0;

            alljobssent = 1;
            for (i = 0; i < m->workerthreadcount; i++) {
                libtrace_message_queue_put(&(m->workthreads[i].jobqueue),
                        &reflectjob);
            }
            printf("sent reflects...\n");

        }

    }

    for (i = 0; i < fin->threads_ended; i++) {
        next = (corsaro_metric_set_t *)(tomerge[i]);
        destroy_metric_set(next);
        free(next);

    }

    /* Open an output file if we need one */
    if (!corsaro_is_avro_writer_active(m->writer)) {
        outname = p->derive_output_name(p, local, fin->timestamp, -1);
        if (outname == NULL) {
            return -1;
        }
        if (corsaro_start_avro_writer(m->writer, outname) == -1) {
            free(outname);
            return -1;
        }
        free(outname);
    }

    ret = 0;
    if (write_all_metrics(p->logger, m->writer, &combined) < 0) {
        ret = -1;
    }

    return ret;
}

int corsaro_report_rotate_output(corsaro_plugin_t *p, void *local) {

    corsaro_report_merge_state_t *m;

    m = (corsaro_report_merge_state_t *)local;
    if (m == NULL) {
        return -1;
    }

    if (m->writer == NULL || corsaro_close_avro_writer(m->writer) < 0) {
        return -1;
    }
    return 0;
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
