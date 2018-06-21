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

#include <uthash.h>
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

typedef struct report_metric_identifier {
    corsaro_report_metric_class_t class;
    uint32_t metricval;
} corsaro_report_metric_id_t;

typedef struct metric_per_ip {
    corsaro_report_metric_id_t metid;
    corsaro_memsource_t *source;
    UT_hash_handle hh;
} corsaro_report_ip_metric_t;

typedef struct report_metric {
    corsaro_report_metric_id_t metid;
    uint64_t pkt_cnt;
    uint64_t ip_len;
    UT_hash_handle hh;
} corsaro_report_metric_t;

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

    UT_hash_handle hh;

} corsaro_report_result_t;

typedef struct known_ip {
    uint32_t ipaddr;
    corsaro_report_ip_metric_t *assocmetrics;
    corsaro_memsource_t *source;
    UT_hash_handle hh;
} corsaro_report_ip_t;

typedef struct metric_set {
    corsaro_report_metric_t *activemetrics;
    corsaro_report_ip_t *srcips;
    corsaro_report_ip_t *destips;
    corsaro_memhandler_t *ipreport_handler;
    corsaro_memhandler_t *ip_handler;
} corsaro_metric_set_t;


typedef struct report_state {
    corsaro_metric_set_t *metrics;
} corsaro_report_state_t;


typedef struct report_merge_state {
    corsaro_avro_writer_t *writer;
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
        free(p->config);
    }
    p->config = NULL;
}

static inline void init_metric_set(corsaro_metric_set_t *mset,
            corsaro_logger_t *logger) {

    mset->srcips = NULL;
    mset->destips = NULL;
    mset->activemetrics = NULL;
}

void *corsaro_report_init_processing(corsaro_plugin_t *p, int threadid) {

    corsaro_report_state_t *state;

    state = (corsaro_report_state_t *)malloc(sizeof(corsaro_report_state_t));
    state->metrics = (corsaro_metric_set_t *)malloc(
            sizeof(corsaro_metric_set_t));

    init_metric_set(state->metrics, p->logger);
    state->metrics->ipreport_handler = (corsaro_memhandler_t *)malloc(
            sizeof(corsaro_memhandler_t));
    state->metrics->ip_handler = (corsaro_memhandler_t *)malloc(
            sizeof(corsaro_memhandler_t));
    init_corsaro_memhandler(p->logger, state->metrics->ipreport_handler,
            sizeof(corsaro_report_ip_metric_t), 1000);
    init_corsaro_memhandler(p->logger, state->metrics->ip_handler,
            sizeof(corsaro_report_ip_t), 5000);
    return state;
}

static inline void destroy_metric_set(corsaro_metric_set_t *mset) {

    corsaro_report_ip_t *ip, *tmp;
    corsaro_report_metric_t *met, *tmp2;
    corsaro_report_ip_metric_t *ipmet, *tmp3;

    HASH_ITER(hh, mset->srcips, ip, tmp) {
        HASH_ITER(hh, ip->assocmetrics, ipmet, tmp3) {
            HASH_DELETE(hh, (ip->assocmetrics), ipmet);
            release_corsaro_memhandler_item(mset->ipreport_handler,
                    ipmet->source);
        }
        HASH_DELETE(hh, mset->srcips, ip);
        release_corsaro_memhandler_item(mset->ip_handler, ip->source);
    }

    HASH_ITER(hh, mset->destips, ip, tmp) {
        HASH_ITER(hh, ip->assocmetrics, ipmet, tmp3) {
            HASH_DELETE(hh, ip->assocmetrics, ipmet);
            release_corsaro_memhandler_item(mset->ipreport_handler,
                    ipmet->source);
        }
        HASH_DELETE(hh, mset->destips, ip);
        release_corsaro_memhandler_item(mset->ip_handler, ip->source);
    }

    HASH_ITER(hh, mset->activemetrics, met, tmp2) {
        HASH_DELETE(hh, mset->activemetrics, met);
        free(met);
    }

    destroy_corsaro_memhandler(mset->ipreport_handler);
    destroy_corsaro_memhandler(mset->ip_handler);

}

int corsaro_report_halt_processing(corsaro_plugin_t *p, void *local) {

    corsaro_report_state_t *state;
    state = (corsaro_report_state_t *)local;

    if (state == NULL) {
        return 0;
    }
    destroy_metric_set(state->metrics);
    destroy_corsaro_memhandler(state->metrics->ipreport_handler);
    destroy_corsaro_memhandler(state->metrics->ip_handler);
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
    state->metrics = (corsaro_metric_set_t *)malloc(
            sizeof(corsaro_metric_set_t));

    init_metric_set(state->metrics, p->logger);
    state->metrics->ipreport_handler = mset->ipreport_handler;
    state->metrics->ip_handler = mset->ip_handler;
    add_corsaro_memhandler_user(mset->ipreport_handler);
    add_corsaro_memhandler_user(mset->ip_handler);
    return mset;
}

static inline void update_metric(corsaro_metric_set_t *metrics,
        corsaro_report_metric_class_t metclass, uint32_t metval,
        corsaro_report_ip_t *srcip, corsaro_report_ip_t *dstip,
        uint16_t iplen, corsaro_report_state_t *state) {

    corsaro_report_metric_id_t lookup;
    corsaro_report_metric_t *metdata;
    corsaro_report_ip_metric_t *find;

    memset(&lookup, 0, sizeof(corsaro_report_metric_id_t));
    lookup.class = metclass;
    lookup.metricval = metval;

    HASH_FIND(hh, metrics->activemetrics, &lookup,
            sizeof(corsaro_report_metric_id_t), metdata);
    if (metdata == NULL) {
        metdata = (corsaro_report_metric_t *)malloc(
                sizeof(corsaro_report_metric_t));
        memset(&metdata->metid, 0, sizeof(corsaro_report_metric_id_t));
        metdata->metid.class = metclass;
        metdata->metid.metricval = metval;
        metdata->pkt_cnt = 0;
        metdata->ip_len = 0;

        HASH_ADD_KEYPTR(hh, metrics->activemetrics, &(metdata->metid),
                sizeof(corsaro_report_metric_id_t), metdata);
    }

    metdata->pkt_cnt ++;
    metdata->ip_len += iplen;

    HASH_FIND(hh, srcip->assocmetrics, &(metdata->metid),
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

        HASH_ADD_KEYPTR(hh, srcip->assocmetrics, &(ipmet->metid),
                    sizeof(corsaro_report_metric_id_t), ipmet);
    }

    HASH_FIND(hh, dstip->assocmetrics, &(metdata->metid),
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

        HASH_ADD_KEYPTR(hh, dstip->assocmetrics, &(ipmet->metid),
                    sizeof(corsaro_report_metric_id_t), ipmet);
    }

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
        uint32_t srcaddr, uint32_t dstaddr, uint16_t iplen,
        corsaro_report_state_t *state) {

/*
    update_metric(metrics->maxmind_continents, tags->maxmind_continent,
            srcaddr, dstaddr, iplen, state);
    update_metric(metrics->maxmind_countries, tags->maxmind_country,
            srcaddr, dstaddr, iplen, state);
*/

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
    corsaro_report_ip_t *srcip, *destip;

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


    HASH_FIND(hh, state->metrics->srcips, &srcaddr, sizeof(uint32_t), srcip);
    if (srcip == NULL) {
        corsaro_memsource_t *memsrc;

        srcip = (corsaro_report_ip_t *)
                get_corsaro_memhandler_item(state->metrics->ip_handler,
                        &memsrc);
        srcip->ipaddr = srcaddr;
        srcip->assocmetrics = NULL;
        srcip->source = memsrc;
        HASH_ADD_KEYPTR(hh, state->metrics->srcips, &(srcip->ipaddr),
                sizeof(uint32_t), srcip);
    }

    HASH_FIND(hh, state->metrics->destips, &dstaddr, sizeof(uint32_t), destip);
    if (destip == NULL) {
        corsaro_memsource_t *memsrc;
        destip = (corsaro_report_ip_t *)
                get_corsaro_memhandler_item(state->metrics->ip_handler,
                        &memsrc);
        destip->ipaddr = dstaddr;
        destip->assocmetrics = NULL;
        destip->source = memsrc;
        HASH_ADD_KEYPTR(hh, state->metrics->destips, &(destip->ipaddr),
                sizeof(uint32_t), destip);
    }

    if (basic_tagged(tags)) {
        update_basic_tag_metrics(p->logger, state->metrics, tags, srcip,
                destip, iplen, state);
    }

/*
    if (maxmind_tagged(tags)) {
        update_maxmind_tag_metrics(p->logger, state->metrics, tags, srcaddr,
                dstaddr, iplen, state);
    }
*/
    return 0;
}

/** ------------- MERGING API -------------------- */

void *corsaro_report_init_merging(corsaro_plugin_t *p, int sources) {

    corsaro_report_merge_state_t *m;
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

    return m;
}

int corsaro_report_halt_merging(corsaro_plugin_t *p, void *local) {
    corsaro_report_merge_state_t *m;

    m = (corsaro_report_merge_state_t *)local;
    if (m == NULL) {
        return 0;
    }

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

static void tally_ip_counters(corsaro_report_result_t *rmap,
        corsaro_report_ip_t *source_ips, corsaro_report_ip_t *dest_ips) {

    corsaro_report_result_t *r;
    corsaro_report_ip_t *ip, *tmp;
    corsaro_report_ip_metric_t *ipmet, *tmpmet;

    HASH_ITER(hh, source_ips, ip, tmp) {
        HASH_ITER(hh, ip->assocmetrics, ipmet, tmpmet) {
            HASH_FIND(hh, rmap, &(ipmet->metid),
                    sizeof(corsaro_report_metric_id_t), r);
            assert(r);
            r->uniq_src_ips ++;
        }
    }

    HASH_ITER(hh, dest_ips, ip, tmp) {
        HASH_ITER(hh, ip->assocmetrics, ipmet, tmpmet) {
            HASH_FIND(hh, rmap, &(ipmet->metid),
                    sizeof(corsaro_report_metric_id_t), r);
            assert(r);
            r->uniq_dst_ips ++;
        }
    }


}

static int write_all_metrics(corsaro_logger_t *logger,
        corsaro_avro_writer_t *writer, corsaro_metric_set_t *metrics,
        uint32_t ts, corsaro_report_config_t *conf) {

    corsaro_report_result_t *resultmap, *r, *tmpres;
    corsaro_report_metric_id_t metricid;
    corsaro_report_metric_t *met, *tmpmet;

    resultmap = NULL;

    HASH_ITER(hh, metrics->activemetrics, met, tmpmet) {
        r = (corsaro_report_result_t *)malloc(sizeof(corsaro_report_result_t));
        memset(&(r->metid), 0, sizeof(corsaro_report_metric_id_t));

        r->metid.class = met->metid.class;
        r->metid.metricval = met->metid.metricval;

        r->pkt_cnt = met->pkt_cnt;
        r->ip_len = met->ip_len;
        r->attimestamp = ts;
        r->uniq_src_ips = 0;
        r->uniq_dst_ips = 0;
        r->label = conf->outlabel;
        r->metrictype = NULL;
        r->metricval = NULL;

        HASH_ADD_KEYPTR(hh, resultmap, &(r->metid),
                sizeof(corsaro_report_metric_id_t), r);
    }

    /* Tally up all the IPs seen for each metric */
    tally_ip_counters(resultmap, metrics->srcips, metrics->destips);

    HASH_ITER(hh, resultmap, r, tmpres) {
        write_single_metric(logger, writer, r);
        HASH_DELETE(hh, resultmap, r);
        free(r);
    }

    return 0;

}

static void combine_ip_metsets(corsaro_report_ip_metric_t **combset,
        corsaro_report_ip_metric_t **newset) {

    corsaro_report_ip_metric_t *toadd, *existing, *tmp;

    HASH_ITER(hh, *newset, toadd, tmp) {

        HASH_FIND(hh, *combset, &(toadd->metid),
                sizeof(corsaro_report_metric_id_t), existing);

        if (!existing) {
            HASH_DELETE(hh, *newset, toadd);
            HASH_ADD_KEYPTR(hh, *combset, &(toadd->metid),
                    sizeof(corsaro_report_metric_id_t), toadd);
            assert(toadd->source);
        }
    }

}

static void combine_ip_maps(corsaro_report_ip_t **combips,
        corsaro_report_ip_t **newips) {

    corsaro_report_ip_t *thisip, *existing, *tmp;

    HASH_ITER(hh, *newips, thisip, tmp) {
        HASH_FIND(hh, *combips, &(thisip->ipaddr), sizeof(uint32_t), existing);

        if (!existing) {
            existing = thisip;
            HASH_DELETE(hh, *newips, thisip);
            HASH_ADD_KEYPTR(hh, *combips, &(thisip->ipaddr), sizeof(uint32_t),
                    thisip);
        } else {
            combine_ip_metsets(&(existing->assocmetrics),
                    &(thisip->assocmetrics));
        }
    }
}

static void combine_metrics(corsaro_report_metric_t **dest,
        corsaro_report_metric_t **src) {

    corsaro_report_metric_t *existing, *srcmet, *tmp;

    HASH_ITER(hh, *src, srcmet, tmp) {

        HASH_FIND(hh, *dest, &(srcmet->metid),
                sizeof(corsaro_report_metric_id_t), existing);

        if (existing) {
            existing->pkt_cnt += srcmet->pkt_cnt;
            existing->ip_len += srcmet->ip_len;
        } else {
            HASH_DELETE(hh, *src, srcmet);
            HASH_ADD_KEYPTR(hh, *dest, &(srcmet->metid),
                    sizeof(corsaro_report_metric_id_t), srcmet);
        }

    }
}

static int update_combined_result(corsaro_metric_set_t *combined,
        corsaro_metric_set_t *next, corsaro_logger_t *logger) {

    combine_metrics(&combined->activemetrics, &next->activemetrics);
    combine_ip_maps(&combined->srcips, &next->srcips);
    combine_ip_maps(&combined->destips, &next->destips);

    destroy_metric_set(next);
    free(next);
    return 0;
}

int corsaro_report_merge_interval_results(corsaro_plugin_t *p, void *local,
        void **tomerge, corsaro_fin_interval_t *fin) {

    corsaro_metric_set_t *combined;
    corsaro_report_merge_state_t *m;
    int i, ret;
    char *outname;

    m = (corsaro_report_merge_state_t *)local;
    if (m == NULL) {
        return -1;
    }

    /* Use tomerge[0] as the "combined" result */
    combined = (corsaro_metric_set_t *)(tomerge[0]);

    /* First step, open an output file if we need one */
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

    for (i = 1; i < fin->threads_ended; i++) {
        if (update_combined_result(combined,
                (corsaro_metric_set_t *)(tomerge[i]), p->logger) < 0) {
            corsaro_log(p->logger,
                    "error while merging report results from thread %d", i);
            return -1;
        }
    }

    ret = 0;
    if (write_all_metrics(p->logger, m->writer, combined, fin->timestamp,
            (corsaro_report_config_t *)(p->config)) < 0) {
        ret = -1;
    }

    destroy_metric_set(combined);
    free(combined);

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
