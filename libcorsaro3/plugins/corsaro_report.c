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

#include "khash.h"
#include "ksort.h"
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

typedef struct report_metric {
    uint64_t pkt_cnt;
    uint64_t ip_len;
} corsaro_report_metric_t;

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

typedef struct report_result {
    uint64_t pkt_cnt;
    uint64_t ip_len;
    uint32_t uniq_src_ips;
    uint32_t uniq_dst_ips;
    uint32_t attimestamp;

    char *label;
    char *metrictype;
    char *metricval;

} corsaro_report_result_t;

#define HASHER_SHIFT_AND_XOR(value) h^=(h << 5) + (h >> 27) + (value)
static inline khint32_t metric_id_hash_func(corsaro_report_metric_id_t *mid) {
    khint32_t h = (khint32_t)(mid->metricval * 67);
    HASHER_SHIFT_AND_XOR(((uint32_t)mid->class));
}

#define metric_id_hash_equal(a,b) \
    ((a)->class == (b)->class && (a)->metricval == (b)->metricval)

KHASH_INIT(metid, corsaro_report_metric_id_t *, corsaro_report_metric_t *, 1,
        metric_id_hash_func, metric_id_hash_equal);

KHASH_INIT(metset, corsaro_report_metric_id_t *, char, 0,
        metric_id_hash_func, metric_id_hash_equal);

KHASH_INIT(res, corsaro_report_metric_id_t *, corsaro_report_result_t *, 1,
        metric_id_hash_func, metric_id_hash_equal);

KHASH_MAP_INIT_INT(ip, khash_t(metset) *);

typedef struct metric_set {
    kh_metid_t *activemetrics;
    kh_ip_t *source_ips;
    kh_ip_t *dest_ips;

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

static inline void init_metric_set(corsaro_metric_set_t *mset) {

    mset->source_ips = kh_init(ip);
    mset->dest_ips = kh_init(ip);
    mset->activemetrics = kh_init(metid);

    /* Immediately bump the hash table sizes to a non-trivial
     * amount of entries -- if we let the table grow naturally from
     * its default (small) size, we're going to waste a TON of time
     * expanding and re-adjusting the table.
     */
    kh_resize(ip, mset->source_ips, 100000);
    kh_resize(ip, mset->dest_ips, 100000);
}

void *corsaro_report_init_processing(corsaro_plugin_t *p, int threadid) {

    corsaro_report_state_t *state;

    state = (corsaro_report_state_t *)malloc(sizeof(corsaro_report_state_t));
    state->metrics = (corsaro_metric_set_t *)malloc(
            sizeof(corsaro_metric_set_t));

    init_metric_set(state->metrics);
    return state;
}

static inline void free_metrics(corsaro_report_metric_id_t *metid) {
    free(metid);
}

static inline void free_ip_entries(kh_metset_t *ip) {
    kh_destroy(metset, ip);
}

static inline void free_metric_vals(corsaro_report_metric_t *met) {
    free(met);
}

static inline void destroy_metric_set(corsaro_metric_set_t *mset) {

    kh_free_vals(ip, mset->source_ips, free_ip_entries);
    kh_free_vals(ip, mset->dest_ips, free_ip_entries);
    kh_free_vals(metid, mset->activemetrics, free_metric_vals);
    kh_free(metid, mset->activemetrics, free_metrics);

    kh_destroy(ip, mset->source_ips);
    kh_destroy(ip, mset->dest_ips);
    kh_destroy(metid, mset->activemetrics);

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
    state->metrics = (corsaro_metric_set_t *)malloc(
            sizeof(corsaro_metric_set_t));

    init_metric_set(state->metrics);
    return mset;
}

static inline void update_metric(corsaro_metric_set_t *metrics,
        corsaro_report_metric_class_t metclass, uint32_t metval,
        kh_metset_t *srcipmap, kh_metset_t *dstipmap, uint16_t iplen) {

    khiter_t khiter;
    int khret;
    corsaro_report_metric_id_t *metricid, lookup;
    corsaro_report_metric_t *metdata;

    lookup.class = metclass;
    lookup.metricval = metval;

    /* Update the metric itself */
    if ((khiter = kh_get(metid, metrics->activemetrics, &lookup)) ==
            kh_end(metrics->activemetrics)) {

        metricid = (corsaro_report_metric_id_t *)malloc(sizeof(lookup));
        metricid->class = metclass;
        metricid->metricval = metval;

        metdata = (corsaro_report_metric_t *)malloc(
                sizeof(corsaro_report_metric_t));
        metdata->pkt_cnt = 0;
        metdata->ip_len = 0;

        khiter = kh_put(metid, metrics->activemetrics, metricid, &khret);
        kh_value(metrics->activemetrics, khiter) = metdata;

    } else {
        metricid = kh_key(metrics->activemetrics, khiter);
        metdata = kh_value(metrics->activemetrics, khiter);
    }

    metdata->pkt_cnt += 1;
    metdata->ip_len += iplen;

    /* Update source IP map */
    if ((khiter = kh_get(metset, srcipmap, metricid)) == kh_end(srcipmap)) {
        khiter = kh_put(metset, srcipmap, metricid, &khret);
    }

    /* Update dest IP map */

    if ((khiter = kh_get(metset, dstipmap, metricid)) == kh_end(dstipmap)) {
        khiter = kh_put(metset, dstipmap, metricid, &khret);
    }

}

static void update_basic_tag_metrics(corsaro_logger_t *logger,
        corsaro_metric_set_t *metrics, corsaro_packet_tags_t *tags,
        kh_metset_t *srcs, kh_metset_t *dsts, uint16_t iplen) {

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
                tags->src_port, srcs, dsts, iplen);
        update_metric(metrics, CORSARO_METRIC_CLASS_ICMP_CODE,
                tags->dest_port, srcs, dsts, iplen);

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
                tags->src_port, srcs, dsts, iplen);
        update_metric(metrics, CORSARO_METRIC_CLASS_TCP_DEST_PORT,
                tags->dest_port, srcs, dsts, iplen);
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
                tags->src_port, srcs, dsts, iplen);
        update_metric(metrics, CORSARO_METRIC_CLASS_UDP_DEST_PORT,
                tags->dest_port, srcs, dsts, iplen);
    }

    update_metric(metrics, CORSARO_METRIC_CLASS_COMBINED, 0, srcs, dsts,
            iplen);
    update_metric(metrics, CORSARO_METRIC_CLASS_IP_PROTOCOL, tags->protocol,
            srcs, dsts, iplen);

}

static void update_maxmind_tag_metrics(corsaro_logger_t *logger,
        corsaro_metric_set_t *metrics, corsaro_packet_tags_t *tags,
        uint32_t srcaddr, uint32_t dstaddr, uint16_t iplen) {

/*
    update_metric(metrics->maxmind_continents, tags->maxmind_continent,
            srcaddr, dstaddr, iplen);
    update_metric(metrics->maxmind_countries, tags->maxmind_country,
            srcaddr, dstaddr, iplen);
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
    kh_metset_t *srcipmap, *destipmap;
    khiter_t khiter;
    int khret;

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


    if ((khiter = kh_get(ip, state->metrics->source_ips, srcaddr)) ==
            kh_end(state->metrics->source_ips)) {

        srcipmap = kh_init(metset);
        kh_resize(metset, srcipmap, 10000);
        khiter = kh_put(ip, state->metrics->source_ips, srcaddr, &khret);
        kh_value(state->metrics->source_ips, khiter) = srcipmap;
    } else {
        srcipmap = kh_value(state->metrics->source_ips, khiter);
    }

    if ((khiter = kh_get(ip, state->metrics->dest_ips, dstaddr)) ==
            kh_end(state->metrics->dest_ips)) {

        destipmap = kh_init(metset);
        kh_resize(metset, destipmap, 10000);
        khiter = kh_put(ip, state->metrics->dest_ips, dstaddr, &khret);
        kh_value(state->metrics->dest_ips, khiter) = destipmap;
    } else {
        destipmap = kh_value(state->metrics->dest_ips, khiter);
    }

    if (basic_tagged(tags)) {
        update_basic_tag_metrics(p->logger, state->metrics, tags, srcipmap,
                destipmap, iplen);
    }

    if (maxmind_tagged(tags)) {
        update_maxmind_tag_metrics(p->logger, state->metrics, tags, srcaddr,
                dstaddr, iplen);
    }

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
        corsaro_avro_writer_t *writer, corsaro_report_metric_id_t *metricid,
        corsaro_report_result_t *res) {

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

static void tally_ip_counters(kh_res_t *rmap, kh_ip_t *source_ips,
        kh_ip_t *dest_ips) {

    kh_metset_t *mset;
    khiter_t i, j, find;
    int khret;
    corsaro_report_result_t *r;
    corsaro_report_metric_id_t *metricid;

    for (i = kh_begin(source_ips); i != kh_end(source_ips); ++i) {
        if (!kh_exist(source_ips, i)) {
            continue;
        }
        mset = kh_value(source_ips, i);
        for (j = kh_begin(mset); j != kh_end(mset); ++j) {

            if (!kh_exist(mset, j)) {
                continue;
            }
            metricid = kh_key(mset, j);
            find = kh_get(res, rmap, metricid);
            assert(find != kh_end(rmap));

            r = kh_value(rmap, find);
            r->uniq_src_ips ++;
        }
    }

    for (i = kh_begin(dest_ips); i != kh_end(dest_ips); ++i) {
        if (!kh_exist(dest_ips, i)) {
            continue;
        }
        mset = kh_value(dest_ips, i);
        for (j = kh_begin(mset); j != kh_end(mset); ++j) {

            if (!kh_exist(mset, j)) {
                continue;
            }
            metricid = kh_key(mset, j);
            find = kh_get(res, rmap, metricid);
            assert(find != kh_end(rmap));

            r = kh_value(rmap, find);
            r->uniq_dst_ips ++;
        }
    }

}

static inline void free_result(corsaro_report_result_t *r) {
    free(r);
}

static int write_all_metrics(corsaro_logger_t *logger,
        corsaro_avro_writer_t *writer, corsaro_metric_set_t *metrics,
        uint32_t ts, corsaro_report_config_t *conf) {

    kh_res_t *resultmap = kh_init(res);
    corsaro_report_result_t *r;
    corsaro_report_metric_id_t *metricid;
    corsaro_report_metric_t *counters;

    khiter_t i, ins;
    int khret;

    for (i = kh_begin(metrics->activemetrics);
            i != kh_end(metrics->activemetrics); ++i) {

        if (!kh_exist(metrics->activemetrics, i)) {
            continue;
        }

        metricid = kh_key(metrics->activemetrics, i);
        counters = kh_value(metrics->activemetrics, i);

        ins = kh_put(res, resultmap, metricid, &khret);
        r = (corsaro_report_result_t *)malloc(sizeof(corsaro_report_result_t));
        r->pkt_cnt = counters->pkt_cnt;
        r->ip_len = counters->ip_len;
        r->attimestamp = ts;
        r->uniq_src_ips = 0;
        r->uniq_dst_ips = 0;
        r->label = conf->outlabel;
        r->metrictype = NULL;
        r->metricval = NULL;
        kh_value(resultmap, ins) = r;
    }


    for (i = kh_begin(resultmap); i != kh_end(resultmap); ++i) {
        if (!kh_exist(resultmap, i)) {
            continue;
        }

        metricid = kh_key(resultmap, i);
        r = kh_value(resultmap, i);
    }

    /* Tally up all the IPs seen for each metric */
    tally_ip_counters(resultmap, metrics->source_ips, metrics->dest_ips);

    for (i = kh_begin(resultmap); i != kh_end(resultmap); ++i) {
        if (!kh_exist(resultmap, i)) {
            continue;
        }

        r = kh_value(resultmap, i);
        metricid = kh_key(resultmap, i);

        write_single_metric(logger, writer, metricid, r);
    }

    kh_free_vals(res, resultmap, free_result);
    kh_destroy(res, resultmap);

    return 0;

}

static void combine_metsets(kh_metset_t *dest, kh_metset_t *src,
        kh_metid_t *metrefs) {

    khiter_t i, find;
    int khret;
    corsaro_report_metric_id_t *toadd, *canon;

    for (i = kh_begin(src); i != kh_end(src); ++i) {
        if (!kh_exist(src, i)) {
            continue;
        }
        toadd = kh_key(src, i);

        /* This metric ID is probably about to be deleted, so we need to make
         * sure we put the "canonical" reference in our metset instead.
         */
        find = kh_get(metid, metrefs, toadd);
        assert(find != kh_end(metrefs));
        canon = kh_key(metrefs, find);
        find = kh_get(metset, dest, canon);

        if (find == kh_end(dest)) {
            /* metric not in destination set, add it */
            find = kh_put(metset, dest, canon, &khret);
            kh_del(metset, src, i);
        }
    }
}

static void combine_ip_maps(kh_ip_t *dest, kh_ip_t *src, kh_metid_t *metrefs) {

    khiter_t i, find;
    uint32_t ipaddr;
    int khret;
    kh_metset_t *srcmets, *dstmets;

    for (i = kh_begin(src); i != kh_end(src); ++i) {
        if (!kh_exist(src, i)) {
            continue;
        }

        ipaddr = kh_key(src, i);
        srcmets = kh_value(src, i);
        find = kh_get(ip, dest, ipaddr);

        if (find == kh_end(dest)) {
            /* This IP is not in the dest map */
            find = kh_put(ip, dest, ipaddr, &khret);
            dstmets = kh_init(metset);
            kh_resize(metset, dstmets, 10000);
            kh_value(dest, find) = dstmets;
        } else {
            dstmets = kh_value(dest, find);
        }
        combine_metsets(dstmets, srcmets, metrefs);
    }
}

static void combine_metrics(kh_metid_t *dest, kh_metid_t *src) {

    khiter_t i, find;
    int khret;
    corsaro_report_metric_id_t *toadd;
    corsaro_report_metric_t *existing, *srcmet;

    for (i = kh_begin(src); i != kh_end(src); ++i) {
        if (!kh_exist(src, i)) {
            continue;
        }
        toadd = kh_key(src, i);
        srcmet = kh_value(src, i);
        find = kh_get(metid, dest, toadd);

        if (find == kh_end(dest)) {
            find = kh_put(metid, dest, toadd, &khret);
            kh_value(dest, find) = srcmet;
            kh_del(metid, src, i);
            continue;
        }

        existing = kh_value(dest, find);
        existing->pkt_cnt += srcmet->pkt_cnt;
        existing->ip_len += srcmet->ip_len;
    }
}

static int update_combined_result(corsaro_metric_set_t *combined,
        corsaro_metric_set_t *next, corsaro_logger_t *logger) {

    combine_metrics(combined->activemetrics, next->activemetrics);
    combine_ip_maps(combined->source_ips, next->source_ips,
            combined->activemetrics);
    combine_ip_maps(combined->dest_ips, next->dest_ips,
            combined->activemetrics); 

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
