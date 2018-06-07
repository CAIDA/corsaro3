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

KHASH_SET_INIT_INT(32xx)

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
    khash_t(32xx) *uniq_src_ip;
    khash_t(32xx) *uniq_dst_ip;
} corsaro_report_metric_t;

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

typedef struct metric_set {
    corsaro_report_metric_t maxmind_continents[METRIC_MAXMIND_2CHAR_MAX];
    corsaro_report_metric_t maxmind_countries[METRIC_MAXMIND_2CHAR_MAX];

    corsaro_report_metric_t tcp_source_ports[METRIC_PORT_MAX];
    corsaro_report_metric_t tcp_dest_ports[METRIC_PORT_MAX];
    corsaro_report_metric_t udp_source_ports[METRIC_PORT_MAX];
    corsaro_report_metric_t udp_dest_ports[METRIC_PORT_MAX];
    corsaro_report_metric_t icmp_codes[METRIC_ICMP_MAX];
    corsaro_report_metric_t icmp_types[METRIC_ICMP_MAX];
    corsaro_report_metric_t ip_protocols[METRIC_IPPROTOS_MAX];

    corsaro_report_metric_t combined[1];
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

/* XXX should become a utility function since this is duplicated elsewhere */
static int combine_32_hash(kh_32xx_t *dest, kh_32xx_t *src) {

    khiter_t i;
    uint32_t toadd;
    int khret;

    for (i = kh_begin(src); i != kh_end(src); ++i) {
        if (!kh_exist(src, i)) {
            continue;
        }

        toadd = kh_key(src, i);
        /* Just add it -- any duplicates should be silently ignored */
        kh_put(32xx, dest, toadd, &khret);
    }
    return 0;
}

static inline void init_metrics(corsaro_report_metric_t *array,
        int itemcount) {

    int i;
    for (i = 0; i < itemcount; i++) {
        array[i].uniq_src_ip = kh_init(32xx);
        array[i].uniq_dst_ip = kh_init(32xx);
        array[i].pkt_cnt = 0;
        array[i].ip_len = 0;
    }
}

static inline void destroy_metrics(corsaro_report_metric_t *array,
        int itemcount) {
    int i;
    for (i = 0; i < itemcount; i++) {
        kh_destroy(32xx, array[i].uniq_src_ip);
        kh_destroy(32xx, array[i].uniq_dst_ip);
    }
}

static inline void clear_metrics(corsaro_report_metric_t *array,
        int itemcount) {
    int i;
    for (i = 0; i < itemcount; i++) {
        kh_clear(32xx, array[i].uniq_src_ip);
        kh_clear(32xx, array[i].uniq_dst_ip);
        array[i].pkt_cnt = 0;
        array[i].ip_len = 0;
    }
}

static inline void combine_metrics(corsaro_report_metric_t *target,
        corsaro_report_metric_t *source, int itemcount) {

    int i;
    for (i = 0; i < itemcount; i++) {
        combine_32_hash(target[i].uniq_src_ip, source[i].uniq_src_ip);
        combine_32_hash(target[i].uniq_dst_ip, source[i].uniq_dst_ip);
        target[i].pkt_cnt += source[i].pkt_cnt;
        target[i].ip_len += source[i].ip_len;
    }
}


static inline void for_all_metrics(corsaro_metric_set_t *mset,
        void (*callback)(corsaro_report_metric_t *, int)) {

    callback(mset->maxmind_continents, METRIC_MAXMIND_2CHAR_MAX);
    callback(mset->maxmind_countries, METRIC_MAXMIND_2CHAR_MAX);
    callback(mset->tcp_source_ports, METRIC_PORT_MAX);
    callback(mset->tcp_dest_ports, METRIC_PORT_MAX);
    callback(mset->udp_source_ports, METRIC_PORT_MAX);
    callback(mset->udp_dest_ports, METRIC_PORT_MAX);
    callback(mset->icmp_types, METRIC_ICMP_MAX);
    callback(mset->icmp_codes, METRIC_ICMP_MAX);
    callback(mset->ip_protocols, METRIC_IPPROTOS_MAX);
    callback(mset->combined, 1);

}

void *corsaro_report_init_processing(corsaro_plugin_t *p, int threadid) {

    corsaro_report_state_t *state;

    state = (corsaro_report_state_t *)malloc(sizeof(corsaro_report_state_t));
    state->metrics = (corsaro_metric_set_t *)malloc(
            sizeof(corsaro_metric_set_t));

    for_all_metrics(state->metrics, init_metrics);
    return state;
}

int corsaro_report_halt_processing(corsaro_plugin_t *p, void *local) {

    corsaro_report_state_t *state;
    state = (corsaro_report_state_t *)local;

    if (state == NULL) {
        return 0;
    }
    for_all_metrics(state->metrics, destroy_metrics);
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

    for_all_metrics(state->metrics, init_metrics);
    return mset;
}

static inline void update_metric(corsaro_report_metric_t *met,
        uint32_t index, uint32_t srcaddr, uint32_t dstaddr, uint16_t iplen) {

    int khret;

    met[index].pkt_cnt ++;
    met[index].ip_len += iplen;
    kh_put(32xx, met[index].uniq_src_ip, srcaddr, &khret);
    kh_put(32xx, met[index].uniq_dst_ip, dstaddr, &khret);

}

static void update_basic_tag_metrics(corsaro_logger_t *logger,
        corsaro_metric_set_t *metrics, corsaro_packet_tags_t *tags,
        uint32_t srcaddr, uint32_t dstaddr, uint16_t iplen) {

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
        update_metric(metrics->icmp_types, tags->src_port, srcaddr,
                dstaddr, iplen);
        update_metric(metrics->icmp_codes, tags->dest_port, srcaddr,
                dstaddr, iplen);

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

        update_metric(metrics->tcp_source_ports, tags->src_port, srcaddr,
                dstaddr, iplen);
        update_metric(metrics->tcp_dest_ports, tags->dest_port, srcaddr,
                dstaddr, iplen);
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

        update_metric(metrics->udp_source_ports, tags->src_port, srcaddr,
                dstaddr, iplen);
        update_metric(metrics->udp_dest_ports, tags->dest_port, srcaddr,
                dstaddr, iplen);

    }

    update_metric(metrics->combined, 0, srcaddr, dstaddr, iplen);
    update_metric(metrics->ip_protocols, tags->protocol, srcaddr, dstaddr,
            iplen);

}

static void update_maxmind_tag_metrics(corsaro_logger_t *logger,
        corsaro_metric_set_t *metrics, corsaro_packet_tags_t *tags,
        uint32_t srcaddr, uint32_t dstaddr, uint16_t iplen) {

    update_metric(metrics->maxmind_continents, tags->maxmind_continent,
            srcaddr, dstaddr, iplen);
    update_metric(metrics->maxmind_countries, tags->maxmind_country,
            srcaddr, dstaddr, iplen);


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

    if (basic_tagged(tags)) {
        update_basic_tag_metrics(p->logger, state->metrics, tags, srcaddr,
                dstaddr, iplen);
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
        corsaro_avro_writer_t *writer, corsaro_report_metric_t *met,
        uint32_t ts, char *outlabel, char *metrictype, char *metricvalue) {


    corsaro_report_result_t res;


    res.attimestamp = ts;
    res.pkt_cnt = met->pkt_cnt;
    res.ip_len = met->ip_len;
    res.uniq_src_ips = kh_size(met->uniq_src_ip);
    res.uniq_dst_ips = kh_size(met->uniq_dst_ip);

    res.label = outlabel;
    res.metrictype = metrictype;
    res.metricval = metricvalue;

    if (report_do_avro_write(logger, writer, &res) == -1) {
        return -1;
    }
    return 0;

}

static int write_all_metrics(corsaro_logger_t *logger,
        corsaro_avro_writer_t *writer, corsaro_metric_set_t *metrics,
        uint32_t ts, corsaro_report_config_t *conf) {

    int i;

    if (write_single_metric(logger, writer, &(metrics->combined[0]), ts,
            conf->outlabel, "combined", "all") != 0) {
        return -1;
    }

    /* TODO all the other metrics */

    return 0;

}

static int update_combined_result(corsaro_metric_set_t *combined,
        corsaro_metric_set_t *next, corsaro_logger_t *logger) {

    /* Can an error occur when combining? */

    combine_metrics(combined->maxmind_continents, next->maxmind_continents,
            METRIC_MAXMIND_2CHAR_MAX);
    combine_metrics(combined->maxmind_countries, next->maxmind_countries,
            METRIC_MAXMIND_2CHAR_MAX);
    combine_metrics(combined->tcp_source_ports, next->tcp_source_ports,
            METRIC_PORT_MAX);
    combine_metrics(combined->tcp_dest_ports, next->tcp_dest_ports,
            METRIC_PORT_MAX);
    combine_metrics(combined->udp_source_ports, next->udp_source_ports,
            METRIC_PORT_MAX);
    combine_metrics(combined->udp_dest_ports, next->udp_dest_ports,
            METRIC_PORT_MAX);
    combine_metrics(combined->icmp_types, next->icmp_types, METRIC_ICMP_MAX);
    combine_metrics(combined->icmp_codes, next->icmp_codes, METRIC_ICMP_MAX);
    combine_metrics(combined->ip_protocols, next->ip_protocols,
            METRIC_IPPROTOS_MAX);
    combine_metrics(combined->combined, next->combined, 1);

    for_all_metrics(next, destroy_metrics);
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

    for_all_metrics(combined, destroy_metrics);
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
