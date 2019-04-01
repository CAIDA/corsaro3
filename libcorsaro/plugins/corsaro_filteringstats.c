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

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <yaml.h>
#include <Judy.h>

#include "khash.h"
#include "ksort.h"
#include "libcorsaro_plugin.h"
#include "libcorsaro_avro.h"
#include "libcorsaro_filtering.h"
#include "corsaro_filteringstats.h"
#include "utils.h"

#define CORSARO_FILTERINGSTATS_MAGIC 0x46494C54
#define PLUGIN_NAME "filteringstats"

KHASH_SET_INIT_INT(32xx)

static corsaro_plugin_t corsaro_filteringstats_plugin = {

    PLUGIN_NAME,
    CORSARO_PLUGIN_ID_FILTERINGSTATS,
    CORSARO_FILTERINGSTATS_MAGIC,
    CORSARO_PLUGIN_GENERATE_BASE_PTRS(corsaro_filteringstats),
    CORSARO_PLUGIN_GENERATE_TRACE_PTRS(corsaro_filteringstats),
    CORSARO_PLUGIN_GENERATE_MERGE_PTRS(corsaro_filteringstats),
    CORSARO_PLUGIN_GENERATE_TAIL
};

typedef struct filtstats {
    uint32_t bin_ts;
    char *filtername;
    uint64_t packets;
    uint64_t bytes;
    uint32_t sourceips;
    uint32_t destips;
} corsaro_filteringstats_counter_t;

typedef struct corsaro_filteringstats_config {
    /** Standard options, e.g. template */
    corsaro_plugin_proc_options_t basic;

    char *filtersource;
} corsaro_filteringstats_config_t;

KHASH_MAP_INIT_STR(cusstats, corsaro_filteringstats_counter_t *)

struct corsaro_filteringstats_state_t {

    libtrace_list_t *customfilters;
    Pvoid_t sourceips;
    Pvoid_t destips;
    uint64_t packets[CORSARO_FILTERID_MAX];
    uint64_t bytes[CORSARO_FILTERID_MAX];

    khash_t(cusstats) *customstats;
    int threadid;
    uint32_t lastpktts;
};

typedef struct corsaro_filteringstats_merge_state {
    corsaro_avro_writer_t *writer;
} corsaro_filteringstats_merge_state_t;


static const char FILTERINGSTATS_SCHEMA[] =
"{\"type\": \"record\",\
  \"namespace\": \"org.caida.corsaro\",\
  \"name\": \"filteringstats\",\
  \"doc\": \"Statistics describing the packets that would have been \
             excluded by each internal filter and subfilter.\",\
  \"fields\": [\
        {\"name\": \"bin_timestamp\", \"type\": \"long\"}, \
        {\"name\": \"packet_count\", \"type\": \"long\"}, \
        {\"name\": \"byte_count\", \"type\": \"long\"}, \
        {\"name\": \"source_ips\", \"type\": \"long\"}, \
        {\"name\": \"destination_ips\", \"type\": \"long\"}, \
        {\"name\": \"filter_name\", \"type\": \"string\"} \
    ]}";


corsaro_plugin_t *corsaro_filteringstats_alloc(void) {
    return &(corsaro_filteringstats_plugin);
}

int corsaro_filteringstats_parse_config(corsaro_plugin_t *p,
        yaml_document_t *doc, yaml_node_t *options) {

    corsaro_filteringstats_config_t *conf;

    conf = (corsaro_filteringstats_config_t *)(malloc(sizeof(
            corsaro_filteringstats_config_t)));


    /* TODO actually read a filter source filename from the config file */
    conf->filtersource = NULL;
    p->config = conf;
    return 0;
}

int corsaro_filteringstats_finalise_config(corsaro_plugin_t *p,
        corsaro_plugin_proc_options_t *stdopts, void *zmq_ctxt) {

    corsaro_filteringstats_config_t *conf;
    conf = (corsaro_filteringstats_config_t *)(p->config);

    conf->basic.template = stdopts->template;
    conf->basic.monitorid = stdopts->monitorid;
    return 0;
}

void corsaro_filteringstats_destroy_self(corsaro_plugin_t *p) {
    corsaro_filteringstats_config_t *conf;
    conf = (corsaro_filteringstats_config_t *)(p->config);

    if (p->config) {
        if (conf->filtersource) {
            free(conf->filtersource);
        }
        free(p->config);
    }
    p->config = NULL;
}

void *corsaro_filteringstats_init_processing(corsaro_plugin_t *p,
        int threadid) {

    struct corsaro_filteringstats_state_t *state;
    int i;
    state = (struct corsaro_filteringstats_state_t *)malloc(
            sizeof(struct corsaro_filteringstats_state_t));
    if (state == NULL) {
        corsaro_log(p->logger,
                "failed to allocate thread-local state within filteringstats plugin.");
        return NULL;
    }

    memset(state->packets, 0, sizeof(uint64_t) * CORSARO_FILTERID_MAX);
    memset(state->bytes, 0, sizeof(uint64_t) * CORSARO_FILTERID_MAX);
    state->sourceips = NULL;
    state->destips = NULL;
    state->customstats = kh_init(cusstats);
    state->lastpktts = 0;
    state->threadid = threadid;
    state->customfilters = NULL;

    return state;
}

int corsaro_filteringstats_halt_processing(corsaro_plugin_t *p, void *local) {

    struct corsaro_filteringstats_state_t *state;
    int k, ret;

    state = (struct corsaro_filteringstats_state_t *)local;
    if (state == NULL) {
        return 0;
    }

    if (state->sourceips) {
        JLFA(ret, state->sourceips);
    }
    if (state->destips) {
        JLFA(ret, state->destips);
    }

    for (k = 0; k < kh_end(state->customstats); ++k) {
        if (kh_exist(state->customstats, k)) {
            //free_counter(kh_value(state->customstats, k));
        }
    }

    kh_destroy(cusstats, state->customstats);
    if (state->customfilters) {
        corsaro_destroy_filters(state->customfilters);
    }
    free(state);
    return 0;
}


char *corsaro_filteringstats_derive_output_name(corsaro_plugin_t *p,
        void *local, uint32_t timestamp, int threadid) {

    corsaro_filteringstats_config_t *conf;
    char *outname = NULL;
    conf = (corsaro_filteringstats_config_t *)(p->config);

    if (conf == NULL) {
        return NULL;
    }

    outname = corsaro_generate_avro_file_name(conf->basic.template, p->name,
            conf->basic.monitorid, timestamp, threadid);
    if (outname == NULL) {
        corsaro_log(p->logger,
                "failed to generate suitable filename for filteringstats output");
        return NULL;
    }
    return outname;
}

int corsaro_filteringstats_start_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_start) {

    struct corsaro_filteringstats_state_t *state;
    int i;
    int khret;
    khiter_t k;

    state = (struct corsaro_filteringstats_state_t *)local;
    if (state == NULL) {
        corsaro_log(p->logger,
                "corsaro_filteringstats_start_interval: thread-local state is NULL!");
        return -1;
    }

    memset(state->packets, 0, sizeof(uint64_t) * CORSARO_FILTERID_MAX);
    memset(state->bytes, 0, sizeof(uint64_t) * CORSARO_FILTERID_MAX);

    /* TODO create custom filters if a) the user has specified a file with
     * them in and b) they don't already exist in state.
     */

    /* TODO reset custom filter stats */

    return 0;
}

void *corsaro_filteringstats_end_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_end, uint8_t complete) {

    struct corsaro_filteringstats_state_t *state, *copy;
    int i;
    Word_t rcret;

    state = (struct corsaro_filteringstats_state_t *)local;
    if (state == NULL) {
        corsaro_log(p->logger,
                "corsaro_filteringstats_end_interval: thread-local state is NULL!");
        return NULL;
    }

    if (complete) {
        copy = (struct corsaro_filteringstats_state_t *)malloc(
                sizeof(struct corsaro_filteringstats_state_t));

        copy->sourceips = state->sourceips;
        copy->destips = state->destips;
        memcpy(copy->packets, state->packets,
                sizeof(uint64_t) * CORSARO_FILTERID_MAX);
        memcpy(copy->bytes, state->packets,
                sizeof(uint64_t) * CORSARO_FILTERID_MAX);
        copy->customstats = state->customstats;
    } else {
        copy = NULL;
        JLFA(rcret, state->sourceips);
        JLFA(rcret, state->destips);
        kh_destroy(cusstats, state->customstats);
    }

    state->sourceips = NULL;
    state->destips = NULL;
    state->customstats = kh_init(cusstats);

    return (void *)copy;
}

int corsaro_filteringstats_process_packet(corsaro_plugin_t *p, void *local,
        libtrace_packet_t *packet, corsaro_packet_tags_t *tags) {

    struct corsaro_filteringstats_state_t *state;
    corsaro_filter_torun_t torun[CORSARO_FILTERID_MAX];
    libtrace_ip_t *ip;
    int i, kret;
    PWord_t srcvalp, destvalp;
    khiter_t srckey, destkey;
    uint16_t iplen;
    uint32_t srcip, destip;
    uint32_t mask, rem;
    uint16_t ethertype;

    state = (struct corsaro_filteringstats_state_t *)local;
    if (state == NULL) {
        corsaro_log(p->logger,
                "corsaro_filteringstats_process_packet: thread-local state is NULL!");
        return -1;
    }

    ip = (libtrace_ip_t *)trace_get_layer3(packet, &ethertype, &rem);
    if (!ip || rem < sizeof(libtrace_ip_t)) {
        return 0;
    }
    if (ethertype != TRACE_ETHERTYPE_IP) {
        return 0;
    }

    iplen = ntohs(ip->ip_len);
    srcip = ip->ip_src.s_addr;
    destip = ip->ip_dst.s_addr;

    /* Check all built-in filters, including high-level filters */
    for (i = 0; i < CORSARO_FILTERID_MAX; i++) {
        torun[i].filterid = i;
        torun[i].result = 0;
    }

    if (corsaro_apply_multiple_filters(p->logger, ip, rem, torun,
            CORSARO_FILTERID_MAX) < 0) {
        return -1;
    }

    /* TODO error handling via kret value */

    JLG(srcvalp, state->sourceips, srcip);
    if (srcvalp == NULL) {
        JLI(srcvalp, state->sourceips, srcip);
    }

    JLG(destvalp, state->destips, destip);
    if (destvalp == NULL) {
        JLI(destvalp, state->destips, destip);
    }

    for (i = 0; i < CORSARO_FILTERID_MAX; i++) {

        if (torun[i].result == 0) {
            continue;
        }

        state->packets[i] ++;
        state->bytes[i] += iplen;

        (*srcvalp) = (*srcvalp) | (1 << i);
        (*destvalp) = (*destvalp) | (1 << i);
    }

    /* Check all custom filters TODO */

    return 0;
}


/** ------------- MERGING API -------------------- */

void *corsaro_filteringstats_init_merging(corsaro_plugin_t *p, int sources) {

    corsaro_filteringstats_merge_state_t *m;
    m = (corsaro_filteringstats_merge_state_t *)calloc(1,
            sizeof(corsaro_filteringstats_merge_state_t));
    if (m == NULL) {
        return NULL;
    }

    m->writer = corsaro_create_avro_writer(p->logger, FILTERINGSTATS_SCHEMA);

    return m;
}

int corsaro_filteringstats_halt_merging(corsaro_plugin_t *p, void *local) {

    corsaro_filteringstats_merge_state_t *m;

    m = (corsaro_filteringstats_merge_state_t *)(local);
    if (m == NULL) {
        return 0;
    }

    if (m->writer) {
        corsaro_destroy_avro_writer(m->writer);
    }
    free(m);
    return 0;
}

/* XXX Consider making this a utility function? */
static int combine_ipmap_hash(Pvoid_t dest, Pvoid_t src) {

    Word_t iterind = 0;
    PWord_t pval;
    PWord_t found;

    JLF(pval, src, iterind);
    while (pval) {
        JLG(found, dest, iterind);
        if (found == NULL) {
            JLI(found, dest, iterind);
            (*found) = (*pval);
        } else {
            (*found) = (*found) | (*pval);
        }

        JLN(pval, src, iterind);
    }
    return 0;
}

static int update_combined_result(
        struct corsaro_filteringstats_state_t *combined,
        struct corsaro_filteringstats_state_t *next,
        corsaro_logger_t *logger) {

    int i, khret, ret;
    khiter_t k;

    combine_ipmap_hash(combined->sourceips, next->sourceips);
    combine_ipmap_hash(combined->destips, next->destips);

    for (i = 0; i < CORSARO_FILTERID_MAX; i++) {

        combined->packets[i] += next->packets[i];
        combined->bytes[i] += next->bytes[i];
    }

    /* TODO combine custom filter stats */

    for (i = 0; i < kh_end(next->customstats); ++i) {
        if (kh_exist(next->customstats, i)) {
            //free_counter(kh_value(next->customstats, i));
        }
    }

    JLFA(ret, next->sourceips);
    JLFA(ret, next->destips);
    kh_destroy(cusstats, next->customstats);

    free(next);
    return 0;
}

static int filteringstats_to_avro(corsaro_logger_t *logger, avro_value_t *av,
        void *counter) {

    corsaro_filteringstats_counter_t *c;
    c = (corsaro_filteringstats_counter_t *)counter;

    avro_value_t field;
    CORSARO_AVRO_SET_FIELD(long, av, field, 0, "bin_timestamp",
            "filteringstats", c->bin_ts);
    CORSARO_AVRO_SET_FIELD(long, av, field, 1, "packet_count",
            "filteringstats", c->packets);
    CORSARO_AVRO_SET_FIELD(long, av, field, 2, "byte_count",
            "filteringstats", c->bytes);
    CORSARO_AVRO_SET_FIELD(long, av, field, 3, "source_ips",
            "filteringstats", c->sourceips);
    CORSARO_AVRO_SET_FIELD(long, av, field, 4, "destination_ips",
            "filteringstats", c->destips);
    CORSARO_AVRO_SET_FIELD(string, av, field, 5, "filter_name",
            "filteringstats", c->filtername);

    return 0;
}

static void count_filter_ips(uint32_t *results, Pvoid_t ipmap) {

    int i;
    PWord_t pval;
    Word_t iterindex = 0;

    JLF(pval, ipmap, iterindex);
    while (pval) {
        for (i = 0; i < CORSARO_FILTERID_MAX; i++) {
            if ((*pval) & (1 << i)) {
                results[i] ++;
            }
        }
        JLN(pval, ipmap, iterindex);
    }
}

static int write_builtin_filter_stats(corsaro_logger_t *logger,
        corsaro_avro_writer_t *writer,
        struct corsaro_filteringstats_state_t *stats,
        uint32_t timestamp) {

    int i;
    khiter_t k;
    avro_value_t *avro;

    uint32_t srcips[CORSARO_FILTERID_MAX];
    uint32_t destips[CORSARO_FILTERID_MAX];

    memset(srcips, 0, sizeof(uint32_t) * CORSARO_FILTERID_MAX);
    memset(destips, 0, sizeof(uint32_t) * CORSARO_FILTERID_MAX);

    count_filter_ips(srcips, stats->sourceips);
    count_filter_ips(destips, stats->destips);

    for (i = 0; i < CORSARO_FILTERID_MAX; i++) {
        corsaro_filteringstats_counter_t c;

        c.bin_ts = timestamp;
        c.filtername = (char *)corsaro_get_builtin_filter_name(logger, i);
        c.packets = stats->packets[i];
        c.bytes = stats->bytes[i];
        c.sourceips = srcips[i];
        c.destips = destips[i];

        avro = corsaro_populate_avro_item(writer, &c, filteringstats_to_avro);
        if (avro == NULL) {
            corsaro_log(logger,
                    "could not convert filtering stats to Avro record");
            return -1;
        }

        if (corsaro_append_avro_writer(writer, avro) < 0) {
            corsaro_log(logger,
                    "could not write filtering stats to Avro output file");
            return -1;
        }
    }
    return 0;
}

int corsaro_filteringstats_merge_interval_results(corsaro_plugin_t *p,
        void *local, void **tomerge, corsaro_fin_interval_t *fin) {

    struct corsaro_filteringstats_state_t *combined;
    corsaro_filteringstats_merge_state_t *m;
    int i;
    int ret = 0, rcret;

    m = (corsaro_filteringstats_merge_state_t *)(local);
    if (m == NULL) {
        return -1;
    }

    /* Plugin result data is NULL, must be a partial interval */
    if (tomerge[0] == NULL) {
        return 0;
    }

    /* Use tomerge[0] as the combined result */
    combined = (struct corsaro_filteringstats_state_t *)(tomerge[0]);

    /* First step, open an output file if we need one */
    if (m->writer && !corsaro_is_avro_writer_active(m->writer)) {
        char *outname = p->derive_output_name(p, local, fin->timestamp, -1);
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
                (struct corsaro_filteringstats_state_t *)(tomerge[i]),
                p->logger) < 0) {
            corsaro_log(p->logger,
                    "error while merging filteringstats results from thread %d",
                    i);
            return -1;
        }
    }

    if (write_builtin_filter_stats(p->logger, m->writer, combined,
            fin->timestamp) < 0) {
        ret = -1;
    }

    /* TODO write custom filter stats */

    for (i = 0; i < kh_end(combined->customstats); ++i) {
        if (kh_exist(combined->customstats, i)) {
            //free_counter(kh_value(combined->customstats, i));
        }
    }

    JLFA(rcret, combined->sourceips);
    JLFA(rcret, combined->destips);
    kh_destroy(cusstats, combined->customstats);

    free(combined);
    return ret;
}

int corsaro_filteringstats_rotate_output(corsaro_plugin_t *p, void *local) {

    corsaro_filteringstats_merge_state_t *m;

    m = (corsaro_filteringstats_merge_state_t *)(local);
    if (m == NULL) {
        return -1;
    }

    if (m->writer == NULL || corsaro_close_avro_writer(m->writer) < 0) {
        return -1;
    }

    return 0;
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
