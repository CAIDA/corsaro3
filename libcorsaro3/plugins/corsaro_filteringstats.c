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

#include "khash.h"
#include "ksort.h"
#include "libcorsaro3_plugin.h"
#include "libcorsaro3_avro.h"
#include "libcorsaro3_filtering.h"
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
    kh_32xx_t *sourceips;
    kh_32xx_t *destips;
} corsaro_filteringstats_counter_t;

typedef struct corsaro_filteringstats_config {
    /** Standard options, e.g. template */
    corsaro_plugin_proc_options_t basic;

    char *filtersource;
} corsaro_filteringstats_config_t;

KHASH_MAP_INIT_INT(fstats, corsaro_filteringstats_counter_t *)
KHASH_MAP_INIT_STR(cusstats, corsaro_filteringstats_counter_t *)

struct corsaro_filteringstats_state_t {

    libtrace_list_t *customfilters;
    corsaro_filteringstats_counter_t *stats;
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

static void init_counter(corsaro_filteringstats_counter_t *c) {

    if (c == NULL) {
        return;
    }

    c->sourceips = kh_init(32xx);
    c->destips = kh_init(32xx);
    c->packets = 0;
    c->bytes = 0;
    c->filtername = NULL;
}

static void free_counter(corsaro_filteringstats_counter_t *c) {
    if (c == NULL) {
        return;
    }

    kh_destroy(32xx, c->sourceips);
    kh_destroy(32xx, c->destips);
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
        corsaro_plugin_proc_options_t *stdopts) {

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

    state->stats = calloc(CORSARO_FILTERID_MAX,
            sizeof(corsaro_filteringstats_counter_t));;
    state->customstats = kh_init(cusstats);
    state->lastpktts = 0;
    state->threadid = threadid;
    state->customfilters = NULL;

    for (i = 0; i < CORSARO_FILTERID_MAX; i++) {
        init_counter(&(state->stats[i]));
    }
    return state;
}

int corsaro_filteringstats_halt_processing(corsaro_plugin_t *p, void *local) {

    struct corsaro_filteringstats_state_t *state;
    int k;

    state = (struct corsaro_filteringstats_state_t *)local;
    if (state == NULL) {
        return 0;
    }

    for (k = 0; k < CORSARO_FILTERID_MAX; k++) {
        free_counter(&(state->stats[k]));
    }

    for (k = 0; k < kh_end(state->customstats); ++k) {
        if (kh_exist(state->customstats, k)) {
            free_counter(kh_value(state->customstats, k));
        }
    }

    free(state->stats);
    kh_destroy(cusstats, state->customstats);
    if (state->customfilters) {
        corsaro_destroy_filters(state->customfilters);
    }
    free(state);
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

    for (i = 0; i < CORSARO_FILTERID_MAX; i++) {
        init_counter(&(state->stats[i]));
    }

    /* TODO create custom filters if a) the user has specified a file with
     * them in and b) they don't already exist in state.
     */

    /* TODO reset custom filter stats */

    return 0;
}

void *corsaro_filteringstats_end_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_end) {

    struct corsaro_filteringstats_state_t *state, *copy;
    int i;

    state = (struct corsaro_filteringstats_state_t *)local;
    if (state == NULL) {
        corsaro_log(p->logger,
                "corsaro_filteringstats_end_interval: thread-local state is NULL!");
        return NULL;
    }

    copy = (struct corsaro_filteringstats_state_t *)malloc(
            sizeof(struct corsaro_filteringstats_state_t));

    copy->stats = calloc(CORSARO_FILTERID_MAX,
            sizeof(corsaro_filteringstats_counter_t));
    memcpy(copy->stats, state->stats, CORSARO_FILTERID_MAX *
            sizeof(corsaro_filteringstats_counter_t));

    copy->customstats = state->customstats;

    for (i = 0; i < CORSARO_FILTERID_MAX; i++) {
        init_counter(&(state->stats[i]));
    }

    state->customstats = kh_init(cusstats);

    return (void *)copy;
}

static inline void update_counter(corsaro_filteringstats_counter_t *c,
        uint16_t iplen, uint32_t srcip, uint32_t destip) {

    int khret;

    c->packets ++;
    c->bytes += iplen;
    kh_put(32xx, c->sourceips, srcip, &khret);
    kh_put(32xx, c->destips, destip, &khret);
}

int corsaro_filteringstats_process_packet(corsaro_plugin_t *p, void *local,
        libtrace_packet_t *packet, corsaro_packet_tags_t *tags) {

    struct corsaro_filteringstats_state_t *state;
    corsaro_filter_torun_t torun[CORSARO_FILTERID_MAX];
    libtrace_ip_t *ip;
    int i;
    khiter_t k;
    uint16_t iplen;
    uint32_t srcip, destip;

    state = (struct corsaro_filteringstats_state_t *)local;
    if (state == NULL) {
        corsaro_log(p->logger,
                "corsaro_filteringstats_process_packet: thread-local state is NULL!");
        return -1;
    }

    ip = trace_get_ip(packet);
    if (!ip) {
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

    if (corsaro_apply_multiple_filters(p->logger, packet, torun,
            CORSARO_FILTERID_MAX) < 0) {
        return -1;
    }

    for (i = 0; i < CORSARO_FILTERID_MAX; i++) {

        if (torun[i].result == 0) {
            continue;
        }

        update_counter(&(state->stats[i]), iplen, srcip, destip);
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


static int update_combined_result(
        struct corsaro_filteringstats_state_t *combined,
        struct corsaro_filteringstats_state_t *next,
        corsaro_logger_t *logger) {

    int i, khret;
    khiter_t k;

    for (i = 0; i < CORSARO_FILTERID_MAX; i++) {
        corsaro_filteringstats_counter_t *existing, *toadd;

        existing = &(combined->stats[i]);
        toadd = &(next->stats[i]);

        existing->packets += toadd->packets;
        existing->bytes += toadd->bytes;
        combine_32_hash(existing->sourceips, toadd->sourceips);
        combine_32_hash(existing->destips, toadd->destips);

        free_counter(&(next->stats[i]));
    }

    /* TODO combine custom filter stats */

    for (i = 0; i < kh_end(next->customstats); ++i) {
        if (kh_exist(next->customstats, i)) {
            free_counter(kh_value(next->customstats, i));
        }
    }

    free(next->stats);
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
            "filteringstats", kh_size(c->sourceips));
    CORSARO_AVRO_SET_FIELD(long, av, field, 4, "destination_ips",
            "filteringstats", kh_size(c->destips));
    CORSARO_AVRO_SET_FIELD(string, av, field, 5, "filter_name",
            "filteringstats", c->filtername);

    return 0;
}

static int write_builtin_filter_stats(corsaro_logger_t *logger,
        corsaro_avro_writer_t *writer, corsaro_filteringstats_counter_t *stats,
        uint32_t timestamp) {

    int i;
    khiter_t k;
    avro_value_t *avro;

    for (i = 0; i < CORSARO_FILTERID_MAX; i++) {
        corsaro_filteringstats_counter_t *c;

        c = &(stats[i]);

        c->bin_ts = timestamp;
        c->filtername = (char *)corsaro_get_builtin_filter_name(logger, i);

        avro = corsaro_populate_avro_item(writer, c, filteringstats_to_avro);
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
    int ret = 0;

    m = (corsaro_filteringstats_merge_state_t *)(local);
    if (m == NULL) {
        return -1;
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

    if (write_builtin_filter_stats(p->logger, m->writer, combined->stats,
            fin->timestamp) < 0) {
        ret = -1;
    }

    /* TODO write custom filter stats */

    for (i = 0; i < CORSARO_FILTERID_MAX; ++i) {
        free_counter(&(combined->stats[i]));
    }

    for (i = 0; i < kh_end(combined->customstats); ++i) {
        if (kh_exist(combined->customstats, i)) {
            free_counter(kh_value(combined->customstats, i));
        }
    }

    free(combined->stats);
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
