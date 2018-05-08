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
#include <sys/mman.h>

#include "libcorsaro3.h"
#include "libcorsaro3_plugin.h"
#include "libcorsaro3_avro.h"
#include "corsaro_flowtuple.h"
#include "utils.h"

/* This magic number is a legacy number from when we used to call it the
   'sixtuple' */
/** The magic number for this plugin when not using /8 opts - "SIXU" */
#define CORSARO_FLOWTUPLE_MAGIC 0x53495855

#define CORSARO_FLOWTUPLE_MMAP_SIZE 4096

/** Initialize the sorting functions and datatypes */
KSORT_INIT(sixt, struct corsaro_flowtuple *, corsaro_flowtuple_lt);

/** Initialize the hash functions and datatypes */
KHASH_INIT(sixt, struct corsaro_flowtuple *, char, 0,
        corsaro_flowtuple_hash_func, corsaro_flowtuple_hash_equal);


/** The number of output file pointers to support non-blocking close at the end
  of an interval. If the wandio buffers are large enough that it takes more
  than 1 interval to drain the buffers, consider increasing this number */
#define OUTFILE_POINTERS 2

/** Possible states for FlowTuple output sorting */
typedef enum corsaro_flowtuple_sort {
    /** FlowTuple output sorting is disabled */
    CORSARO_FLOWTUPLE_SORT_DISABLED = 0,

    /** FlowTuple output sorting is enabled */
    CORSARO_FLOWTUPLE_SORT_ENABLED = 1,

    /** Default FlowTuple output sorting behavior (enabled) */
    CORSARO_FLOWTUPLE_SORT_DEFAULT = CORSARO_FLOWTUPLE_SORT_ENABLED,

} corsaro_flowtuple_sort_t;

struct corsaro_flowtuple_class {
    uint16_t classtype;
    uint64_t members;
};

/** Holds the state for an instance of this plugin */
struct corsaro_flowtuple_state_t {
    /** Array of hash tables, one for each corsaro_flowtuple_class_type_t */
    khash_t(sixt) * st_hash;

    uint32_t last_interval_start;

    /** The ID of the thread running this plugin instance */
    int threadid;

};

typedef struct corsaro_flowtuple_iterator {
    khiter_t khiter;
    int sortiter;
    kh_sixt_t *hmap;
    struct corsaro_flowtuple *nextft;
    corsaro_result_type_t state;
    struct corsaro_flowtuple **sorted_keys;
} corsaro_flowtuple_iterator_t;

struct corsaro_flowtuple_merge_state_t {
    corsaro_avro_writer_t *writer;
};

typedef struct corsaro_flowtuple_config {
    corsaro_plugin_proc_options_t basic;
    corsaro_flowtuple_sort_t sort_enabled;
} corsaro_flowtuple_config_t;

/** The name of this plugin */
#define PLUGIN_NAME "flowtuple"

static const char FLOWTUPLE_RESULT_SCHEMA[] =
"{\"type\": \"record\",\
  \"namespace\":\"org.caida.corsaro\",\
  \"name\":\"flowtuple\",\
  \"doc\":\"A Corsaro FlowTuple record. All byte fields are in network byte order.\",\
  \"fields\":[\
      {\"name\": \"time\", \"type\": \"long\"}, \
      {\"name\": \"src_ip\", \"type\": \"long\"}, \
      {\"name\": \"dst_ip\", \"type\": \"long\"}, \
      {\"name\": \"src_port\", \"type\": \"int\"}, \
      {\"name\": \"dst_port\", \"type\": \"int\"}, \
      {\"name\": \"protocol\", \"type\": \"int\"}, \
      {\"name\": \"ttl\", \"type\": \"int\"}, \
      {\"name\": \"tcp_flags\", \"type\": \"int\"}, \
      {\"name\": \"ip_len\", \"type\": \"int\"}, \
      {\"name\": \"packet_cnt\", \"type\": \"long\"}]}";

static corsaro_plugin_t corsaro_flowtuple_plugin = {

    PLUGIN_NAME,
    CORSARO_PLUGIN_ID_FLOWTUPLE,
    CORSARO_FLOWTUPLE_MAGIC,
    CORSARO_PLUGIN_GENERATE_BASE_PTRS(corsaro_flowtuple),
    CORSARO_PLUGIN_GENERATE_TRACE_PTRS(corsaro_flowtuple),
    CORSARO_PLUGIN_GENERATE_MERGE_PTRS(corsaro_flowtuple),
    CORSARO_PLUGIN_GENERATE_TAIL

};

corsaro_plugin_t *corsaro_flowtuple_alloc(void) {
      return &corsaro_flowtuple_plugin;
}

static int flowtuple_to_avro(corsaro_logger_t *logger, avro_value_t *av,
        void *flowtuple) {
    struct corsaro_flowtuple *ft = (struct corsaro_flowtuple *)flowtuple;
    avro_value_t field;

    CORSARO_AVRO_SET_FIELD(long, av, field, 0, "time", "flowtuple",
            ft->interval_ts);
    CORSARO_AVRO_SET_FIELD(long, av, field, 1, "src_ip", "flowtuple",
            ft->src_ip);
    CORSARO_AVRO_SET_FIELD(long, av, field, 2, "dst_ip", "flowtuple",
            ft->dst_ip);
    CORSARO_AVRO_SET_FIELD(int, av, field, 3, "src_port", "flowtuple",
            ft->src_port);
    CORSARO_AVRO_SET_FIELD(int, av, field, 4, "dst_port", "flowtuple",
            ft->dst_port);
    CORSARO_AVRO_SET_FIELD(int, av, field, 5, "protocol", "flowtuple",
            ft->protocol);
    CORSARO_AVRO_SET_FIELD(int, av, field, 6, "ttl", "flowtuple",
            ft->ttl);
    CORSARO_AVRO_SET_FIELD(int, av, field, 7, "tcp_flags", "flowtuple",
            ft->tcp_flags);
    CORSARO_AVRO_SET_FIELD(int, av, field, 8, "ip_len", "flowtuple",
            ft->ip_len);
    CORSARO_AVRO_SET_FIELD(long, av, field, 9, "packet_cnt", "flowtuple",
            ft->packet_cnt);

    return 0;
}


/* TODO create more generic wrappers for decoding avro fields */
static inline int get_avro_long(avro_value_t *av, int64_t *avlong,
        const char *fieldname, corsaro_logger_t *logger) {

    avro_value_t field;

    if (avro_value_get_by_name(av, fieldname, &field, NULL)) {
        corsaro_log(logger,
                "unable to find a '%s' field in flowtuple Avro record.",
                fieldname);
        return -1;
    }

    if (avro_value_get_long(&field, avlong)) {
        corsaro_log(logger,
                "unable to extract '%s' field in flowtuple Avro record: %s",
                fieldname, avro_strerror());
        return -1;
    }

    return 0;
}

static inline int get_avro_int(avro_value_t *av, int32_t *avint,
        const char *fieldname, corsaro_logger_t *logger) {

    avro_value_t field;

    if (avro_value_get_by_name(av, fieldname, &field, NULL)) {
        corsaro_log(logger,
                "unable to find a '%s' field in flowtuple Avro record.",
                fieldname);
        return -1;
    }

    if (avro_value_get_int(&field, avint)) {
        corsaro_log(logger,
                "unable to extract '%s' field in flowtuple Avro record: %s",
                fieldname, avro_strerror());
        return -1;
    }

    return 0;
}

static struct corsaro_flowtuple *avro_to_flowtuple(corsaro_logger_t *logger,
        avro_value_t *av) {

    struct corsaro_flowtuple *ft = (struct corsaro_flowtuple *)malloc(
            sizeof(struct corsaro_flowtuple));

    int64_t avlong;
    int32_t avint;

    if (ft == NULL) {
        corsaro_log(logger,
                "unable to allocate memory for avro->flowtuple conversion.");
        return NULL;
    }

    /* TODO bounds checking on fields which are smaller than their
     * corresponding avro type (e.g. uint8_t values should be < 256).
     */

    if (get_avro_long(av, &avlong, "time", logger) < 0) {
        goto fail;
    }
    ft->interval_ts = (uint32_t)(avlong);

    if (get_avro_long(av, &avlong, "src_ip", logger) < 0) {
        goto fail;
    }
    ft->src_ip = (uint32_t)(avlong);

    if (get_avro_long(av, &avlong, "dst_ip", logger) < 0) {
        goto fail;
    }
    ft->dst_ip = (uint32_t)(avlong);

    if (get_avro_int(av, &avint, "src_port", logger) < 0) {
        goto fail;
    }
    ft->src_port = (uint16_t)(avint);

    if (get_avro_int(av, &avint, "dst_port", logger) < 0) {
        goto fail;
    }
    ft->dst_port = (uint16_t)(avint);

    if (get_avro_int(av, &avint, "protocol", logger) < 0) {
        goto fail;
    }
    ft->protocol = (uint8_t)(avint);

    if (get_avro_int(av, &avint, "ttl", logger) < 0) {
        goto fail;
    }
    ft->ttl = (uint8_t)(avint);

    if (get_avro_int(av, &avint, "tcp_flags", logger) < 0) {
        goto fail;
    }
    ft->tcp_flags = (uint8_t)(avint);

    if (get_avro_int(av, &avint, "ip_len", logger) < 0) {
        goto fail;
    }
    ft->ip_len = (uint16_t)(avint);

    if (get_avro_long(av, &avlong, "packet_cnt", logger) < 0) {
        goto fail;
    }
    ft->packet_cnt = (uint32_t)(avlong);

    return ft;

fail:
    free(ft);
    return NULL;


}


int corsaro_flowtuple_parse_config(corsaro_plugin_t *p, yaml_document_t *doc,
        yaml_node_t *options) {

    corsaro_flowtuple_config_t *conf;
    yaml_node_t *key, *value;
    yaml_node_pair_t *pair;

    conf = (corsaro_flowtuple_config_t *)malloc(
            sizeof(corsaro_flowtuple_config_t));
    if (conf == NULL) {
        /* OOM */
        return -1;
    }

    CORSARO_INIT_PLUGIN_PROC_OPTS(conf->basic);
    conf->sort_enabled = CORSARO_FLOWTUPLE_SORT_DEFAULT;

    if (options->type != YAML_MAPPING_NODE) {
        corsaro_log(p->logger,
                "Flowtuple plugin config should be a map.");
        free(conf);
        return -1;
    }

    for (pair = options->data.mapping.pairs.start;
            pair < options->data.mapping.pairs.top; pair ++) {

        key = yaml_document_get_node(doc, pair->key);
        value = yaml_document_get_node(doc, pair->value);

        /* TODO allow for custom log file? */

        /* TODO allow overriding of compress level, file mode etc. */

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "sorttuples") == 0) {
            if (strcmp((char *)value->data.scalar.value, "yes") == 0) {
                conf->sort_enabled = CORSARO_FLOWTUPLE_SORT_ENABLED;
            }
            if (strcmp((char *)value->data.scalar.value, "enabled") == 0) {
                conf->sort_enabled = CORSARO_FLOWTUPLE_SORT_ENABLED;
            }
            if (strcmp((char *)value->data.scalar.value, "on") == 0) {
                conf->sort_enabled = CORSARO_FLOWTUPLE_SORT_ENABLED;
            }

            if (strcmp((char *)value->data.scalar.value, "no") == 0) {
                conf->sort_enabled = CORSARO_FLOWTUPLE_SORT_DISABLED;
            }
            if (strcmp((char *)value->data.scalar.value, "disabled") == 0) {
                conf->sort_enabled = CORSARO_FLOWTUPLE_SORT_DISABLED;
            }
            if (strcmp((char *)value->data.scalar.value, "off") == 0) {
                conf->sort_enabled = CORSARO_FLOWTUPLE_SORT_DISABLED;
            }
        }

    }

    p->config = conf;
    return 0;

}

int corsaro_flowtuple_finalise_config(corsaro_plugin_t *p,
        corsaro_plugin_proc_options_t *stdopts) {

    corsaro_flowtuple_config_t *conf;

    /* Configure standard 'global' options for any options that
     * were not overridden by plugin-specific config.
     */
    conf = (corsaro_flowtuple_config_t *)(p->config);

    conf->basic.template = stdopts->template;
    conf->basic.monitorid = stdopts->monitorid;

    return 0;
}

/** Given a st hash, malloc and return a sorted array of pointers */
static int sort_hash(corsaro_logger_t *logger, kh_sixt_t *hash,
        struct corsaro_flowtuple ***sorted)
{
    khiter_t i;
    struct corsaro_flowtuple **ptr;

    if ((ptr = malloc(sizeof(struct corsaro_flowtuple *) * kh_size(hash))) == NULL) {
        corsaro_log(logger, "could not malloc array for sorted flowtuple keys");
        return -1;
    }
    *sorted = ptr;

    if (kh_size(hash) == 0) {
        /* no need to try and sort an empty hash */
        return 0;
    }

    for (i = kh_begin(hash); i != kh_end(hash); ++i) {
        if (kh_exist(hash, i)) {
            *ptr = kh_key(hash, i);
            ptr++;
        }
    }

    ks_introsort(sixt, kh_size(hash), *sorted);
    return 0;
}


void corsaro_flowtuple_destroy_self(corsaro_plugin_t *p) {
    if (p->config) {
        free(p->config);
    }
    p->config = NULL;
}

void *corsaro_flowtuple_init_processing(corsaro_plugin_t *p, int threadid) {

    struct corsaro_flowtuple_state_t *state;
    int i;

    state = (struct corsaro_flowtuple_state_t *)calloc(1,
            sizeof(struct corsaro_flowtuple_state_t));

    if (state == NULL) {
        /* OOM */
        return NULL;
    }

    state->last_interval_start = 0;
    state->threadid = threadid;

    state->st_hash = kh_init(sixt);

    return state;
}

int corsaro_flowtuple_halt_processing(corsaro_plugin_t *p, void *local) {

    struct corsaro_flowtuple_state_t *state;
    int i;

    state = (struct corsaro_flowtuple_state_t *)local;
    if (state == NULL) {
        return 0;
    }

    kh_destroy(sixt, state->st_hash);
    free(state);

    return 0;
}

char *corsaro_flowtuple_derive_output_name(corsaro_plugin_t *p,
        void *local, uint32_t timestamp, int threadid) {

    corsaro_flowtuple_config_t *conf;
    char *outname = NULL;

    conf = (corsaro_flowtuple_config_t *)(p->config);

    outname = corsaro_generate_avro_file_name(conf->basic.template, p->name,
            conf->basic.monitorid, timestamp, threadid);
    if (outname == NULL) {
        corsaro_log(p->logger,
                "failed to generate suitable filename for flowtuple output");
        return NULL;
    }
    return outname;

}

int corsaro_flowtuple_start_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_start) {

    corsaro_flowtuple_config_t *conf;
    struct corsaro_flowtuple_state_t *state;

    FLOWTUPLE_PROC_FUNC_START("corsaro_flowtuple_start_interval", -1);

    state->last_interval_start = int_start->time;
    return 0;
}

void *corsaro_flowtuple_end_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_end) {

    corsaro_flowtuple_config_t *conf;
    struct corsaro_flowtuple_state_t *state;
    kh_sixt_t *h;

    FLOWTUPLE_PROC_FUNC_START("corsaro_flowtuple_end_interval", NULL);
    h = state->st_hash;

    /* Replace the hash map with an empty one -- the merging process
     * will free up everything associated with the old hash map. */
    state->st_hash = kh_init(sixt);
    return h;
}

/** Either add the given flowtuple to the hash, or increment the current count
 */
int corsaro_flowtuple_add_inc(corsaro_logger_t *logger,
        void *h, struct corsaro_flowtuple *t, uint32_t increment)
{
  kh_sixt_t *hash = (kh_sixt_t *)h;
  int khret;
  khiter_t khiter;
  struct corsaro_flowtuple *new_6t = NULL;

  assert(hash != NULL);

  /* check if this is in the hash already */
  if ((khiter = kh_get(sixt, hash, t)) == kh_end(hash)) {
    /* create a new tuple struct */
    if ((new_6t = malloc(sizeof(struct corsaro_flowtuple))) == NULL) {
      corsaro_log(logger, "malloc of flowtuple failed");
      return -1;
    }

    /* fill it */
    memcpy(new_6t, t, sizeof(struct corsaro_flowtuple));

    /* add it to the hash */
    khiter = kh_put(sixt, hash, new_6t, &khret);
    /* set the count to one */
    /*kh_value(hash, khiter) = increment;*/
    new_6t->packet_cnt = increment;
  } else {
    /* simply increment the existing one */
    /*kh_value(hash, khiter)+=increment;*/
    new_6t = kh_key(hash, khiter);

    /* will this cause a wrap? */
    assert((UINT32_MAX - new_6t->packet_cnt) > increment);

    new_6t->packet_cnt = (new_6t->packet_cnt) + increment;
  }
  return 0;
}


int corsaro_flowtuple_process_packet(corsaro_plugin_t *p, void *local,
        libtrace_packet_t *packet, corsaro_packet_state_t *pstate) {
    libtrace_ip_t *ip_hdr = NULL;
    libtrace_icmp_t *icmp_hdr = NULL;
    libtrace_tcp_t *tcp_hdr = NULL;
    struct corsaro_flowtuple t;

    corsaro_flowtuple_config_t *conf;
    struct corsaro_flowtuple_state_t *state;

    FLOWTUPLE_PROC_FUNC_START("corsaro_flowtuple_process_packet", -1);

    if ((pstate->flags & CORSARO_PACKET_STATE_FLAG_IGNORE) != 0) {
        return 0;
    }

    if ((ip_hdr = trace_get_ip(packet)) == NULL) {
        /* non-ipv4 packet */
        return 0;
    }

    t.ip_len = ntohs(ip_hdr->ip_len);
    t.src_ip = ntohl(ip_hdr->ip_src.s_addr);
    t.dst_ip = ntohl(ip_hdr->ip_dst.s_addr);
    t.interval_ts = state->last_interval_start;

    t.protocol = ip_hdr->ip_p;
    t.tcp_flags = 0; /* in case we don't find a tcp header */

    t.ttl = ip_hdr->ip_ttl;

    if (ip_hdr->ip_p == TRACE_IPPROTO_ICMP &&
            (icmp_hdr = trace_get_icmp(packet)) != NULL) {
        t.src_port = icmp_hdr->type;
        t.dst_port = icmp_hdr->code;
    } else {
        if (ip_hdr->ip_p == TRACE_IPPROTO_TCP &&
                (tcp_hdr = trace_get_tcp(packet)) != NULL) {
            /* we have ignore the NS flag because it doesn't fit in
               an 8 bit field. blame alberto (ak - 2/2/12) */
            t.tcp_flags =
                ((tcp_hdr->cwr << 7) | (tcp_hdr->ece << 6) | (tcp_hdr->urg << 5) |
                 (tcp_hdr->ack << 4) | (tcp_hdr->psh << 3) | (tcp_hdr->rst << 2) |
                 (tcp_hdr->syn << 1) | (tcp_hdr->fin << 0));
        }
        t.src_port = trace_get_source_port(packet);
        t.dst_port = trace_get_destination_port(packet);
    }

    if (corsaro_flowtuple_add_inc(p->logger, state->st_hash, &t, 1) != 0) {
        corsaro_log(p->logger, "could not increment value for flowtuple");
        return -1;
    }
    return 0;
}

void *corsaro_flowtuple_init_merging(corsaro_plugin_t *p, int sources) {
    struct corsaro_flowtuple_merge_state_t *m;

    m = (struct corsaro_flowtuple_merge_state_t *)calloc(1,
            sizeof(struct corsaro_flowtuple_merge_state_t));

    m->writer = corsaro_create_avro_writer(p->logger,
            FLOWTUPLE_RESULT_SCHEMA);

    if (!m->writer) {
        corsaro_log(p->logger,
                "error while creating avro writer for flowtuple plugin!");
        free(m);
        return NULL;
    }

    return m;
}

int corsaro_flowtuple_halt_merging(corsaro_plugin_t *p, void *local) {

    struct corsaro_flowtuple_merge_state_t *m;

    m = (struct corsaro_flowtuple_merge_state_t *)local;
    if (m == NULL) {
        return 0;
    }

    if (m->writer) {
        corsaro_destroy_avro_writer(m->writer);
    }
    free(m);
    return 0;
}

static int choose_next_merge_ft(corsaro_plugin_t *p,
        corsaro_flowtuple_iterator_t *inputs, int inpcount) {

    corsaro_flowtuple_config_t *conf;
    int candind = -1;
    int i;

    conf = (corsaro_flowtuple_config_t *)(p->config);

    for (i = 0; i < inpcount; i++) {
        if (inputs[i].state == CORSARO_RESULT_TYPE_EOF) {
            continue;
        }

        while (inputs[i].nextft == NULL) {
            if (inputs[i].sorted_keys == NULL) {
                if (inputs[i].khiter == kh_end(inputs[i].hmap)) {
                    inputs[i].state = CORSARO_RESULT_TYPE_EOF;
                    break;
                }

                if (kh_exist(inputs[i].hmap, inputs[i].khiter)) {
                    inputs[i].nextft = (struct corsaro_flowtuple *)kh_key(
                            inputs[i].hmap, inputs[i].khiter);
                }
                inputs[i].khiter ++;
            } else {
                if (inputs[i].sortiter == kh_size(inputs[i].hmap)) {
                    inputs[i].state = CORSARO_RESULT_TYPE_EOF;
                    break;
                }
                inputs[i].nextft = inputs[i].sorted_keys[inputs[i].sortiter];
                inputs[i].sortiter ++;
            }
        }


        if (inputs[i].state == CORSARO_RESULT_TYPE_EOF) {
            continue;
        }

        if (candind == -1) {
            candind = i;
            continue;
        }

        if (conf->sort_enabled == CORSARO_FLOWTUPLE_SORT_DISABLED) {
            /* order doesn't matter, just pick the first usable result */
            break;
        }

        if (corsaro_flowtuple_lt(inputs[i].nextft, inputs[candind].nextft)) {
            candind = i;
        }
    }

    return candind;
}


int corsaro_flowtuple_merge_interval_results(corsaro_plugin_t *p, void *local,
        void **tomerge, corsaro_fin_interval_t *fin) {

    struct corsaro_flowtuple_merge_state_t *m;
    corsaro_flowtuple_config_t *conf;
    corsaro_flowtuple_iterator_t *inputs;
    int i, candind;
    avro_value_t *avrores;

    conf = (corsaro_flowtuple_config_t *)(p->config);
    m = (struct corsaro_flowtuple_merge_state_t *)local;
    if (m == NULL || m->writer == NULL) {
        return -1;
    }

    /* First step, open an output file if we need one */
    if (!corsaro_is_avro_writer_active(m->writer)) {
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

    inputs = (corsaro_flowtuple_iterator_t *)calloc(fin->threads_ended,
            sizeof(corsaro_flowtuple_iterator_t));

    for (i = 0; i < fin->threads_ended; i++) {
        inputs[i].hmap = (kh_sixt_t *)(tomerge[i]);
        inputs[i].khiter = kh_begin(inputs[i].hmap);
        inputs[i].nextft = NULL;
        inputs[i].state = CORSARO_RESULT_TYPE_DATA;
        if (conf->sort_enabled == CORSARO_FLOWTUPLE_SORT_ENABLED) {
            if (sort_hash(p->logger, inputs[i].hmap,
                    &(inputs[i].sorted_keys)) != 0) {
                corsaro_log(p->logger,
                        "could not sort flowtuple keys for input %d", i);
                inputs[i].sorted_keys = NULL;
                inputs[i].sortiter = -1;
            } else {
                inputs[i].sortiter = 0;
            }
        } else {
            inputs[i].sorted_keys = NULL;
            inputs[i].sortiter = -1;
        }
    }

    do {
        candind = choose_next_merge_ft(p, inputs, fin->threads_ended);
        if (candind == -1) {
            break;
        }

        avrores = corsaro_populate_avro_item(m->writer, inputs[candind].nextft,
                flowtuple_to_avro);
        if (avrores == NULL) {
            corsaro_log(p->logger,
                    "error while converting flowtuple to avro format, skipping.");
        } else {
            if (corsaro_append_avro_writer(m->writer, avrores) == -1) {

            }
        }

        free(inputs[candind].nextft);
        inputs[candind].nextft = NULL;
    } while (candind != -1);

    /* All inputs are exhausted */
    for (i = 0; i < fin->threads_ended; i++) {
        kh_destroy(sixt, inputs[i].hmap);
        free(inputs[i].sorted_keys);
    }
    free(inputs);

    /* Don't close the file -- rotate_output will deal with that */

    return 0;
}

int corsaro_flowtuple_rotate_output(corsaro_plugin_t *p, void *local) {

    struct corsaro_flowtuple_merge_state_t *m;
    m = (struct corsaro_flowtuple_merge_state_t *)local;
    if (m == NULL || m->writer == NULL) {
        return -1;
    }

    return corsaro_close_avro_writer(m->writer);
}

/*
 * Hashes the flowtuple based on the following table
 *
 *         --------------------------------
 *         |           SRC_IP * 59        |
 *         --------------------------------
 *         |            DST_IP            |
 *         --------------------------------
 *         | SRC_PORT <<16 |   DST_PORT   |
 *         --------------------------------
 *         |  TTL  |TCP_FLG|PROTO|  LEN   |
 *         --------------------------------
 */
khint32_t corsaro_flowtuple_hash_func(struct corsaro_flowtuple *ft)
{
  khint32_t h = (khint32_t)ft->src_ip * 59;
  CORSARO_FLOWTUPLE_SHIFT_AND_XOR(ft->dst_ip);
  CORSARO_FLOWTUPLE_SHIFT_AND_XOR(ft->src_port << 16);
  CORSARO_FLOWTUPLE_SHIFT_AND_XOR(ft->dst_port);
  CORSARO_FLOWTUPLE_SHIFT_AND_XOR((ft->ttl << 24) | (ft->tcp_flags << 16));
  CORSARO_FLOWTUPLE_SHIFT_AND_XOR((ft->protocol << 8) | (ft->ip_len));
  return h;
}



// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
