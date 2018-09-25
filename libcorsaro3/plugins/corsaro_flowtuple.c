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

#include "pqueue.h"
#include "libcorsaro3.h"
#include "libcorsaro3_plugin.h"
#include "libcorsaro3_avro.h"
#include "corsaro_flowtuple.h"
#include "utils.h"

/* This magic number is a legacy number from when we used to call it the
   'sixtuple' */
/** The magic number for this plugin when not using /8 opts - "SIXU" */
#define CORSARO_FLOWTUPLE_MAGIC 0x53495855

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

/** Holds the state for an instance of this plugin */
struct corsaro_flowtuple_state_t {
    /** Array of hash tables, one for each corsaro_flowtuple_class_type_t */
    khash_t(sixt) * st_hash;

    /** Timestamp of the start of the current interval */
    uint32_t last_interval_start;

    /** The ID of the thread running this plugin instance */
    int threadid;

    /** Custom memory allocator for doing efficient management of flowtuple
     *  records.
     */
    corsaro_memhandler_t *fthandler;

    uint32_t pkt_cnt;
};

typedef struct corsaro_flowtuple_iterator {
    corsaro_memhandler_t *handler;
    khiter_t khiter;
    int sortiter;
    kh_sixt_t *hmap;
    struct corsaro_flowtuple *nextft;
    corsaro_result_type_t state;
    struct corsaro_flowtuple **sorted_keys;
} corsaro_flowtuple_iterator_t;

typedef struct corsaro_flowtuple_interim {
    corsaro_memhandler_t *handler;
    kh_sixt_t *hmap;
    struct corsaro_flowtuple **sorted_keys;
    corsaro_logger_t *logger;
    pthread_mutex_t mutex;
    pthread_t tid;
    int usable;
} corsaro_flowtuple_interim_t;

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
      {\"name\": \"packet_cnt\", \"type\": \"long\"}, \
      {\"name\": \"maxmind_continent\", \"type\": \"string\"}, \
      {\"name\": \"maxmind_country\", \"type\": \"string\"}, \
      {\"name\": \"netacq_continent\", \"type\": \"string\"}, \
      {\"name\": \"netacq_country\", \"type\": \"string\"}, \
      {\"name\": \"prefix2asn\", \"type\": \"long\"}]}";

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

static int ft_cmp_pri(void *next, void *curr) {

    struct corsaro_flowtuple *prevft, *nextft;
    int res = 0;

    prevft = (struct corsaro_flowtuple *)curr;
    nextft = (struct corsaro_flowtuple *)next;
    res = corsaro_flowtuple_lt(nextft, prevft);

    if (res == 0) {
        return 1;
    }
    return 0;
}

static size_t ft_get_pos(void *a) {
    struct corsaro_flowtuple *ft = (struct corsaro_flowtuple *)a;
    return ft->pqueue_pos;
}

static void ft_set_pos(void *a, size_t pos) {
    struct corsaro_flowtuple *ft = (struct corsaro_flowtuple *)a;
    ft->pqueue_pos = pos;
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


    state->fthandler = (corsaro_memhandler_t *)malloc(
            sizeof(corsaro_memhandler_t));
    init_corsaro_memhandler(p->logger, state->fthandler,
            sizeof(struct corsaro_flowtuple), 1000000);

    state->st_hash = kh_init(sixt);
    kh_resize_sixt(state->st_hash, 1000000);

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
    destroy_corsaro_memhandler(state->fthandler);
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
    state->pkt_cnt = 0;
    return 0;
}

static void *sort_job(void *tdata) {
    corsaro_flowtuple_interim_t *interim = (corsaro_flowtuple_interim_t *)tdata;

    if (sort_hash(interim->logger, interim->hmap, &(interim->sorted_keys)) != 0)
    {
        corsaro_log(interim->logger, "unable to sort flowtuple keys");
        interim->sorted_keys = NULL;
        pthread_mutex_lock(&(interim->mutex));
        interim->usable = -1;
    } else {
        pthread_mutex_lock(&(interim->mutex));
        interim->usable = 1;
    }
    pthread_mutex_unlock(&(interim->mutex));
    pthread_exit(NULL);
}

void *corsaro_flowtuple_end_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_end) {

    corsaro_flowtuple_config_t *conf;
    struct corsaro_flowtuple_state_t *state;
    corsaro_flowtuple_interim_t *interim = NULL;
    kh_sixt_t *h;

    FLOWTUPLE_PROC_FUNC_START("corsaro_flowtuple_end_interval", NULL);

    interim = (corsaro_flowtuple_interim_t *)calloc(1,
            sizeof(corsaro_flowtuple_interim_t));
    interim->handler = state->fthandler;
    add_corsaro_memhandler_user(state->fthandler);
    interim->hmap = state->st_hash;
    interim->usable = 0;
    interim->sorted_keys = NULL;
    interim->logger = p->logger;

    pthread_mutex_init(&(interim->mutex), NULL);

    if (conf->sort_enabled == CORSARO_FLOWTUPLE_SORT_ENABLED) {
        pthread_create(&(interim->tid), NULL, sort_job, interim);
    } else {
        interim->usable = 1;
    }

    /* Replace the hash map with an empty one -- the merging process
     * will free up everything associated with the old hash map. */
    state->st_hash = kh_init(sixt);
    return interim;
}

/** Either add the given flowtuple to the hash, or increment the current count
 */
static int corsaro_flowtuple_add_inc(corsaro_logger_t *logger,
        struct corsaro_flowtuple_state_t *state, struct corsaro_flowtuple *t,
        uint32_t increment) {
  kh_sixt_t *hash = state->st_hash;
  int khret;
  khiter_t khiter;
  struct corsaro_flowtuple *new_6t = NULL;
  corsaro_memsource_t *memsrc = NULL;

  assert(hash != NULL);

  /* check if this is in the hash already */
  if ((khiter = kh_get(sixt, hash, t)) == kh_end(hash)) {
    /* create a new tuple struct */
    new_6t = (struct corsaro_flowtuple *)
            get_corsaro_memhandler_item(state->fthandler, &memsrc);


    if (new_6t == NULL) {
      corsaro_log(logger, "malloc of flowtuple failed");
      return -1;
    }

    /* fill it */
    memcpy(new_6t, t, sizeof(struct corsaro_flowtuple));
    new_6t->memsrc = memsrc;

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
        libtrace_packet_t *packet, corsaro_packet_tags_t *tags) {
    libtrace_ip_t *ip_hdr = NULL;
    libtrace_icmp_t *icmp_hdr = NULL;
    libtrace_tcp_t *tcp_hdr = NULL;
    struct corsaro_flowtuple t;

    corsaro_flowtuple_config_t *conf;
    struct corsaro_flowtuple_state_t *state;

    FLOWTUPLE_PROC_FUNC_START("corsaro_flowtuple_process_packet", -1);

    if ((ip_hdr = trace_get_ip(packet)) == NULL) {
        /* non-ipv4 packet */
        return 0;
    }

    memset(&t, 0, sizeof(struct corsaro_flowtuple));
    t.ip_len = ntohs(ip_hdr->ip_len);
    t.src_ip = ntohl(ip_hdr->ip_src.s_addr);
    t.dst_ip = ntohl(ip_hdr->ip_dst.s_addr);
    t.interval_ts = state->last_interval_start;

    t.protocol = ip_hdr->ip_p;
    t.tcp_flags = 0; /* in case we don't find a tcp header */

    t.ttl = ip_hdr->ip_ttl;
    t.src_port = tags->src_port;
    t.dst_port = tags->dest_port;

    if (ip_hdr->ip_p == TRACE_IPPROTO_TCP &&
                (tcp_hdr = trace_get_tcp(packet)) != NULL) {
        /* we have ignore the NS flag because it doesn't fit in
           an 8 bit field. blame alberto (ak - 2/2/12) */
        t.tcp_flags =
            ((tcp_hdr->cwr << 7) | (tcp_hdr->ece << 6) | (tcp_hdr->urg << 5) |
             (tcp_hdr->ack << 4) | (tcp_hdr->psh << 3) | (tcp_hdr->rst << 2) |
             (tcp_hdr->syn << 1) | (tcp_hdr->fin << 0));
    }

    if (tags && tags->providers_used & (1 << IPMETA_PROVIDER_MAXMIND)) {
        t.maxmind_continent = tags->maxmind_continent;
        t.maxmind_country = tags->maxmind_country;
    }

    if (tags && tags->providers_used & (1 << IPMETA_PROVIDER_NETACQ_EDGE)) {
        t.netacq_continent = tags->netacq_continent;
        t.netacq_country = tags->netacq_country;
    }

    if (tags && tags->providers_used & (1 << IPMETA_PROVIDER_PFX2AS)) {
        t.prefixasn = tags->prefixasn;
    }

    if (tags) {
        t.tagproviders = tags->providers_used;
    } else {
        t.tagproviders = 0;
    }

    if (corsaro_flowtuple_add_inc(p->logger, state, &t, 1) != 0) {
        corsaro_log(p->logger, "could not increment value for flowtuple");
        return -1;
    }
    state->pkt_cnt ++;
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

static inline void _write_next_merged_ft(struct corsaro_flowtuple *nextft,
        corsaro_avro_writer_t *writer, corsaro_logger_t *logger) {

    char valspace[128];
    uint32_t zero = 0;

    if (corsaro_start_avro_encoding(writer) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(nextft->interval_ts), sizeof(nextft->interval_ts)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(nextft->src_ip), sizeof(nextft->src_ip)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(nextft->dst_ip), sizeof(nextft->dst_ip)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(nextft->src_port), sizeof(nextft->src_port)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(nextft->dst_port), sizeof(nextft->dst_port)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(nextft->protocol), sizeof(nextft->protocol)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(nextft->ttl), sizeof(nextft->ttl)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(nextft->tcp_flags), sizeof(nextft->tcp_flags)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(nextft->ip_len), sizeof(nextft->ip_len)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(nextft->packet_cnt), sizeof(nextft->packet_cnt)) < 0) {
        return;
    }

    if (nextft->tagproviders & (1 << IPMETA_PROVIDER_MAXMIND)) {
        snprintf(valspace, 128, "%c%c", (int)(nextft->maxmind_continent & 0xff),
                (int)((nextft->maxmind_continent >> 8) & 0xff));

        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                    valspace, strlen(valspace)) < 0) {
            return;
        }

        snprintf(valspace, 128, "%c%c", (int)(nextft->maxmind_country & 0xff),
                (int)((nextft->maxmind_country >> 8) & 0xff));

        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                    valspace, strlen(valspace)) < 0) {
            return;
        }

    } else {
        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                "??", 2) < 0) {
            return;
        }
        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                "??", 2) < 0) {
            return;
        }
    }


    if (nextft->tagproviders & (1 << IPMETA_PROVIDER_NETACQ_EDGE)) {
        snprintf(valspace, 128, "%c%c", (int)(nextft->netacq_continent & 0xff),
                (int)((nextft->netacq_continent >> 8) & 0xff));

        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                    valspace, strlen(valspace)) < 0) {
            return;
        }

        snprintf(valspace, 128, "%c%c", (int)(nextft->netacq_country & 0xff),
                (int)((nextft->netacq_country >> 8) & 0xff));

        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                    valspace, strlen(valspace)) < 0) {
            return;
        }

    } else {
        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                "??", 2) < 0) {
            return;
        }
        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                "??", 2) < 0) {
            return;
        }
    }

    if (nextft->tagproviders & (1 << IPMETA_PROVIDER_PFX2AS)) {
        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                    &(nextft->prefixasn), sizeof(nextft->prefixasn)) < 0) {
            return;
        }

    } else {
        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                    &(zero), sizeof(zero)) < 0) {
            return;
        }
    }

    if (corsaro_append_avro_writer(writer, NULL) < 0) {
        return;
    }

}

static void merge_sorted_inputs(corsaro_plugin_t *p,
        struct corsaro_flowtuple_merge_state_t *m,
        corsaro_flowtuple_iterator_t *inputs, corsaro_fin_interval_t *fin) {

    int i;
    struct corsaro_flowtuple *nextft, *prevft;
    corsaro_memhandler_t *handler;
    pqueue_t *pq;
    uint64_t count = 0, exptotal = 0, combines = 0;

    pq = pqueue_init(fin->threads_ended, ft_cmp_pri, ft_get_pos, ft_set_pos);

    if (!pq) {
        corsaro_log(p->logger, "error while creating priority queue to sort flowtuple results.");
        return;
    }

    for (i = 0; i < fin->threads_ended; i++) {
        exptotal += kh_size(inputs[i].hmap);
        while (inputs[i].sortiter < kh_size(inputs[i].hmap)) {
            nextft = inputs[i].sorted_keys[inputs[i].sortiter];
            inputs[i].sortiter ++;

            nextft->from = (void *) &(inputs[i]);
            nextft->fromind = i;
            pqueue_insert(pq, nextft);
            break;
        }
    }

    prevft = NULL;
    while ((nextft = (struct corsaro_flowtuple *)(pqueue_pop(pq)))) {
        corsaro_flowtuple_iterator_t *ftsrc;
        struct corsaro_flowtuple *toinsert;

        ftsrc = (corsaro_flowtuple_iterator_t *)(nextft->from);

        if (prevft && !corsaro_flowtuple_hash_equal(prevft, nextft)) {
            _write_next_merged_ft(prevft,  m->writer, p->logger);
            release_corsaro_memhandler_item(handler, prevft->memsrc);
        } else if (prevft) {
            combines ++;
            nextft->packet_cnt += prevft->packet_cnt;
            release_corsaro_memhandler_item(handler, prevft->memsrc);
        }

        count ++;

        prevft = nextft;
        handler = ftsrc->handler;
        if (ftsrc->sortiter == kh_size(ftsrc->hmap)) {
            continue;
        }

        toinsert = ftsrc->sorted_keys[ftsrc->sortiter];
        ftsrc->sortiter ++;
        toinsert->from = (void *)ftsrc;
        toinsert->fromind = prevft->fromind;
        pqueue_insert(pq, toinsert);


    }

    if (prevft) {
        _write_next_merged_ft(prevft,  m->writer, p->logger);
        release_corsaro_memhandler_item(handler, prevft->memsrc);
    }

}


static void merge_unsorted_inputs(corsaro_plugin_t *p,
        struct corsaro_flowtuple_merge_state_t *m,
        corsaro_flowtuple_iterator_t *inputs, corsaro_fin_interval_t *fin) {

    int i;
    khiter_t khiter;
    struct corsaro_flowtuple *nextft;

    uint64_t count = 0;

    for (i = 0; i < fin->threads_ended; i++) {
        for (khiter = kh_begin(inputs[i].hmap);
                khiter != kh_end(inputs[i].hmap); ++khiter) {

            if (!kh_exist(inputs[i].hmap, khiter)) {
                continue;
            }

            nextft = (struct corsaro_flowtuple *)kh_key(inputs[i].hmap,
                    khiter);

            _write_next_merged_ft(nextft, m->writer, p->logger);
            release_corsaro_memhandler_item(inputs[i].handler,
                        nextft->memsrc);
            count ++;
        }
    }
}

int corsaro_flowtuple_merge_interval_results(corsaro_plugin_t *p, void *local,
        void **tomerge, corsaro_fin_interval_t *fin) {

    struct corsaro_flowtuple_merge_state_t *m;
    corsaro_flowtuple_config_t *conf;
    corsaro_flowtuple_iterator_t *inputs;
    int i, candind;
    int inputsready;

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

    if (conf->sort_enabled == CORSARO_FLOWTUPLE_SORT_ENABLED) {
        corsaro_log(p->logger, "waiting on flowtuple sort jobs to finish");
    }
    inputs = (corsaro_flowtuple_iterator_t *)calloc(fin->threads_ended,
            sizeof(corsaro_flowtuple_iterator_t));

    inputsready = 0;
    while (inputsready < fin->threads_ended) {
        for (i = 0; i < fin->threads_ended; i++) {
            corsaro_flowtuple_interim_t *interim;

            if (inputs[i].hmap != NULL) {
                continue;
            }

            interim = (corsaro_flowtuple_interim_t *)(tomerge[i]);

            if (pthread_mutex_trylock(&(interim->mutex)) == 0) {
                if (interim->usable == 0) {
                    pthread_mutex_unlock(&(interim->mutex));
                    continue;
                }
                if (interim->usable < 0) {
                    corsaro_log(p->logger,
                            "flowtuple sort failed for input %d\n", i);
                }
                inputsready ++;

                inputs[i].hmap = interim->hmap;
                inputs[i].handler = interim->handler;
                inputs[i].khiter = kh_begin(inputs[i].hmap);
                inputs[i].nextft = NULL;
                if (interim->usable == 1) {
                    inputs[i].state = CORSARO_RESULT_TYPE_DATA;
                } else {
                    inputs[i].state = CORSARO_RESULT_TYPE_EOF;
                }
                if (conf->sort_enabled == CORSARO_FLOWTUPLE_SORT_ENABLED) {
                    inputs[i].sorted_keys = interim->sorted_keys;
                    inputs[i].sortiter = 0;
                } else {
                    inputs[i].sorted_keys = NULL;
                    inputs[i].sortiter = -1;
                }

                pthread_join(interim->tid, NULL);
                pthread_mutex_unlock(&(interim->mutex));
            }
        }

        if (inputsready < fin->threads_ended) {
            usleep(100);
        }
    }

    if (conf->sort_enabled == CORSARO_FLOWTUPLE_SORT_ENABLED) {
        corsaro_log(p->logger, "flowtuple sorting is complete, now merging");
        merge_sorted_inputs(p, m, inputs, fin);
    } else {
        merge_unsorted_inputs(p, m, inputs, fin);
    }

    /* All inputs are exhausted */
    for (i = 0; i < fin->threads_ended; i++) {
        corsaro_flowtuple_interim_t *interim;

        kh_destroy(sixt, inputs[i].hmap);
        if (inputs[i].sorted_keys) {
            free(inputs[i].sorted_keys);
        }
        destroy_corsaro_memhandler(inputs[i].handler);

        interim = (corsaro_flowtuple_interim_t *)(tomerge[i]);

        pthread_mutex_destroy(&(interim->mutex));
        free(tomerge[i]);
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
