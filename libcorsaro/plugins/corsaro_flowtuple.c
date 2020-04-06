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
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,
 * EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED
 * HEREUNDER IS ON AN “AS IS” BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO
 * OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 */

#include "config.h"

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
#include <Judy.h>
#include <zmq.h>

#include <librdkafka/rdkafka.h>

#include "pqueue.h"
#include "libcorsaro.h"
#include "libcorsaro_plugin.h"
#include "libcorsaro_common.h"
#include "libcorsaro_avro.h"
#include "libcorsaro_filtering.h"
#include "corsaro_flowtuple.h"
#include "utils.h"

/* This magic number is a legacy number from when we used to call it the
   'sixtuple' */
/** The magic number for this plugin when not using /8 opts - "SIXU" */
#define CORSARO_FLOWTUPLE_MAGIC 0x53495855

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
    Pvoid_t  st_hash;

    /** Timestamp of the start of the current interval */
    uint32_t last_interval_start;

    /** The ID of the thread running this plugin instance */
    int threadid;

    /** Custom memory allocator for doing efficient management of flowtuple
     *  records.
     */
    corsaro_memhandler_t *fthandler;

    uint32_t pkt_cnt;

    Pvoid_t keysort_levelone;

};

enum {
    CORSARO_FT_MSG_STOP,
    CORSARO_FT_MSG_ROTATE,
    CORSARO_FT_MSG_MERGE_SORTED,
    CORSARO_FT_MSG_MERGE_UNSORTED,
};

/** Enum describing the different compression methods we support for avro
 *  output.
 */
enum {
    CORSARO_AVRO_OUTPUT_NONE,       /**<< Do not write avro output */
    CORSARO_AVRO_OUTPUT_DEFLATE,    /**<< Write gzipped avro output */
    CORSARO_AVRO_OUTPUT_SNAPPY      /**<< Write snappy-compressed avro output */
};

typedef struct corsaro_ft_merge_msg {
    uint8_t dest;
    uint8_t type;
    void *content;
    uint32_t interval_ts;
    uint8_t input_source;
} PACKED corsaro_ft_write_msg_t;

typedef struct corsaro_flowtuple_interim {
    Pvoid_t hmap;
    uint64_t hsize;
    Pvoid_t sorted_keys;
    corsaro_logger_t *logger;
    pthread_mutex_t mutex;
    pthread_t tid;
    int usable;
} corsaro_flowtuple_interim_t;

typedef struct corsaro_flowtuple_iterator {
    corsaro_memhandler_t *handler;
    int sortiter;
    uint64_t hsize;
    Pvoid_t hmap;
    struct corsaro_flowtuple *nextft;
    Word_t sortindex_top;
    Word_t sortindex_bot;
    corsaro_result_type_t state;

    Pvoid_t sorted_keys;
    Pvoid_t current_subkeys;

    corsaro_flowtuple_interim_t *parent;
} corsaro_flowtuple_iterator_t;

/** Configuration options for publishing via kafka */
typedef struct corsaro_ft_kafka_options {
    /** The broker(s) to connect to */
    char *brokeruri;

    /** A custom string to prepend to the topic name */
    char *topicprefix;

    /** Number of messages to send in a single batch */
    int batchsize;

    /** Send an incomplete batch after this number of milliseconds */
    int lingerms;

    /** Publish this number of flows (per 10,000 flows). */
    uint16_t sampling;

} corsaro_ft_kafka_options_t;

/** Parameters used to determine which kafka partition a flow should be
 *  published to.
 */
typedef struct corsaro_ft_kafka_partkey {
    uint32_t ts;        /**<< The interval that the flow was observed in */
    uint32_t hash_val;  /**<< The hash value of the flow */
} corsaro_ft_kafka_partkey_t;


/** State for a single flowtuple merging worker thread */
typedef struct corsaro_flowtuple_merger {
    /** The pthread identifier for this merging worker thread */
    pthread_t tid;

    /** The internal identifier for this merging worker thread */
    uint8_t thread_num;

    /** A hash map of corsaro avro writers, keyed by the ids of the
     *  processing threads. If there are less merging threads than
     *  processing threads, a merging thread will have to manage
     *  multiple writers -- one for each interim file that the merger
     *  is responsible for.
     */
    Pvoid_t writers;

    /** A kafka instance for publishing flowtuple records */
    rd_kafka_t *rdk;
    /** A kafka topic that flowtuple records can be published to */
    rd_kafka_topic_t *rdktopic;

    /** A zeromq socket for receiving flowtuple records from the processing
     *  threads.
     */
    void *inqueue;

    /** A corsaro logger instance for reporting errors, messages */
    corsaro_logger_t *logger;

    /** The standard plugin configuration options, provided by corsarotrace */
    corsaro_plugin_proc_options_t *baseconf;
    /** The number of merging worker threads being used by this plugin */
    uint8_t maxmergeworkers;
    /** The compression method to use when writing avro output */
    uint8_t avrooutput;
    /** The kafka configuration options for this plugin */
    corsaro_ft_kafka_options_t *kafkaopts;

    /** A buffer for constructing messages to publish to kafka */
    uint8_t *buf;

    /** The current write pointer for the kafka message buffer */
    uint8_t *writeptr;

    /** The partitioning key data for the current kafka message */
    corsaro_ft_kafka_partkey_t partkey;

} corsaro_flowtuple_merger_t;

struct corsaro_flowtuple_merge_state_t {
    corsaro_flowtuple_merger_t *writerthreads;
    uint8_t nextworker;
    uint8_t maxworkers;
    void *pubqueue;
};

typedef struct corsaro_flowtuple_config {
    corsaro_plugin_proc_options_t basic;
    corsaro_flowtuple_sort_t sort_enabled;
    void *zmq_ctxt;
    uint8_t maxmergeworkers;
    uint8_t avrooutput;
    corsaro_ft_kafka_options_t kafkaopts;
} corsaro_flowtuple_config_t;

/** The name of this plugin */
#define PLUGIN_NAME "flowtuple"

#define CORSARO_FT_INTERNAL_QUEUE "inproc://flowtuplemergejobs"

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

    /* Default config settings: avro using deflate, no kafka output */
    CORSARO_INIT_PLUGIN_PROC_OPTS(conf->basic);
    conf->sort_enabled = CORSARO_FLOWTUPLE_SORT_DEFAULT;
    conf->maxmergeworkers = 4;
    conf->avrooutput = CORSARO_AVRO_OUTPUT_DEFLATE;
    conf->kafkaopts.brokeruri = NULL;
    conf->kafkaopts.topicprefix = NULL;
    conf->kafkaopts.lingerms = 500;
    conf->kafkaopts.batchsize = 50;
    conf->kafkaopts.sampling = 10000;

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

            uint8_t opt = 0;

            if (parse_onoff_option(p->logger, (char *)value->data.scalar.value,
                    &(opt), "sorttuples") == 0) {

                if (opt == 1) {
                    conf->sort_enabled = CORSARO_FLOWTUPLE_SORT_ENABLED;
                } else {
                    conf->sort_enabled = CORSARO_FLOWTUPLE_SORT_DISABLED;
                }
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "avrooutput") == 0) {

            if (strcasecmp((char *)value->data.scalar.value, "none") == 0) {
                conf->avrooutput = CORSARO_AVRO_OUTPUT_NONE;
            } else if (strcasecmp((char *)value->data.scalar.value, "deflate")
                    == 0) {
                conf->avrooutput = CORSARO_AVRO_OUTPUT_DEFLATE;
            } else if (strcasecmp((char *)value->data.scalar.value, "snappy")
                    == 0) {
                conf->avrooutput = CORSARO_AVRO_OUTPUT_SNAPPY;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value,
                        "mergethreads") == 0) {
            conf->maxmergeworkers = strtoul((char *)value->data.scalar.value,
                    NULL, 10);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value,
                        "kafkabatchsize") == 0) {
            conf->kafkaopts.batchsize = strtoul((char *)value->data.scalar.value,
                    NULL, 10);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value,
                        "kafkalingerms") == 0) {
            conf->kafkaopts.lingerms = strtoul((char *)value->data.scalar.value,
                    NULL, 10);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value,
                        "kafkasampling") == 0) {
            conf->kafkaopts.sampling = strtoul((char *)value->data.scalar.value,
                    NULL, 10);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value,
                        "kafkatopicprefix") == 0) {
            conf->kafkaopts.topicprefix = strdup((char *)value->data.scalar.value);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value,
                        "kafkabrokers") == 0) {
            conf->kafkaopts.brokeruri = strdup((char *)value->data.scalar.value);
        }
    }

    p->config = conf;
    return 0;

}

int corsaro_flowtuple_finalise_config(corsaro_plugin_t *p,
        corsaro_plugin_proc_options_t *stdopts, void *zmq_ctxt) {

    corsaro_flowtuple_config_t *conf;

    srand(time(0));

    /* Configure standard 'global' options for any options that
     * were not overridden by plugin-specific config.
     */
    conf = (corsaro_flowtuple_config_t *)(p->config);

    conf->basic.template = stdopts->template;
    conf->basic.monitorid = stdopts->monitorid;
    conf->zmq_ctxt = zmq_ctxt;

    corsaro_log(p->logger, "flowtuple plugin: using %u merging threads",
            conf->maxmergeworkers);
    if (conf->sort_enabled == CORSARO_FLOWTUPLE_SORT_ENABLED) {
        corsaro_log(p->logger,
                "flowtuple plugin: sorting flowtuples before output");
    } else {
        corsaro_log(p->logger,
                "flowtuple plugin: NOT sorting flowtuples before output");
    }

    if (conf->avrooutput == CORSARO_AVRO_OUTPUT_SNAPPY) {
        corsaro_log(p->logger,
                "flowtuple plugin: using snappy compression for avro output");
    } else if (conf->avrooutput == CORSARO_AVRO_OUTPUT_DEFLATE) {
        corsaro_log(p->logger,
                "flowtuple plugin: using deflate compression for avro output");
    } else {
        corsaro_log(p->logger,
                "flowtuple plugin: not writing any avro output");
    }

    if (conf->kafkaopts.brokeruri != NULL) {
        corsaro_log(p->logger,
                "flowtuple plugin: writing flowtuples to kafka broker: %s, using topic prefix '%s'",
                conf->kafkaopts.brokeruri,
                conf->kafkaopts.topicprefix ? conf->kafkaopts.topicprefix : "");
        corsaro_log(p->logger,
                "flowtuple plugin: kafka batch size = %d, max message delay = %dms, sampling %u/10000 flows",
                conf->kafkaopts.batchsize, conf->kafkaopts.lingerms,
                conf->kafkaopts.sampling);
    }

    return 0;
}


void corsaro_flowtuple_destroy_self(corsaro_plugin_t *p) {
    corsaro_flowtuple_config_t *conf;

    conf = (corsaro_flowtuple_config_t *)(p->config);

    if (conf && conf->kafkaopts.brokeruri) {
        free(conf->kafkaopts.brokeruri);
    }

    if (conf && conf->kafkaopts.topicprefix) {
        free(conf->kafkaopts.topicprefix);
    }

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

#ifdef HAVE_TCMALLOC
    state->fthandler = NULL;
#else
    state->fthandler = (corsaro_memhandler_t *)malloc(
            sizeof(corsaro_memhandler_t));
    init_corsaro_memhandler(p->logger, state->fthandler,
            sizeof(struct corsaro_flowtuple), 1000000);
#endif

    state->st_hash = NULL;
    state->keysort_levelone = NULL;

    return state;
}

int corsaro_flowtuple_halt_processing(corsaro_plugin_t *p, void *local) {

    struct corsaro_flowtuple_state_t *state;
    int i;
    PWord_t pval;
    Word_t index = 0;

    state = (struct corsaro_flowtuple_state_t *)local;
    if (state == NULL) {
        return 0;
    }

    if (state->fthandler) {
        destroy_corsaro_memhandler(state->fthandler);
    }
    free(state);

    return 0;
}

static inline char * _flowtuple_derive_output_name(corsaro_logger_t *logger,
        corsaro_plugin_proc_options_t *baseconf, uint32_t timestamp,
        int threadid) {

    char *outname = NULL;
    outname = corsaro_generate_avro_file_name(baseconf->template, "flowtuple",
            baseconf->monitorid, timestamp, threadid);

    if (outname == NULL) {
        corsaro_log(logger,
                "failed to generate suitable filename for flowtuple output");
        return NULL;
    }
    return outname;
}

char *corsaro_flowtuple_derive_output_name(corsaro_plugin_t *p,
        void *local, uint32_t timestamp, int threadid) {

    corsaro_flowtuple_config_t *conf;

    conf = (corsaro_flowtuple_config_t *)(p->config);
    return _flowtuple_derive_output_name(p->logger, &(conf->basic),
            timestamp, threadid);
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

void *corsaro_flowtuple_end_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_end, uint8_t complete) {

    corsaro_flowtuple_config_t *conf;
    struct corsaro_flowtuple_state_t *state;
    corsaro_flowtuple_interim_t *interim = NULL;
    Word_t hashsize;

    FLOWTUPLE_PROC_FUNC_START("corsaro_flowtuple_end_interval", NULL);

    interim = (corsaro_flowtuple_interim_t *)calloc(1,
            sizeof(corsaro_flowtuple_interim_t));
    if (state->fthandler) {
        add_corsaro_memhandler_user(state->fthandler);
    }
    interim->hmap = state->st_hash;
    JLC(hashsize, state->st_hash, 0, -1);
    interim->hsize = hashsize;
    interim->usable = 0;
    interim->sorted_keys = NULL;
    interim->logger = p->logger;

    pthread_mutex_init(&(interim->mutex), NULL);

    if (conf->sort_enabled == CORSARO_FLOWTUPLE_SORT_ENABLED) {
        interim->sorted_keys = state->keysort_levelone;
        interim->usable = 1;
    } else {
        interim->usable = 1;
    }

    /* Replace the hash map with an empty one -- the merging process
     * will free up everything associated with the old hash map. */
    state->st_hash = NULL;
    state->keysort_levelone = NULL;
    return interim;
}

static struct corsaro_flowtuple *insert_sorted_key(Pvoid_t *topmap,
        struct corsaro_flowtuple *ft, corsaro_logger_t *logger) {

    PWord_t tval, bval;
    Pvoid_t botmap = NULL;
    struct corsaro_flowtuple *newft;
    uint64_t sk_top, sk_bot;

    sk_top = FT_CALC_SORT_KEY_TOP(ft);
    sk_bot = FT_CALC_SORT_KEY_BOTTOM(ft);

    JLI(tval, (*topmap), sk_top);
    botmap = (Pvoid_t) *tval;

    JLI(bval, botmap, sk_bot);
    if (*bval == 0) {
        newft = calloc(1, sizeof(struct corsaro_flowtuple));

        if (newft == NULL) {
          corsaro_log(logger, "malloc of flowtuple failed");
          return NULL;
        }

        /* fill it */
        memcpy(newft, ft, sizeof(struct corsaro_flowtuple));
        newft->memsrc = NULL;
        newft->packet_cnt = 0;
        newft->sort_key_top = sk_top;
        newft->sort_key_bot = sk_bot;
        *bval = (Word_t)newft;
    } else {
        newft =(struct corsaro_flowtuple *)(*bval);
    }
    *tval = (Word_t)botmap;
    return newft;
}

/** Either add the given flowtuple to the hash, or increment the current count
 */
static int corsaro_flowtuple_add_inc(corsaro_logger_t *logger,
        struct corsaro_flowtuple_state_t *state, struct corsaro_flowtuple *t,
        uint32_t increment, corsaro_flowtuple_config_t *conf) {
  struct corsaro_flowtuple *new_6t = NULL;
  corsaro_memsource_t *memsrc = NULL;
  PWord_t pval;

  if (conf->sort_enabled == CORSARO_FLOWTUPLE_SORT_ENABLED) {
    new_6t = insert_sorted_key(&(state->keysort_levelone), t, logger);

    if (new_6t == NULL) {
        return -1;
    }
  } else {
    JLI(pval, state->st_hash, t->hash_val);
    if (*pval == 0) {
      new_6t = calloc(1, sizeof(struct corsaro_flowtuple));
      if (new_6t == NULL) {
          corsaro_log(logger, "malloc of flowtuple failed");
          return -1;
      }

      /* fill it */
      memcpy(new_6t, t, sizeof(struct corsaro_flowtuple));
      new_6t->memsrc = NULL;
      new_6t->packet_cnt = 0;
      new_6t->sort_key_top = 0;
      new_6t->sort_key_bot = 0;
      *pval = (Word_t)new_6t;
    } else {
      new_6t =(struct corsaro_flowtuple *)(*pval);
    }
  }

  assert(new_6t != NULL);

  /* will this cause a wrap? */
  assert((UINT32_MAX - new_6t->packet_cnt) > increment);

  new_6t->packet_cnt = (new_6t->packet_cnt) + increment;
  return 0;
}



int corsaro_flowtuple_process_packet(corsaro_plugin_t *p, void *local,
        libtrace_packet_t *packet, corsaro_packet_tags_t *tags) {
    libtrace_ip_t *ip_hdr = NULL;
    libtrace_tcp_t *tcp_hdr = NULL;
    struct corsaro_flowtuple t;
    uint16_t ethertype;
    uint32_t rem;

    corsaro_flowtuple_config_t *conf;
    struct corsaro_flowtuple_state_t *state;

    FLOWTUPLE_PROC_FUNC_START("corsaro_flowtuple_process_packet", -1);

    ip_hdr = (libtrace_ip_t *)(trace_get_layer3(packet, &ethertype, &rem));
    if (ip_hdr == NULL || ethertype != TRACE_ETHERTYPE_IP ||
            rem < sizeof(libtrace_ip_t)) {
        /* non-ipv4 packet or truncated */
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
    if (tags) {
        t.src_port = ntohs(tags->src_port);
        t.dst_port = ntohs(tags->dest_port);
    } else {
        t.src_port = trace_get_source_port(packet);
        t.dst_port = trace_get_destination_port(packet);
    }

    if (ip_hdr->ip_p == TRACE_IPPROTO_TCP) {
        tcp_hdr = (libtrace_tcp_t *) (((char *)ip_hdr) + (ip_hdr->ip_hl * 4));

        if (rem - (ip_hdr->ip_hl * 4) >= sizeof(libtrace_tcp_t)) {

            /* we have ignore the NS flag because it doesn't fit in
               an 8 bit field. blame alberto (ak - 2/2/12) */
            t.tcp_flags =
                ((tcp_hdr->cwr << 7) | (tcp_hdr->ece << 6) |
                 (tcp_hdr->urg << 5) | (tcp_hdr->ack << 4) |
                 (tcp_hdr->psh << 3) | (tcp_hdr->rst << 2) |
                 (tcp_hdr->syn << 1) | (tcp_hdr->fin << 0));
            if (t.tcp_flags == (1 << 1)) {
                t.tcp_synlen = tcp_hdr->doff * 4;
                t.tcp_synwinlen = ntohs(tcp_hdr->window);
            }
        }
    }

    if (tags) {
        uint64_t filterbits = bswap_be_to_host64(tags->filterbits);

        t.tagproviders = ntohl(tags->providers_used);

        if (t.tagproviders & (1 << IPMETA_PROVIDER_MAXMIND)) {
            t.maxmind_continent = tags->maxmind_continent;
            t.maxmind_country = tags->maxmind_country;
        }

        if (t.tagproviders & (1 << IPMETA_PROVIDER_NETACQ_EDGE)) {
            t.netacq_continent = tags->netacq_continent;
            t.netacq_country = tags->netacq_country;
        }

        if (t.tagproviders & (1 << IPMETA_PROVIDER_PFX2AS)) {
            t.prefixasn = ntohl(tags->prefixasn);
        }


        if (filterbits & (1 << CORSARO_FILTERID_SPOOFED)) {
            t.is_spoofed = 1;
        }
        if (filterbits & (1 << CORSARO_FILTERID_LARGE_SCALE_SCAN)) {
            t.is_masscan = 1;
        }

        t.hash_val = ntohl(tags->ft_hash);
    } else {
        t.tagproviders = 0;
        t.hash_val = corsaro_flowtuple_hash_func(&t);
    }

    if (corsaro_flowtuple_add_inc(p->logger, state, &t, 1, conf) != 0) {
        corsaro_log(p->logger, "could not increment value for flowtuple");
        return -1;
    }
    state->pkt_cnt ++;
    return 0;
}

/** Decodes an avro flowtuple record back into the corsaro flowtuple struct.
 *
 *  Used by corsaroftmerge, so don't remove this just because it isn't called
 *  in this source file!
 *
 *  @param record       The avro record to be decoded
 *  @param ft           The corsaro flowtuple structure to populate with the
 *                      decoded field contents.
 *
 *  @return 1 on success
 */
int decode_flowtuple_from_avro(avro_value_t *record,
        struct corsaro_flowtuple *ft) {

    avro_value_t av;
    int32_t tmp32;
    int64_t tmp64;
    const char *str = NULL;
    size_t strsize = 0;

    /* TODO error detection and handling... */

    avro_value_get_by_index(record, 0, &av, NULL);
    avro_value_get_long(&av, &(tmp64));
    ft->interval_ts = (uint32_t)tmp64;

    avro_value_get_by_index(record, 1, &av, NULL);
    avro_value_get_long(&av, &(tmp64));
    ft->src_ip = (uint32_t)tmp64;

    avro_value_get_by_index(record, 2, &av, NULL);
    avro_value_get_long(&av, &(tmp64));
    ft->dst_ip = (uint32_t)tmp64;

    avro_value_get_by_index(record, 3, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->src_port = (uint16_t)tmp32;

    avro_value_get_by_index(record, 4, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->dst_port = (uint16_t)tmp32;

    avro_value_get_by_index(record, 5, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->protocol = (uint8_t)tmp32;

    avro_value_get_by_index(record, 6, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->ttl = (uint8_t)tmp32;

    avro_value_get_by_index(record, 7, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->tcp_flags = (uint8_t)tmp32;

    avro_value_get_by_index(record, 8, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->ip_len = (uint16_t)tmp32;

    avro_value_get_by_index(record, 9, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->tcp_synlen = (uint16_t)tmp32;

    avro_value_get_by_index(record, 10, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->tcp_synwinlen = (uint16_t)tmp32;

    avro_value_get_by_index(record, 11, &av, NULL);
    avro_value_get_long(&av, &(tmp64));
    ft->packet_cnt = (uint32_t)tmp64;

    avro_value_get_by_index(record, 12, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->is_spoofed = (uint8_t)tmp32;

    avro_value_get_by_index(record, 13, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->is_masscan = (uint8_t)tmp32;

    avro_value_get_by_index(record, 14, &av, NULL);
    avro_value_get_string(&av, &str, &strsize);
    assert(strsize == 2);
    ft->maxmind_continent = (uint16_t)(str[0]) + (((uint16_t)str[1]) << 8);

    avro_value_get_by_index(record, 15, &av, NULL);
    avro_value_get_string(&av, &str, &strsize);
    assert(strsize == 2);
    ft->maxmind_country = (uint16_t)(str[0]) + (((uint16_t)str[1]) << 8);

    avro_value_get_by_index(record, 16, &av, NULL);
    avro_value_get_string(&av, &str, &strsize);
    assert(strsize == 2);
    ft->netacq_continent = (uint16_t)(str[0]) + (((uint16_t)str[1]) << 8);

    avro_value_get_by_index(record, 17, &av, NULL);
    avro_value_get_string(&av, &str, &strsize);
    assert(strsize == 2);
    ft->netacq_country = (uint16_t)(str[0]) + (((uint16_t)str[1]) << 8);


    avro_value_get_by_index(record, 18, &av, NULL);
    avro_value_get_long(&av, &(tmp64));
    ft->prefixasn = (uint32_t)tmp64;

    ft->tagproviders = (1 << IPMETA_PROVIDER_MAXMIND) |
            (1 << IPMETA_PROVIDER_NETACQ_EDGE) |
            (1 << IPMETA_PROVIDER_PFX2AS);

    ft->hash_val = 0;
    ft->memsrc = NULL;
    ft->sort_key_top = 0;
    ft->sort_key_bot = 0;
    ft->pqueue_pos = 0;
    ft->from = NULL;
    ft->fromind = 0;
    ft->pqueue_pri = 0;

    return 1;
}

void encode_flowtuple_as_avro(struct corsaro_flowtuple *ft,
        corsaro_avro_writer_t *writer, corsaro_logger_t *logger) {

    char valspace[128];
    uint32_t zero = 0;

    if (corsaro_start_avro_encoding(writer) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->interval_ts), sizeof(ft->interval_ts)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->src_ip), sizeof(ft->src_ip)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->dst_ip), sizeof(ft->dst_ip)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->src_port), sizeof(ft->src_port)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->dst_port), sizeof(ft->dst_port)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->protocol), sizeof(ft->protocol)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->ttl), sizeof(ft->ttl)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->tcp_flags), sizeof(ft->tcp_flags)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->ip_len), sizeof(ft->ip_len)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->tcp_synlen), sizeof(ft->tcp_synlen)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->tcp_synwinlen), sizeof(ft->tcp_synwinlen)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->packet_cnt), sizeof(ft->packet_cnt)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->is_spoofed), sizeof(ft->is_spoofed)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->is_masscan), sizeof(ft->is_masscan)) < 0) {
        return;
    }

    assert(ft->tagproviders != 0);

    if (ft->tagproviders & (1 << IPMETA_PROVIDER_MAXMIND)) {
        valspace[0] = (char)(ft->maxmind_continent & 0xff);
        valspace[1] = (char)((ft->maxmind_continent >> 8) & 0xff);
        valspace[2] = '\0';

        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                    valspace, 2) < 0) {
            return;
        }

        valspace[0] = (char)(ft->maxmind_country & 0xff);
        valspace[1] = (char)((ft->maxmind_country >> 8) & 0xff);
        valspace[2] = '\0';

        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                    valspace, 2) < 0) {
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


    if (ft->tagproviders & (1 << IPMETA_PROVIDER_NETACQ_EDGE)) {
        valspace[0] = (char)(ft->netacq_continent & 0xff);
        valspace[1] = (char)((ft->netacq_continent >> 8) & 0xff);
        valspace[2] = '\0';

        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                    valspace, 2) < 0) {
            return;
        }

        valspace[0] = (char)(ft->netacq_country & 0xff);
        valspace[1] = (char)((ft->netacq_country >> 8) & 0xff);
        valspace[2] = '\0';

        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                    valspace, 2) < 0) {
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

    if (ft->tagproviders & (1 << IPMETA_PROVIDER_PFX2AS)) {
        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                    &(ft->prefixasn), sizeof(ft->prefixasn)) < 0) {
            return;
        }

    } else {
        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                    &(zero), sizeof(zero)) < 0) {
            return;
        }
    }
}

/** Push a single flowtuple record onto a kafka topic
 *
 *  @param m        The merging thread that has received the flowtuple
 *  @param ft       The flowtuple record to be published
 */
static void kafka_publish_flowtuple(corsaro_flowtuple_merger_t *m,
        struct corsaro_flowtuple *ft) {

    corsaro_flowtuple_kafka_record_t rec;
    uint32_t roll;

    /* If we are only publishing a sample of the flowtuples, check to
     * see if this one is selected for publication.
     */
    if (m->kafkaopts->sampling < 10000) {
        roll = rand() % 10000;
        if (roll >= m->kafkaopts->sampling) {
            return;
        }
    }

    if (m->partkey.ts == 0) {
        m->partkey.ts = ft->interval_ts;
    }

    m->partkey.hash_val = ft->hash_val;

    /* We use a specific struct here because:
     * a) there's a lot of additional fields in the regular flowtuple structure
     *    that only have meaning internally and are not worth publishing.
     * b) we need consistent byte ordering on the fields we do publish
     */
    rec.interval_ts = htonl(ft->interval_ts);
    rec.src_ip = htonl(ft->src_ip);
    rec.dst_ip = htonl(ft->dst_ip);
    rec.src_port = htons(ft->src_port);
    rec.dst_port = htons(ft->dst_port);
    rec.protocol = ft->protocol;
    rec.ttl = ft->ttl;
    rec.tcp_flags = ft->tcp_flags;
    rec.ip_len = htons(ft->ip_len);
    rec.tcp_synlen = htons(ft->tcp_synlen);
    rec.tcp_synwinlen = htons(ft->tcp_synwinlen);
    rec.packet_cnt = htonl(ft->packet_cnt);
    rec.is_spoofed = ft->is_spoofed;
    rec.is_masscan = ft->is_masscan;
    rec.prefixasn = htonl(ft->prefixasn);

    rec.maxmind_country[0] = (char) ft->maxmind_country & 0xff;
    rec.maxmind_country[1] = (char) (ft->maxmind_country >> 8) & 0xff;
    rec.maxmind_continent[0] = (char) ft->maxmind_continent & 0xff;
    rec.maxmind_continent[1] = (char) (ft->maxmind_continent >> 8) & 0xff;
    rec.netacq_country[0] = (char) ft->netacq_country & 0xff;
    rec.netacq_country[1] = (char) (ft->netacq_country >> 8) & 0xff;
    rec.netacq_continent[0] = (char) ft->netacq_continent & 0xff;
    rec.netacq_continent[1] = (char) (ft->netacq_continent >> 8) & 0xff;

    memcpy(m->writeptr, &rec, sizeof(rec));
    m->writeptr += sizeof(rec);

    /* 512 KB seems to be good number for message sizes with kafka. Larger
     * messages require extra configuration on the broker.
     *
     * Also, we flush the message whenever we switch interval to avoid
     * mixing intervals in the same message.
     */
    if (m->writeptr - m->buf > (1024 * 512) || ft->interval_ts !=
            m->partkey.ts) {

        while (rd_kafka_produce(m->rdktopic, RD_KAFKA_PARTITION_UA,
                    RD_KAFKA_MSG_F_COPY, m->buf, m->writeptr - m->buf,
                    &(m->partkey),
                    sizeof(m->partkey), &(m->maxmergeworkers)) == -1) {

            if (rd_kafka_last_error() == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
                usleep(50);
                continue;
            }

            corsaro_log(m->logger, "Error while publishing flowtuple to kafka topic %s: %s",
                    rd_kafka_topic_name(m->rdktopic),
                    rd_kafka_err2str(rd_kafka_last_error()));

            break;
        }

        /* Doing this occasionally allows librdkafka to trigger any extra
         * callbacks (e.g. errors).
         */
        rd_kafka_poll(m->rdk, 0);
        m->writeptr = m->buf;
        m->partkey.ts = ft->interval_ts;
    }
}

static void write_sorted_interim_flowtuples(corsaro_flowtuple_merger_t *m,
        corsaro_avro_writer_t *writer, corsaro_flowtuple_iterator_t *input) {

    PWord_t pval;
    Word_t ret;
    struct corsaro_flowtuple *nextft;
    uint64_t count = 0;

    input->sortindex_top = 0;

    JLF(pval, input->sorted_keys, input->sortindex_top);

    while (pval) {
        input->current_subkeys = (Pvoid_t) (*pval);
        input->sortindex_bot = 0;

        JLF(pval, input->current_subkeys, input->sortindex_bot);
        while (pval) {
            nextft = (struct corsaro_flowtuple *)(*pval);

            if (writer) {
                encode_flowtuple_as_avro(nextft, writer, m->logger);
                if (corsaro_append_avro_writer(writer, NULL) < 0) {
                    /* what shall we do? */
                }
            }

            if (m->rdk) {
                kafka_publish_flowtuple(m, nextft);
            }

            free(nextft);
            count ++;

            JLN(pval, input->current_subkeys, input->sortindex_bot);
        }
        JLFA(ret, input->current_subkeys);
        JLN(pval, input->sorted_keys, input->sortindex_top);
    }
}

static void write_unsorted_interim_flowtuples(corsaro_flowtuple_merger_t *m,
        corsaro_avro_writer_t *writer, corsaro_flowtuple_iterator_t *input) {

    struct corsaro_flowtuple *nextft;
    PWord_t pval;
    Word_t index = 0;

    uint64_t count = 0;

    JLF(pval, input->hmap, index);
    while (pval) {
        nextft = (struct corsaro_flowtuple *)(*pval);

        if (writer) {
            encode_flowtuple_as_avro(nextft, writer, m->logger);
            if (corsaro_append_avro_writer(writer, NULL) < 0) {
                /* shall we do something? */
            }
        }
        if (m->rdk) {
            kafka_publish_flowtuple(m, nextft);
        }
        free(nextft);
        count ++;

        JLN(pval, input->hmap, index);
    }
}

/** Assigns a given flowtuple record to a kafka partition
 *
 *  Function prototype cannot be changed as this is a specific callback
 *  method defined in librdkafka.
 *
 *  @param rkt      The kafka topic that this record is being published to
 *  @param key      The corresponding corsaro_ft_kafka_partkey_t for this record
 *  @param keylen   The size of the key structure
 *  @param partition_cnt    The number of partitions supported by the kafka
 *                          cluster
 *  @param opaque   Unused
 *  @param msg_opaque   Contains the total number of interim writer worker
 *                      threads for this flowtuple plugin instance.
 *
 *  @return the index of the partition that should receive this flowtuple record
 *
 */
static int32_t assign_kafka_partition(const rd_kafka_topic_t *rkt,
        const void *key, size_t keylen, int32_t partition_cnt,
        void *opaque, void *msg_opaque) {

    corsaro_ft_kafka_partkey_t *pkey;

    pkey = (corsaro_ft_kafka_partkey_t *)key;
    assert(keylen == sizeof(corsaro_ft_kafka_partkey_t));

    /* Most important thing is that any flows that are split across
     * multiple records (due to non-flow-specific packet-to-thread
     * mappings) end up on the same kafka partition so that they can be
     * combined into a single record.
     */
    return pkey->hash_val % partition_cnt;
}

/** Creates and configures a kafka producer instance for publishing
 *  flowtuple records.
 *
 *  @param m        The flowtuple "merger" thread that this producer is
 *                  being created for.
 *
 *  @return 1 if the producer is created successfully, -1 if an error
 *          occurs.
 */
static int init_kafka_producer(corsaro_flowtuple_merger_t *m) {

    rd_kafka_conf_t *conf;
    rd_kafka_topic_conf_t *tconf;
    rd_kafka_conf_res_t res;
    char errstr[512];
    char intstr[100];
    char topicname[1024];

    conf = rd_kafka_conf_new();
    tconf = rd_kafka_topic_conf_new();

    /* Set config options for the kafka instance */
    /* XXX consider making this configurable? */
    res = rd_kafka_conf_set(conf, "compression.codec", "snappy",
            errstr, sizeof(errstr));
    if (res != RD_KAFKA_CONF_OK) {
        goto initkafkafail;
    }

    snprintf(intstr, 100, "%d", m->kafkaopts->batchsize);
    res = rd_kafka_conf_set(conf, "batch.num.messages", intstr,
            errstr, sizeof(errstr));
    if (res != RD_KAFKA_CONF_OK) {
        goto initkafkafail;
    }

    snprintf(intstr, 100, "%d", m->kafkaopts->lingerms);
    res = rd_kafka_conf_set(conf, "linger.ms", intstr,
            errstr, sizeof(errstr));
    if (res != RD_KAFKA_CONF_OK) {
        goto initkafkafail;
    }

    m->rdk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
    if (!m->rdk) {
        goto initkafkafail;
    }

    /* Add the broker so kafka can connect to it */
    if (rd_kafka_brokers_add(m->rdk, m->kafkaopts->brokeruri) == 0) {
        corsaro_log(m->logger, "Kafka error connecting to broker: %s",
                m->kafkaopts->brokeruri);
        errstr[0] = '\0';
        goto initkafkafail;
    }

    /* Configure and create the flowtuple topic */
    if (m->kafkaopts->topicprefix != NULL) {
        snprintf(topicname, 1024, "%s.corsaroflowtuple",
                m->kafkaopts->topicprefix);
    } else {
        snprintf(topicname, 1024, "corsaroflowtuple");
    }

    /* Set a callback for assigning flowtuples to kafka partitions */
    rd_kafka_topic_conf_set_partitioner_cb(tconf, assign_kafka_partition);

    m->rdktopic = rd_kafka_topic_new(m->rdk, topicname, tconf);
    if (m->rdktopic == NULL) {
        corsaro_log(m->logger, "Kafka error creating new topic: %s",
                topicname);
        errstr[0] = '\0';
        goto initkafkafail;
    }

    return 1;

initkafkafail:
    if (errstr[0] != 0) {
        corsaro_log(m->logger, "Kafka error: %s", errstr);
    }

    if (m->rdk) {
        rd_kafka_destroy(m->rdk);
    } else {
        rd_kafka_conf_destroy(conf);
    }

    rd_kafka_topic_conf_destroy(tconf);
    return -1;
}

static void *start_ftmerge_worker(void *tdata) {
    corsaro_flowtuple_merger_t *m = (corsaro_flowtuple_merger_t *)tdata;
    corsaro_ft_write_msg_t msg;
    corsaro_flowtuple_iterator_t *input;
    corsaro_avro_writer_t *w = NULL;
    int i;
    PWord_t pval;
    Word_t rc, index;

    /* Create a kafka producer for this thread if we are doing kafka output */
    /*  XXX would we be better off having a single producer shared by all
    *       threads? docs imply that would be ok, but is contention an issue?
    */
    if (m->kafkaopts->brokeruri) {
        if (init_kafka_producer(m) < 0) {
            corsaro_log(m->logger, "error creating kafka producer for flowtuple interim writer thread %d", m->thread_num);
        }
    }

    while (1) {
        if (zmq_recv(m->inqueue, &(msg), sizeof(msg), ZMQ_DONTWAIT) < 0) {

            if (errno == EAGAIN) {
                usleep(1000000);
                continue;
            }
            corsaro_log(m->logger, "error receiving message on flowtuple merger thread socket: %s",
                    strerror(errno));
            break;
        }

        if (msg.type == CORSARO_FT_MSG_STOP) {
            break;
        }

        if (msg.type == CORSARO_FT_MSG_ROTATE) {
            index = 0;
            JLF(pval, m->writers, index);
            while (pval) {
                w = (corsaro_avro_writer_t *)(*pval);
                if (w) {
                    corsaro_close_avro_writer(w);
                }
                JLN(pval, m->writers, index);
            }
            continue;
        }

        if (msg.content == NULL) {
            continue;
        }

        /* If we're doing avro output, make sure we have a writer instance
         * available.
         */
        if (m->avrooutput != CORSARO_AVRO_OUTPUT_NONE) {
            JLG(pval, m->writers, msg.input_source);
            if (!pval) {
                w = corsaro_create_avro_writer(m->logger,
                        FLOWTUPLE_RESULT_SCHEMA);
                JLI(pval, m->writers, msg.input_source);
                *pval = (Word_t)w;
            } else {
                w = (corsaro_avro_writer_t *)(*pval);
            }


            if (!corsaro_is_avro_writer_active(w)) {
                char *outname = _flowtuple_derive_output_name(
                        m->logger, m->baseconf, msg.interval_ts,
                        msg.input_source);
                if (outname == NULL) {
                    continue;
                }
                if (corsaro_start_avro_writer(w, outname,
                            (m->avrooutput == CORSARO_AVRO_OUTPUT_SNAPPY)
                            ) == -1) {
                    free(outname);
                    continue;
                }
                free(outname);
            }
        }

        input = (corsaro_flowtuple_iterator_t *)msg.content;

        if (msg.type == CORSARO_FT_MSG_MERGE_UNSORTED) {
            write_unsorted_interim_flowtuples(m, w, input);
        } else if (msg.type == CORSARO_FT_MSG_MERGE_SORTED) {
            write_sorted_interim_flowtuples(m, w, input);
        }

        JLFA(rc, input->hmap);
        JLFA(rc, input->sorted_keys);
        pthread_mutex_destroy(&(input->parent->mutex));
        free(input->parent);
        free(input);

        corsaro_log(m->logger,
                "merging thread %d has completed the merge job for %u",
                m->thread_num, msg.interval_ts);
    }

    /* If we were publishing to kafka, make sure we wind that down nicely */
    if (m->rdk) {
        rd_kafka_flush(m->rdk, 30 * 1000);
        if (m->rdktopic) {
            rd_kafka_topic_destroy(m->rdktopic);
        }
        rd_kafka_destroy(m->rdk);
    }

    if (m->buf) {
        free(m->buf);
    }

    /* Close any avro writer instances that we were using */
    index = 0;
    JLF(pval, m->writers, index);
    while (pval) {
        w = (corsaro_avro_writer_t *)(*pval);
        if (w) {
            corsaro_destroy_avro_writer(w);
        }
        JLN(pval, m->writers, index);
    }
    JLFA(rc, m->writers);
    pthread_exit(NULL);
}


#define FT_MERGE_THREAD_SUB(tosub) \
    subval = tosub; \
    if (zmq_setsockopt(m->writerthreads[i].inqueue, ZMQ_SUBSCRIBE, &subval, \
                sizeof(subval)) < 0) { \
        corsaro_log(p->logger, \
                "merge thread %u failed to sub to messages: %s", \
                m->writerthreads[i].thread_num, strerror(errno)); \
        zmq_close(m->writerthreads[i].inqueue); \
        m->writerthreads[i].inqueue = NULL; \
        goto mthreadfail; \
    }

void *corsaro_flowtuple_init_merging(corsaro_plugin_t *p, int sources) {
    struct corsaro_flowtuple_merge_state_t *m;
    int i, zero=0;
    uint8_t subval;
    corsaro_flowtuple_config_t *conf;

    conf = (corsaro_flowtuple_config_t *)(p->config);

    m = (struct corsaro_flowtuple_merge_state_t *)calloc(1,
            sizeof(struct corsaro_flowtuple_merge_state_t));

    m->maxworkers = conf->maxmergeworkers;
    m->writerthreads = calloc(m->maxworkers,
            sizeof(corsaro_flowtuple_merger_t));
    m->nextworker = 0;

    m->pubqueue = zmq_socket(conf->zmq_ctxt, ZMQ_PUB);
    if (zmq_setsockopt(m->pubqueue, ZMQ_LINGER, &zero, sizeof(zero)) < 0) {
        corsaro_log(p->logger, "error configuring pub socket for flowtuple merger: %s", strerror(errno));
        goto initfail;
    }

    if (zmq_bind(m->pubqueue, CORSARO_FT_INTERNAL_QUEUE) < 0) {
        corsaro_log(p->logger, "error binding to flowtuple internal merging queu: %s", strerror(errno));
        goto initfail;
    }

    for (i = 0; i < m->maxworkers; i++) {
        m->writerthreads[i].logger = p->logger;
        m->writerthreads[i].baseconf = &(conf->basic);
        m->writerthreads[i].writers = NULL;

        m->writerthreads[i].thread_num = i;
        m->writerthreads[i].inqueue = zmq_socket(conf->zmq_ctxt, ZMQ_SUB);
        m->writerthreads[i].avrooutput = conf->avrooutput;
        m->writerthreads[i].maxmergeworkers = conf->maxmergeworkers;
        m->writerthreads[i].rdk = NULL;
        m->writerthreads[i].rdktopic = NULL;
        m->writerthreads[i].kafkaopts = &(conf->kafkaopts);
        m->writerthreads[i].buf = calloc(1024 * 1024 * 2, sizeof(uint8_t));
        m->writerthreads[i].writeptr = m->writerthreads[i].buf;
        m->writerthreads[i].partkey.ts = 0;
        m->writerthreads[i].partkey.hash_val = 0;

        FT_MERGE_THREAD_SUB(255)
        FT_MERGE_THREAD_SUB(m->writerthreads[i].thread_num)
        if (zmq_connect(m->writerthreads[i].inqueue,
                    CORSARO_FT_INTERNAL_QUEUE) < 0) {
            corsaro_log(p->logger,
                    "error connecting sub socket for flowtuple merging thread %d: %s",
                    i, strerror(errno));
            zmq_close(m->writerthreads[i].inqueue);
            m->writerthreads[i].inqueue = NULL;
        }

        pthread_create(&(m->writerthreads[i].tid), NULL, start_ftmerge_worker,
                &(m->writerthreads[i]));

mthreadfail:
        continue;
    }

    return m;

initfail:
    zmq_close(m->pubqueue);
    free(m->writerthreads);
    free(m);
    return NULL;
}
int corsaro_flowtuple_halt_merging(corsaro_plugin_t *p, void *local) {

    struct corsaro_flowtuple_merge_state_t *m;
    int i;

    m = (struct corsaro_flowtuple_merge_state_t *)local;
    if (m == NULL) {
        return 0;
    }

    for (i = 0; i < m->maxworkers; i++) {
        corsaro_ft_write_msg_t msg;
        if (m->writerthreads[i].inqueue) {
            msg.dest = 255;
            msg.type = CORSARO_FT_MSG_STOP;
            msg.content = NULL;
            msg.interval_ts = 0;
            msg.input_source = 0;

            zmq_send(m->pubqueue, &(msg), sizeof(msg), 0);

            pthread_join(m->writerthreads[i].tid, NULL);
            zmq_close(m->writerthreads[i].inqueue);
        }
    }

    if (m->pubqueue) {
        zmq_close(m->pubqueue);
    }

    free(m->writerthreads);
    free(m);
    return 0;
}
int corsaro_flowtuple_merge_interval_results(corsaro_plugin_t *p, void *local,
        void **tomerge, corsaro_fin_interval_t *fin, void *tagsock) {

    struct corsaro_flowtuple_merge_state_t *m;
    corsaro_flowtuple_config_t *conf;
    corsaro_ft_write_msg_t msg;
    int i, candind;
    int inputsready;
    uint8_t *donethreads;

    conf = (corsaro_flowtuple_config_t *)(p->config);
    m = (struct corsaro_flowtuple_merge_state_t *)local;
    if (m == NULL) {
        return -1;
    }

    donethreads = calloc(fin->threads_ended, sizeof(uint8_t));

    inputsready = 0;
    while (inputsready < fin->threads_ended) {
        for (i = 0; i < fin->threads_ended; i++) {
            corsaro_flowtuple_interim_t *interim;
            corsaro_flowtuple_iterator_t *input = NULL;

            if (donethreads[i] != 0) {
                continue;
            }

            interim = (corsaro_flowtuple_interim_t *)(tomerge[i]);
            assert(interim);
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
                input = calloc(1, sizeof(corsaro_flowtuple_iterator_t));

                input->hmap = interim->hmap;
                input->hsize = interim->hsize;
                input->nextft = NULL;

                if (interim->usable == 1) {
                    input->state = CORSARO_RESULT_TYPE_DATA;
                } else {
                    input->state = CORSARO_RESULT_TYPE_EOF;
                }
                if (conf->sort_enabled == CORSARO_FLOWTUPLE_SORT_ENABLED) {
                    input->sorted_keys = interim->sorted_keys;
                    input->current_subkeys = NULL;
                    input->sortindex_top = 0;
                    input->sortindex_bot = 0;
                    input->sortiter = 0;
                } else {
                    input->sorted_keys = NULL;
                    input->current_subkeys = NULL;
                    input->sortindex_top = 0;
                    input->sortindex_bot = 0;
                    input->sortiter = -1;
                }
                input->parent = interim;
                pthread_join(interim->tid, NULL);
                pthread_mutex_unlock(&(interim->mutex));
            }

            if (input) {
                msg.dest = m->nextworker;

                m->nextworker = (m->nextworker + 1) % m->maxworkers;

                if (conf->sort_enabled == CORSARO_FLOWTUPLE_SORT_ENABLED) {
                    msg.type = CORSARO_FT_MSG_MERGE_SORTED;
                } else {
                    msg.type = CORSARO_FT_MSG_MERGE_UNSORTED;
                }

                msg.content = input;
                msg.interval_ts = fin->timestamp;
                msg.input_source = i;

                zmq_send(m->pubqueue, &(msg), sizeof(msg), 0);
                donethreads[i] = 1;
            }
        }

        if (inputsready < fin->threads_ended) {
            usleep(100);
        }
    }


    return 0;
}

int corsaro_flowtuple_rotate_output(corsaro_plugin_t *p, void *local) {

    struct corsaro_flowtuple_merge_state_t *m;
    corsaro_ft_write_msg_t msg;
    int i;

    m = (struct corsaro_flowtuple_merge_state_t *)local;
    if (m == NULL) {
        return -1;
    }

    msg.type = CORSARO_FT_MSG_ROTATE;
    msg.content = NULL;
    msg.interval_ts = 0;
    msg.input_source = 0;

    for (i = 0; i < m->maxworkers; i++) {
        msg.dest = i;
        zmq_send(m->pubqueue, &(msg), sizeof(msg), 0);
    }

    return 0;
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
uint32_t corsaro_flowtuple_hash_func(struct corsaro_flowtuple *ft)
{
  uint32_t h = (uint32_t)ft->src_ip * 59;
  CORSARO_FLOWTUPLE_SHIFT_AND_XOR(ft->dst_ip);
  CORSARO_FLOWTUPLE_SHIFT_AND_XOR(ft->src_port << 16);
  CORSARO_FLOWTUPLE_SHIFT_AND_XOR(ft->dst_port);
  CORSARO_FLOWTUPLE_SHIFT_AND_XOR((ft->ttl << 24) | (ft->tcp_flags << 16));
  CORSARO_FLOWTUPLE_SHIFT_AND_XOR((ft->protocol << 8) | (ft->ip_len));
  return h;
}



// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
