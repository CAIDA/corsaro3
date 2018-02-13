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

#include <yaml.h>

#include "libcorsaro3_plugin.h"
#include "corsaro_flowtuple.h"
#include "utils.h"

/* This magic number is a legacy number from when we used to call it the
   'sixtuple' */
#ifdef CORSARO_SLASH_EIGHT
/** The magic number for this plugin when using /8 opts - "SIXT" */
#define CORSARO_FLOWTUPLE_MAGIC 0x53495854
#else
/** The magic number for this plugin when not using /8 opts - "SIXU" */
#define CORSARO_FLOWTUPLE_MAGIC 0x53495855
#endif

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
    khash_t(sixt) * st_hash[CORSARO_FLOWTUPLE_CLASS_MAX + 1];
    /** The current class (if we are reading FT data) */
    uint16_t current_class;
    /** The outfile for the plugin */
    corsaro_file_t *outfile;

    /** The ID of the thread running this plugin instance */
    int threadid;
};

typedef struct corsaro_flowtuple_config {
    corsaro_plugin_proc_options_t basic;
    corsaro_flowtuple_sort_t sort_enabled;
} corsaro_flowtuple_config_t;

/** The name of this plugin */
#define PLUGIN_NAME "flowtuple"

/** Array of string names for classes */
static const char *class_names[] = {
  "flowtuple_backscatter", "flowtuple_icmpreq", "flowtuple_other",
};

static corsaro_plugin_t corsaro_flowtuple_plugin = {

    PLUGIN_NAME,
    CORSARO_PLUGIN_ID_FLOWTUPLE,
    CORSARO_FLOWTUPLE_MAGIC,
    CORSARO_PLUGIN_GENERATE_BASE_PTRS(corsaro_flowtuple),
    CORSARO_PLUGIN_GENERATE_TRACE_PTRS(corsaro_flowtuple),
    CORSARO_PLUGIN_GENERATE_READ_PTRS(corsaro_flowtuple),
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

    if (conf->basic.outmode == CORSARO_FILE_MODE_UNKNOWN) {
        conf->basic.outmode = stdopts->outmode;
    }

    if (conf->basic.compress == CORSARO_FILE_COMPRESS_UNSET) {
        conf->basic.compress = stdopts->compress;
    }

    if (conf->basic.compresslevel < 0) {
        conf->basic.compresslevel = stdopts->compresslevel;
    }

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

static void corsaro_flowtuple_fprint(corsaro_file_t *file,
        struct corsaro_flowtuple *flowtuple) {

    char ip_a[INET_ADDRSTRLEN];
    char ip_b[INET_ADDRSTRLEN];
    uint32_t tmp;

    assert(file != NULL);
    assert(flowtuple != NULL);

    tmp = flowtuple->src_ip;
    inet_ntop(AF_INET, &tmp, &ip_a[0], 16);
    tmp = CORSARO_FLOWTUPLE_SIXT_TO_IP(flowtuple);
    inet_ntop(AF_INET, &tmp, &ip_b[0], 16);

    corsaro_file_printf(
            file, "%s|%s"
            "|%" PRIu16 "|%" PRIu16 "|%" PRIu8 "|%" PRIu8 "|0x%02" PRIx8
            "|%" PRIu16 ",%" PRIu32 "\n",
            ip_a, ip_b, ntohs(flowtuple->src_port), ntohs(flowtuple->dst_port),
            flowtuple->protocol, flowtuple->ttl, flowtuple->tcp_flags,
            ntohs(flowtuple->ip_len), ntohl(flowtuple->packet_cnt));
}

/** Dump the given flowtuple to the plugin's outfile in ASCII format */
static int ascii_dump(corsaro_plugin_t *p,
        struct corsaro_flowtuple_state_t *state,
        corsaro_flowtuple_config_t *conf,
        corsaro_flowtuple_class_type_t dist)
{
    kh_sixt_t *h = state->st_hash[dist];
    struct corsaro_flowtuple **sorted_keys;
    int j;
    khiter_t i;

    /*const char *name = class_names[dist];*/
    struct corsaro_flowtuple_class_start class_start;
    struct corsaro_flowtuple_class_end class_end;

    class_start.magic = CORSARO_FLOWTUPLE_MAGIC;
    class_start.class_type = dist;
    class_start.count = kh_size(h);

    class_end.magic = CORSARO_FLOWTUPLE_MAGIC;
    class_end.class_type = dist;

    corsaro_file_printf(state->outfile, "START %s %" PRIu32 "\n",
            class_names[class_start.class_type], class_start.count);

    if (kh_size(h) > 0) {
        if (conf->sort_enabled == CORSARO_FLOWTUPLE_SORT_ENABLED) {
            /* sort the hash before dumping */
            if (sort_hash(p->logger, h, &sorted_keys) != 0) {         // XXX
                corsaro_log(p->logger, "flowtuple: could not sort keys");
                return -1;
            }
            for (j = 0; j < kh_size(h); j++) {
                corsaro_flowtuple_fprint(state->outfile, sorted_keys[j]);
                free(sorted_keys[j]);
            }
            free(sorted_keys);
        } else {
            /* do not sort the hash before dumping */
            for (i = kh_begin(h); i != kh_end(h); ++i) {
                if (kh_exist(h, i)) {
                    corsaro_flowtuple_fprint(state->outfile, kh_key(h, i));
                    free(kh_key(h, i));
                }
            }
        }
    }

    corsaro_file_printf(state->outfile, "END %s\n",
            class_names[class_start.class_type]);
    return 0;
}

/** Dump the given flowtuple to the plugin's outfile in binary format */
static int binary_dump(corsaro_plugin_t *p,
        struct corsaro_flowtuple_state_t *state,
        corsaro_flowtuple_config_t *conf,
        corsaro_flowtuple_class_type_t dist)
{
    kh_sixt_t *h = state->st_hash[dist];

    int j;
    struct corsaro_flowtuple **sorted_keys;
    khiter_t i = 0;

    uint8_t hbuf[4 + 2 + 4];
    uint8_t *hptr = &hbuf[0];

    bytes_htonl(hptr, CORSARO_FLOWTUPLE_MAGIC);
    hptr += 4;

    bytes_htons(hptr, dist);
    hptr += 2;

    bytes_htonl(hptr, kh_size(h));

    if (corsaro_file_write(state->outfile, &hbuf[0], 10) !=
            10) {
        corsaro_log(p->logger,
                "could not dump byte flowtuple header to file");
        return -1;
    }

    if (kh_size(h) > 0) {
        if (conf->sort_enabled == CORSARO_FLOWTUPLE_SORT_ENABLED) {
            /* sort the hash before dumping */
            if (sort_hash(p->logger, h, &sorted_keys) != 0) {
                corsaro_log(p->logger, "could not sort flowtuple keys");
                return -1;
            }
            for (j = 0; j < kh_size(h); j++) {
                if (corsaro_file_write(state->outfile, sorted_keys[j],
                            CORSARO_FLOWTUPLE_BYTECNT) !=
                        CORSARO_FLOWTUPLE_BYTECNT) {
                    corsaro_log(p->logger, "could not write flowtuple to file");
                    return -1;
                }
                /* this actually frees the flowtuples themselves */
                free(sorted_keys[j]);
            }
            free(sorted_keys);
        } else {
            /* do not sort the hash */
            for (i = kh_begin(h); i != kh_end(h); ++i) {
                if (kh_exist(h, i)) {
                    if (corsaro_file_write(state->outfile, kh_key(h, i),
                                CORSARO_FLOWTUPLE_BYTECNT) !=
                            CORSARO_FLOWTUPLE_BYTECNT) {
                        corsaro_log(p->logger, "could not write flowtuple to file");
                        return -1;
                    }
                    free(kh_key(h, i));
                }
            }
        }
    }

    if (corsaro_file_write(state->outfile, &hbuf[0], 6) != 6) {
        corsaro_log(p->logger, "could not dump flowtuple trailer to file");
        return -1;
    }
    return 0;
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

    state->threadid = threadid;

    /* defer opening the output file until we start the first interval */

    for (i = 0; i <= CORSARO_FLOWTUPLE_CLASS_MAX; i++) {
        assert(state->st_hash[i] == NULL);
        state->st_hash[i] = kh_init(sixt);
        assert(state->st_hash[i] != NULL);
    }

    return state;
}

int corsaro_flowtuple_halt_processing(corsaro_plugin_t *p, void *local) {

    struct corsaro_flowtuple_state_t *state;
    int i;

    state = (struct corsaro_flowtuple_state_t *)local;
    if (state == NULL) {
        return 0;
    }

    for (i = 0; i <= CORSARO_FLOWTUPLE_CLASS_MAX; i++) {
        if (state->st_hash[i] != NULL) {
            /* NB: flowtuples are freed in the dump functions */
            kh_destroy(sixt, state->st_hash[i]);
            state->st_hash[i] = NULL;
        }
    }

    if (state->outfile != NULL) {
        corsaro_file_close(state->outfile);
    }
    state->outfile = NULL;
    free(state);

    return 0;
}

char *corsaro_flowtuple_derive_output_name(corsaro_plugin_t *p,
        void *local, uint32_t timestamp, int threadid) {

    corsaro_flowtuple_config_t *conf;
    struct corsaro_flowtuple_state_t *state;
    char *outname = NULL;

    FLOWTUPLE_PROC_FUNC_START("corsaro_flowtuple_derive_output_name", NULL);

    outname = corsaro_generate_file_name(conf->basic.template, p->name,
            conf->basic.monitorid, timestamp, conf->basic.compress,
            threadid);
    if (outname == NULL) {
        corsaro_log(p->logger,
                "failed to generate suitable filename for flowtuple output");
        return NULL;
    }
    return outname;

}

corsaro_file_t *corsaro_flowtuple_open_output_file(corsaro_plugin_t *p,
        void *local, uint32_t timestamp, int threadid) {

    corsaro_flowtuple_config_t *conf;
    struct corsaro_flowtuple_state_t *state;
    char *outname = NULL;
    corsaro_file_t *f = NULL;

    FLOWTUPLE_PROC_FUNC_START("corsaro_flowtuple_open_output_file", NULL);

    outname = corsaro_flowtuple_derive_output_name(p, local, timestamp,
            threadid);
    if (outname == NULL) {
        return f;
    }

    f = corsaro_file_open(p->logger,
            outname, conf->basic.outmode, conf->basic.compress,
            conf->basic.compresslevel,
            O_CREAT);

    if (f == NULL) {
        corsaro_log(p->logger, "failed to open flowtuple output file %s",
                outname);
        free(outname);
    }

    return f;
}

int corsaro_flowtuple_start_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_start) {

    corsaro_flowtuple_config_t *conf;
    struct corsaro_flowtuple_state_t *state;

    FLOWTUPLE_PROC_FUNC_START("corsaro_flowtuple_start_interval", -1);

    if (state->outfile == NULL) {
        state->outfile = corsaro_flowtuple_open_output_file(p, local,
                int_start->time, state->threadid);

        if (state->outfile == NULL) {
            return -1;
        }
    }
    return 0;
}

int corsaro_flowtuple_end_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_end) {

    int i;
    corsaro_flowtuple_config_t *conf;
    struct corsaro_flowtuple_state_t *state;

    FLOWTUPLE_PROC_FUNC_START("corsaro_flowtuple_end_interval", -1);

    for (i = 0; i <= CORSARO_FLOWTUPLE_CLASS_MAX; i++) {
        assert(state->st_hash[i] != NULL);
        if (conf->basic.outmode == CORSARO_FILE_MODE_BINARY) {
            if (binary_dump(p, state, conf, i) < 0) {
                return -1;
            }
        }

        if (conf->basic.outmode == CORSARO_FILE_MODE_ASCII) {
            if (ascii_dump(p, state, conf, i) < 0) {
                return -1;
            }
        }

        kh_clear(sixt, state->st_hash[i]);
    }

    if (corsaro_file_write_interval(state->outfile, int_end, 0) < 0) {
        corsaro_log(p->logger,
                "failed to write interval end to flowtuple output file");
        return -1;
    }
    return 0;
}

/**
 * Determines the traffic class for a packet; possible options are
 * CORSARO_FLOWTUPLE_CLASS_BACKSCATTER, CORSARO_FLOWTUPLE_CLASS_ICMPREQ,
 * CLASS_OTHER
 *
 * This code is ported from crl_attack_flow.c::get_traffic_type
 */
static int flowtuple_classify_packet(libtrace_packet_t *packet)
{
    void *temp = NULL;
    uint8_t proto;
    uint32_t remaining;

    libtrace_tcp_t *tcp_hdr = NULL;
    libtrace_icmp_t *icmp_hdr = NULL;

    /* 10/19/12 ak removed check for ipv4 because it is checked in per_packet */

    /* get the transport header */
    if ((temp = trace_get_transport(packet, &proto, &remaining)) == NULL) {
        /* not enough payload */
        return CORSARO_FLOWTUPLE_CLASS_OTHER;
    }

    /* check for tcp */
    if (proto == TRACE_IPPROTO_TCP && remaining >= 4) {
        tcp_hdr = (libtrace_tcp_t *)temp;

        /* look for SYNACK or RST */
        if ((tcp_hdr->syn && tcp_hdr->ack) || tcp_hdr->rst) {
            return CORSARO_FLOWTUPLE_CLASS_BACKSCATTER;
        } else {
            return CORSARO_FLOWTUPLE_CLASS_OTHER;
        }
    }
    /* check for icmp */
    else if (proto == TRACE_IPPROTO_ICMP && remaining >= 2) {
        icmp_hdr = (libtrace_icmp_t *)temp;
        if (icmp_hdr->type == 0 || icmp_hdr->type == 3 || icmp_hdr->type == 4 ||
                icmp_hdr->type == 5 || icmp_hdr->type == 11 || icmp_hdr->type == 12 ||
                icmp_hdr->type == 14 || icmp_hdr->type == 16 || icmp_hdr->type == 18) {
            return CORSARO_FLOWTUPLE_CLASS_BACKSCATTER;
        } else {
            return CORSARO_FLOWTUPLE_CLASS_ICMPREQ;
        }
    } else {
        return CORSARO_FLOWTUPLE_CLASS_OTHER;
    }

    return -1;
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
    new_6t->packet_cnt = htonl(increment);
  } else {
    /* simply increment the existing one */
    /*kh_value(hash, khiter)+=increment;*/
    new_6t = kh_key(hash, khiter);

    /* will this cause a wrap? */
    assert((UINT32_MAX - ntohl(new_6t->packet_cnt)) > increment);

    new_6t->packet_cnt = htonl(ntohl(new_6t->packet_cnt) + increment);
  }
  return 0;
}


int corsaro_flowtuple_process_packet(corsaro_plugin_t *p, void *local,
        libtrace_packet_t *packet, corsaro_packet_state_t *pstate) {
    libtrace_ip_t *ip_hdr = NULL;
    libtrace_icmp_t *icmp_hdr = NULL;
    libtrace_tcp_t *tcp_hdr = NULL;
    struct corsaro_flowtuple t;
    int class;

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

    t.ip_len = ip_hdr->ip_len;
    t.src_ip = ip_hdr->ip_src.s_addr;

    CORSARO_FLOWTUPLE_IP_TO_SIXT(ip_hdr->ip_dst.s_addr, &t);

    t.protocol = ip_hdr->ip_p;
    t.tcp_flags = 0; /* in case we don't find a tcp header */

    t.ttl = ip_hdr->ip_ttl;

    if (ip_hdr->ip_p == TRACE_IPPROTO_ICMP &&
            (icmp_hdr = trace_get_icmp(packet)) != NULL) {
        t.src_port = htons(icmp_hdr->type);
        t.dst_port = htons(icmp_hdr->code);
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
        t.src_port = htons(trace_get_source_port(packet));
        t.dst_port = htons(trace_get_destination_port(packet));
    }

    /* classify this packet and increment the appropriate hash */
    if ((class = flowtuple_classify_packet(packet)) < 0) {
        corsaro_log(p->logger, "flowtuple plugin could not classify packet");
        return -1;
    }

    if (class == CORSARO_FLOWTUPLE_CLASS_BACKSCATTER) {
        pstate->flags |= CORSARO_PACKET_STATE_FLAG_BACKSCATTER;
    }

    if (corsaro_flowtuple_add_inc(p->logger, state->st_hash[class], &t, 1) != 0) {
        corsaro_log(p->logger, "could not increment value for flowtuple");
        return -1;
    }
    return 0;
}

int corsaro_flowtuple_rotate_output(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *rot_start) {

    corsaro_flowtuple_config_t *conf;
    struct corsaro_flowtuple_state_t *state;

    FLOWTUPLE_PROC_FUNC_START("corsaro_flowtuple_rotate_output", -1);

    if (state->outfile != NULL) {
        /* we're gonna have to wait for this to close */
        corsaro_file_close(state->outfile);
        state->outfile = NULL;
    }
    return 0;
}

int corsaro_flowtuple_write_result(corsaro_plugin_t *p, void *local,
        corsaro_plugin_result_t *res, corsaro_file_t *out) {

    /* TODO */
    return -1;
}

int corsaro_flowtuple_read_result(corsaro_plugin_t *p, void *local,
        corsaro_file_in_t *in, corsaro_plugin_result_t *res) {


    /* TODO */
    return -1;
}

int corsaro_flowtuple_compare_results(corsaro_plugin_t *p, void *local,
        corsaro_plugin_result_t *res1, corsaro_plugin_result_t *res2) {


    /* TODO */
    return -1;
}

void corsaro_flowtuple_release_result(corsaro_plugin_t *p, void *local,
        corsaro_plugin_result_t *res) {

    /* TODO */
    free(res->resdata);
}

/*
 * Hashes the flowtuple based on the following table
 *
 * With slash eight optimization:
 *         --------------------------------
 *         |           SRC_IP * 59        |
 * ----------------------------------------
 * |       |     DST_IP << 8      | PROTO |
 * ----------------------------------------
 *         | SRC_PORT <<16 |   DST_PORT   |
 *         --------------------------------
 *         |  TTL  |TCP_FLG|     LEN      |
 *         --------------------------------
 *
 * Without slash eight optimization:
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
#ifdef CORSARO_SLASH_EIGHT
  CORSARO_FLOWTUPLE_SHIFT_AND_XOR((ft->dst_ip.b << 24) | (ft->dst_ip.c << 16) |
                                  (ft->dst_ip.d << 8) | (ft->protocol));
#else
  CORSARO_FLOWTUPLE_SHIFT_AND_XOR(ft->dst_ip);
#endif
  CORSARO_FLOWTUPLE_SHIFT_AND_XOR(ft->src_port << 16);
  CORSARO_FLOWTUPLE_SHIFT_AND_XOR(ft->dst_port);
  CORSARO_FLOWTUPLE_SHIFT_AND_XOR((ft->ttl << 24) | (ft->tcp_flags << 16));
#ifdef CORSARO_SLASH_EIGHT
  CORSARO_FLOWTUPLE_SHIFT_AND_XOR(ft->ip_len);
#else
  CORSARO_FLOWTUPLE_SHIFT_AND_XOR((ft->protocol << 8) | (ft->ip_len));
#endif
  return h;
}



// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
