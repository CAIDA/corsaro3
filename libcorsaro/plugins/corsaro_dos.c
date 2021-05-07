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

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <yaml.h>
#include <libtrace/linked_list.h>
#include <Judy.h>
#include <libipmeta.h>

#include "khash.h"
#include "ksort.h"
#include "libcorsaro_plugin.h"
#include "libcorsaro_avro.h"
#include "corsaro_dos.h"
#include "utils.h"

/** The magic number for this plugin - "EDOS" */
#define CORSARO_DOS_MAGIC 0x45444F53
#define PLUGIN_NAME "dos"

/** Initialize the hash types needed to hold maps in vectors
 *
 * The convention is a 4 digit name, where the first two digits indicate
 * the length of the key, and the last two indicate the length of the value
 * e.g. 3264 means 32 bit integer keys with 64bit integer values
 */
KHASH_SET_INIT_INT(32xx)

/** Default values for the various configurable options */

/** Minimum number of packets before a vector is considered an attack */
#define CORSARO_DOS_DEFAULT_VECTOR_MIN_PACKETS 25

/** Minimum duration (in seconds) before a vector is considered an attack */
#define CORSARO_DOS_DEFAULT_VECTOR_MIN_DURATION 60

/** The length of the PPM sliding window (in seconds) */
#define CORSARO_DOS_DEFAULT_PPM_WINDOW_SIZE 60

/** The amount of time to slide the PPM window (in seconds) */
#define CORSARO_DOS_DEFAULT_PPM_WINDOW_PRECISION 10

/** The minimum packet rate before a vector can be an attack */
#define CORSARO_DOS_DEFAULT_VECTOR_MIN_PPM 30

static corsaro_plugin_t corsaro_dos_plugin = {

    PLUGIN_NAME,
    CORSARO_PLUGIN_ID_DOS,
    CORSARO_DOS_MAGIC,
    CORSARO_PLUGIN_GENERATE_BASE_PTRS(corsaro_dos),
    CORSARO_PLUGIN_GENERATE_TRACE_PTRS(corsaro_dos),
    CORSARO_PLUGIN_GENERATE_MERGE_PTRS(corsaro_dos),
    CORSARO_PLUGIN_GENERATE_TAIL
};

/** Configuration options for this plugin */
typedef struct corsaro_dos_config {
    /** Standard options, e.g. template */
    corsaro_plugin_proc_options_t basic;
    /** Minimum number of packets before a vector is considered an attack */
    uint16_t attack_min_packets;
    /** Minimum duration (in seconds) before a vector is considered an attack */
    uint16_t attack_min_duration;
    /** The minimum packet rate before a vector can be an attack */
    uint16_t attack_min_ppm;
    /** The length of the PPM sliding window (in seconds) */
    uint16_t ppm_window_size;
    /** The amount of time to slide the PPM window (in seconds) */
    uint16_t ppm_window_slide;

} corsaro_dos_config_t;

/** State for the sliding packet rate algorithm */
typedef struct ppm_window {
    /** Time of the bottom of the current first window */
    uint32_t window_start;
    /** The number of packets in each bucket */
    uint64_t *buckets;
    /** The bucket that packets are currently being added to */
    uint8_t current_bucket;
    /** The maximum packet rate observed thus far */
    uint64_t max_ppm;
} ppm_window_t;

/** A record to store the packet count for PPM buckets that have expired. */
typedef struct expired_ppm_bucket {
    /** Timestamp at the start of this bucket */
    uint32_t ts;
    /** Number of packets observed during this bucket */
    uint64_t count;
} expired_ppm_bucket_t;

typedef struct attack_flow {
    uint32_t attacker_ip;
    uint16_t attacker_port;
    uint16_t target_port;
    uint16_t pkt_len;
    uint64_t total_packet_count;
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t latest_sec;
    uint32_t latest_usec;
    uint32_t attimestamp;
    uint32_t target_ip;
    uint8_t protocol;
} attack_flow_t;

#define HASHER_SHIFT_AND_XOR(value) h^=(h << 5) + (h >> 27) + (value)
static inline khint32_t attack_flow_hash_func(attack_flow_t *ft) {

    khint32_t h = (khint32_t)(ft->attacker_ip * 59);
    HASHER_SHIFT_AND_XOR(ft->attacker_port << 16);
    HASHER_SHIFT_AND_XOR(ft->target_port);
    return h;
}

#define attack_flow_hash_equal(a,b) \
    ((a)->attacker_ip == (b)->attacker_ip && (a)->pkt_len == (b)->pkt_len && \
     (a)->attacker_port == (b)->attacker_port && \
     (a)->target_port == (b)->target_port)

KHASH_INIT(ft, attack_flow_t *, char, 0, attack_flow_hash_func,
        attack_flow_hash_equal);

/** A record for a potential attack vector
 *
 * All values are in HOST byte order
 */
typedef struct attack_vector {
    /** A copy of the packet that caused the vector to be created
     *
     * Can be reconstituted into a libtrace packet
     */
    uint8_t *initial_packet;

    /** Length of the initial packet (in bytes) */
    uint32_t initial_packet_len;

    /* The transport protocol used to send the attack packet(s) */
    uint8_t protocol;

    /** The IP address of the alleged attacker */
    uint32_t attacker_ip;

    /** The IP address of the host which responded to the attack */
    uint32_t responder_ip;

    /** The IP address of the alleged target of the attack */
    uint32_t target_ip;

    /** The number of packets that comprise this vector */
    uint64_t packet_cnt;

    /** Number of mismatched packets observed */
    uint32_t mismatches;

    /** The number of bytes that comprise this vector */
    uint64_t byte_cnt;

    /** Maximum PPM rate seen during this interval */
    uint32_t maxppminterval;

    /** First attack port seen for this vector */
    uint16_t first_attack_port;

    /** First target port seen for this vector */
    uint16_t first_target_port;

    /** The sliding window packet rate state */
    ppm_window_t ppm_window;

    /** The time of the initial packet */
    struct timeval start_time;

    /** The time of the last packet */
    struct timeval latest_time;

    /** Map of all IP addresses the alleged attack has originated from */
    kh_32xx_t *attack_ip_hash;

    /** Map of all ports that alleged attack packets have originated from */
    kh_32xx_t *attack_port_hash;

    /** Map of all ports that alleged attack packets were directed to */
    kh_32xx_t *target_port_hash;

    /** List containing all expired PPM buckets */
    Pvoid_t ppm_bucket_list;

    /** List of timestamps for all packets associated with this attack */
    libtrace_list_t *packet_timestamps;
    /* XXX right now, packet_timestamps are unused and expensive to keep
     * track off so I've removed the code for this */

    /** Geo-located continent for the target IP, according to maxmind */
    uint16_t maxmind_continent;

    /** Geo-located country for the target IP, according to maxmind */
    uint16_t maxmind_country;

    uint32_t attimestamp;

    /** The number of processing threads that saw this vector -- mostly
     *  used for internal valuation.
     */
    uint32_t thread_cnt;

    corsaro_dos_config_t *config;


} attack_vector_t;

/** Compare two attack vectors for equality */
#define attack_vector_hash_equal(a, b) ((a)->target_ip == (b)->target_ip)

/** Hash an attack vector
 *
 * @param av         The attack vector to be hashed
 */
static inline khint32_t attack_vector_hash_func(attack_vector_t *av)
{
    return (khint32_t)av->target_ip * 59;
}


/** Initialize the hash functions and datatypes */
KHASH_INIT(av, attack_vector_t *, char, 0, attack_vector_hash_func,
           attack_vector_hash_equal);

/** Thread-local state for the DOS plugin */
struct corsaro_dos_state_t {
    /** Timestamp of the last time that we rotated the output file */
    uint32_t last_rotation;
    /** Hash tables for storing the possible attack vectors */
    khash_t(av) *attack_hash_tcp;
    khash_t(av) *attack_hash_udp;
    khash_t(av) *attack_hash_icmp;
    /** ID of the processing thread */
    int threadid;
    /** Timestamp of the most recently processed packet */
    uint32_t lastpktts;
};


typedef struct corsaro_dos_merge_state {
    corsaro_avro_writer_t *mainwriter;
    struct corsaro_dos_state_t *combined;
} corsaro_dos_merge_state_t;

static const char DOS_RESULT_SCHEMA[] =
"{\"type\": \"record\",\
  \"namespace\": \"org.caida.corsaro\",\
  \"name\": \"dos\",\
  \"doc\": \"A Corsaro Dos record. All byte fields are in host byte order,\
             except for the initial packet which is as it appeared on the \
             wire.\",\
  \"fields\": [\
        {\"name\":\"bin_timestamp\", \"type\": \"long\"}, \
        {\"name\":\"initial_packet_len\", \"type\": \"int\"}, \
        {\"name\":\"target_ip\", \"type\": \"long\"}, \
        {\"name\":\"target_protocol\", \"type\": \"int\"}, \
        {\"name\":\"attacker_ip_cnt\", \"type\": \"long\"}, \
        {\"name\":\"attack_port_cnt\", \"type\": \"long\"}, \
        {\"name\":\"target_port_cnt\", \"type\": \"long\"}, \
        {\"name\":\"packet_cnt\", \"type\": \"long\"}, \
        {\"name\":\"icmp_mismatches\", \"type\": \"long\"}, \
        {\"name\":\"byte_cnt\", \"type\": \"long\"}, \
        {\"name\":\"max_ppm_interval\", \"type\": \"long\"}, \
        {\"name\":\"start_time_sec\", \"type\": \"long\"}, \
        {\"name\":\"start_time_usec\", \"type\": \"int\"}, \
        {\"name\":\"latest_time_sec\", \"type\": \"long\"}, \
        {\"name\":\"latest_time_usec\", \"type\": \"int\"}, \
        {\"name\":\"first_attack_port\", \"type\": \"int\"}, \
        {\"name\":\"first_target_port\", \"type\": \"int\"}, \
        {\"name\":\"maxmind_continent\", \"type\": \"string\"}, \
        {\"name\":\"maxmind_country\", \"type\": \"string\"}, \
        {\"name\":\"initial_packet\", \"type\": \"bytes\"} \
        ]}";


corsaro_plugin_t *corsaro_dos_alloc(void) {
    return &(corsaro_dos_plugin);
}

static uint32_t calculate_maximum_ppm(corsaro_dos_config_t *conf,
        Pvoid_t *buckets, uint32_t ts) {

    uint32_t maxppm = 0;
    uint32_t currentwin = 0, prune;
    int i, itemsperwin, rcint;
    PWord_t winstart, pval;
    Word_t index, indexend, indexiter;

    itemsperwin = (conf->ppm_window_size / conf->ppm_window_slide);
    if (itemsperwin <= 0) {
        return 0;
    }

    prune = ts - ((itemsperwin - 1) * conf->ppm_window_slide);

    index = 0;
    JLF(winstart, (*buckets), index);

    while (winstart) {
        if (index < prune) {
            JLD(rcint, (*buckets), index);
            JLN(winstart, (*buckets), index);
            continue;
        }

        /* Plenty of room to optimise this in future */

        indexend = index + conf->ppm_window_size;
        indexiter = index;
        pval = winstart;
        currentwin = 0;

        while (indexiter < indexend && pval != NULL) {
            currentwin += (*pval);
            JLN(pval, (*buckets), indexiter);
        }

        if (currentwin > maxppm) {
            maxppm = currentwin;
        }

        JLN(winstart, (*buckets), index);
    }
    return maxppm;
}

/** Writes a single attack vector to an output file using the AVRO format.
 *
 */
static int dos_to_avro(corsaro_logger_t *logger, avro_value_t *av,
        void *vector) {

    attack_vector_t *vec = (attack_vector_t *)vector;
    avro_value_t field;
    char valspace[3];

    assert(vec->protocol);

    CORSARO_AVRO_SET_FIELD(long, av, field, 0, "bin_timestamp", "dos",
            vec->attimestamp);
    CORSARO_AVRO_SET_FIELD(int, av, field, 1, "initial_packet_len", "dos",
            vec->initial_packet_len);
    CORSARO_AVRO_SET_FIELD(long, av, field, 2, "target_ip", "dos",
            vec->target_ip);
    CORSARO_AVRO_SET_FIELD(int, av, field, 3, "target_protocol", "dos",
            vec->protocol);
    CORSARO_AVRO_SET_FIELD(long, av, field, 4, "attacker_ip_cnt", "dos",
            kh_size(vec->attack_ip_hash));
    CORSARO_AVRO_SET_FIELD(long, av, field, 5, "attack_port_cnt", "dos",
            kh_size(vec->attack_port_hash));
    CORSARO_AVRO_SET_FIELD(long, av, field, 6, "target_port_cnt", "dos",
            kh_size(vec->target_port_hash));
    CORSARO_AVRO_SET_FIELD(long, av, field, 7, "packet_cnt", "dos",
            vec->packet_cnt);
    CORSARO_AVRO_SET_FIELD(long, av, field, 8, "icmp_mismatches", "dos",
            vec->mismatches);
    CORSARO_AVRO_SET_FIELD(long, av, field, 9, "byte_cnt", "dos",
            vec->byte_cnt);
    CORSARO_AVRO_SET_FIELD(long, av, field, 10, "max_ppm_interval", "dos",
            vec->maxppminterval);
    CORSARO_AVRO_SET_FIELD(long, av, field, 11, "start_time_sec", "dos",
            vec->start_time.tv_sec);
    CORSARO_AVRO_SET_FIELD(int, av, field, 12, "start_time_usec", "dos",
            vec->start_time.tv_usec);
    CORSARO_AVRO_SET_FIELD(long, av, field, 13, "latest_time_sec", "dos",
            vec->latest_time.tv_sec);
    CORSARO_AVRO_SET_FIELD(int, av, field, 14, "latest_time_usec", "dos",
            vec->latest_time.tv_usec);
    CORSARO_AVRO_SET_FIELD(int, av, field, 15, "first_attack_port", "dos",
            vec->first_attack_port);
    CORSARO_AVRO_SET_FIELD(int, av, field, 16, "first_target_port", "dos",
            vec->first_target_port);

    if (vec->maxmind_continent == 0) {
        CORSARO_AVRO_SET_FIELD(string, av, field, 17, "maxmind_continent",
                "dos", "??");
    } else {
        valspace[0] = (char)(vec->maxmind_continent & 0xff);
        valspace[1] = (char)((vec->maxmind_continent >> 8) & 0xff);
        valspace[2] = '\0';

        CORSARO_AVRO_SET_FIELD(string, av, field, 17, "maxmind_continent",
                "dos", valspace);
    }

    if (vec->maxmind_country == 0) {
        CORSARO_AVRO_SET_FIELD(string, av, field, 18, "maxmind_country",
                "dos", "??");
    } else {
        valspace[0] = (char)(vec->maxmind_country & 0xff);
        valspace[1] = (char)((vec->maxmind_country >> 8) & 0xff);
        valspace[2] = '\0';

        CORSARO_AVRO_SET_FIELD(string, av, field, 18, "maxmind_country",
                "dos", valspace);
    }

    /* Write the saved bytes from the initial packet. */
    if (avro_value_get_by_index(av, 19, &field, NULL)) {
        corsaro_log(logger,
                "unable to find 'initial_packet' (id 19) in dos schema: %s",
                avro_strerror());
        return -1;
    }

    if (avro_value_set_bytes(&field, vec->initial_packet,
            vec->initial_packet_len)) {
        corsaro_log(logger,
                "unable to set 'initial_packet' (id 19) in dos schema: %s",
                avro_strerror());
        return -1;
    }

    return 0;

}

#define AV_INIT_SUCCESS(av) \
    (av->attack_ip_hash && av->attack_port_hash && av->target_port_hash)

static attack_vector_t *attack_vector_init(int ppmbuckets) {
    attack_vector_t *av = NULL;

    av = calloc(1, sizeof(attack_vector_t));
    if (av == NULL) {
        return NULL;
    }

    av->thread_cnt = 1;
    av->attack_ip_hash = kh_init(32xx);
    av->attack_port_hash = kh_init(32xx);
    av->target_port_hash = kh_init(32xx);
    av->ppm_bucket_list = NULL;
    av->ppm_window.buckets = (uint64_t *)calloc(ppmbuckets, sizeof(uint64_t));
    av->config = NULL;

    /* don't init here, since we'll often be assigning an already existing
     * instance to this pointer */
    av->packet_timestamps = NULL;

    return av;
}

static void attack_vector_free(attack_vector_t *av) {

    attack_flow_t *f;
    khiter_t i;
    int rcint;

    if (av == NULL) {
        return;
    }

    if (av->packet_timestamps) {
        libtrace_list_deinit(av->packet_timestamps);
    }

    if (av->ppm_bucket_list) {
        JLFA(rcint, av->ppm_bucket_list);
    }

    if (av->ppm_window.buckets) {
        free(av->ppm_window.buckets);
    }

    if (av->initial_packet != NULL) {
        free(av->initial_packet);
    }

    if (av->attack_ip_hash) {
        kh_destroy(32xx, av->attack_ip_hash);
    }
    if (av->attack_port_hash) {
        kh_destroy(32xx, av->attack_port_hash);
    }
    if (av->target_port_hash) {
        kh_destroy(32xx, av->target_port_hash);
    }
    free(av);
}


/** Parses the dos plugin-specific configuration options */
int corsaro_dos_parse_config(corsaro_plugin_t *p, yaml_document_t *doc,
        yaml_node_t *options) {

    corsaro_dos_config_t *conf;
    yaml_node_t *key, *value;
    yaml_node_pair_t *pair;

    conf = (corsaro_dos_config_t *)malloc(sizeof(corsaro_dos_config_t));
    if (conf == NULL) {
        corsaro_log(p->logger,
                "unable to allocate memory to store dos plugin config.");
        return -1;
    }

    CORSARO_INIT_PLUGIN_PROC_OPTS(conf->basic);
    conf->attack_min_packets = CORSARO_DOS_DEFAULT_VECTOR_MIN_PACKETS;
    conf->attack_min_duration = CORSARO_DOS_DEFAULT_VECTOR_MIN_DURATION;
    conf->attack_min_ppm = CORSARO_DOS_DEFAULT_VECTOR_MIN_PPM;
    conf->ppm_window_size = CORSARO_DOS_DEFAULT_PPM_WINDOW_SIZE;
    conf->ppm_window_slide = CORSARO_DOS_DEFAULT_PPM_WINDOW_PRECISION;

    if (options->type != YAML_MAPPING_NODE) {
        corsaro_log(p->logger,
                "DOS plugin config should be a map.");
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
                    "min_attack_packets") == 0) {
            conf->attack_min_packets = strtoul(val, NULL, 0);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value,
                    "min_attack_duration") == 0) {
            conf->attack_min_duration = strtoul(val, NULL, 0);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value,
                    "min_attack_packet_rate") == 0) {
            conf->attack_min_ppm = strtoul(val, NULL, 0);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value,
                    "rate_window_size") == 0) {
            conf->ppm_window_size = strtoul(val, NULL, 0);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value,
                    "rate_window_slide") == 0) {
            conf->ppm_window_slide = strtoul(val, NULL, 0);
        }

    }

    p->config = conf;
    return 0;
}

/** Fills in any remaining unset configuration options and ensures that
 *  all user-specified values are within suitable bounds.
 */
int corsaro_dos_finalise_config(corsaro_plugin_t *p,
        corsaro_plugin_proc_options_t *stdopts, void *zmq_ctxt) {

    corsaro_dos_config_t *conf;

    /* Configure standard 'global' options for any options that
     * were not overridden by plugin-specific config.
     */
    conf = (corsaro_dos_config_t *)(p->config);

    conf->basic.template = stdopts->template;
    conf->basic.monitorid = stdopts->monitorid;

    if (conf->ppm_window_size <= 0) {
        corsaro_log(p->logger,
                "'rate_window_size' must be larger than zero.");
        return -1;
    }

    if (conf->ppm_window_slide <= 0) {
        corsaro_log(p->logger,
                "'rate_window_slide' must be larger than zero.");
        return -1;
    }

    if (conf->ppm_window_slide > conf->ppm_window_size) {
        corsaro_log(p->logger,
                "'rate_window_slide' should be <= 'rate_window_size'");
        corsaro_log(p->logger,
                "shrinking 'rate_window_slide' to match the window size.");
        conf->ppm_window_slide = conf->ppm_window_size;
    }

    /* Log our configuration so people know what options we are using. */
    corsaro_log(p->logger,
            "dos plugin: minimum number of packets for an attack vector is %u",
            conf->attack_min_packets);
    corsaro_log(p->logger,
            "dos plugin: minimum duration for an attack vector is %u seconds",
            conf->attack_min_duration);
    corsaro_log(p->logger,
            "dos plugin: minimum packet rate for an attack vector is %u packets per window",
            conf->attack_min_ppm);
    corsaro_log(p->logger,
            "dos plugin: window size is %u seconds", conf->ppm_window_size);
    corsaro_log(p->logger,
            "dos plugin: window slides in increments of %u seconds",
            conf->ppm_window_slide);
    return 0;
}

/** Tidies up any memory that has been allocated for this plugin */
void corsaro_dos_destroy_self(corsaro_plugin_t *p) {
    if (p->config) {
        free(p->config);
    }
    p->config = NULL;
}

/** Initialises thread-local state for using this plugin in packet
 *  processing mode.
 */
void *corsaro_dos_init_processing(corsaro_plugin_t *p, int threadid) {

    struct corsaro_dos_state_t *state;

    state = (struct corsaro_dos_state_t *)malloc(
            sizeof(struct corsaro_dos_state_t));
    if (state == NULL) {
        corsaro_log(p->logger,
                "failed to allocate thread-local state within dos plugin.");
        return NULL;
    }

    state->lastpktts = 0;
    state->attack_hash_tcp = kh_init(av);
    state->attack_hash_udp = kh_init(av);
    state->attack_hash_icmp = kh_init(av);
    state->threadid = threadid;
    state->last_rotation = 0;
    return state;
}


/** Destroys any thread-local state that was allocated by the init_processing
 *  function.
 *
 */
int corsaro_dos_halt_processing(corsaro_plugin_t *p, void *local) {

    struct corsaro_dos_state_t *state;

    state = (struct corsaro_dos_state_t *)local;
    if (state == NULL) {
        return 0;
    }

    kh_free(av, state->attack_hash_tcp, &attack_vector_free);
    kh_free(av, state->attack_hash_udp, &attack_vector_free);
    kh_free(av, state->attack_hash_icmp, &attack_vector_free);
    kh_destroy(av, state->attack_hash_tcp);
    kh_destroy(av, state->attack_hash_udp);
    kh_destroy(av, state->attack_hash_icmp);
    free(state);
    return 0;
}


char *corsaro_dos_derive_output_name(corsaro_plugin_t *p,
        void *local, uint32_t timestamp, int threadid) {

    corsaro_dos_config_t *conf;
    char *outname = NULL;

    conf = (corsaro_dos_config_t *)(p->config);

    outname = corsaro_generate_avro_file_name(conf->basic.template, p->name,
            conf->basic.monitorid, timestamp, threadid);
    if (outname == NULL) {
        corsaro_log(p->logger,
                "failed to generate suitable filename for dos output");
        return NULL;
    }
    return outname;
}

int corsaro_dos_start_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_start) {

    struct corsaro_dos_state_t *state;

    state = (struct corsaro_dos_state_t *)local;
    if (state == NULL) {
        corsaro_log(p->logger,
                "corsaro_dos_start_interval: dos thread-local state is NULL!");
        return -1;
    }

    state->last_rotation = int_start->time;
    return 0;
}


static void attack_vector_update_ppm_window(corsaro_dos_config_t *conf,
        attack_vector_t *av, struct timeval *tv, int forcelast) {

    ppm_window_t *ppm = &(av->ppm_window);
    PWord_t pval;
    int buckoff = (tv->tv_sec - ppm->window_start) / conf->ppm_window_slide;

    /* Keep this simple for now -- the sliding window truly comes into
     * force later on when we combine our processing thread results.
     *
     * Packets still arrive in timestamp order, so we only really need to
     * keep track of the current bucket. Once a bucket is complete,
     * timestamp it and add it to the expired list.
     *
     * At output time, we'll just dump that whole list as an ordered
     * array so we can re-construct the full PPM values at merge time.
     */

    while (buckoff > 0) {
        JLI(pval, av->ppm_bucket_list, ppm->window_start);
        *pval = ppm->buckets[0];

        buckoff --;
        ppm->window_start += conf->ppm_window_slide;
        ppm->buckets[0] = 0;
    }

    if (forcelast && ppm->buckets[0] > 0) {
        JLI(pval, av->ppm_bucket_list, ppm->window_start);
        *pval = ppm->buckets[0];
    } else {
        ppm->buckets[0] ++;
    }
}

static void copy_32hash(kh_32xx_t *orig, kh_32xx_t *copy) {

    khiter_t i;
    int khret;
    uint32_t newval;

    for (i = kh_begin(orig); i != kh_end(orig); ++i) {
        if (!kh_exist(orig, i)) {
            continue;
        }
        newval = kh_key(orig, i);
        kh_put(32xx, copy, newval, &khret);
    }
}

static kh_av_t *copy_attack_hash_table(corsaro_dos_config_t *conf,
        corsaro_logger_t *logger,
        kh_av_t *origmap, uint32_t lastrot, uint32_t endts) {

    kh_av_t *newmap = NULL;
    khiter_t i;
    int khret;
    attack_vector_t *origav, *newav;
    struct timeval endtv;

    endtv.tv_sec = endts;
    endtv.tv_usec = 0;

    newmap = kh_init(av);

    for (i = kh_begin(origmap); i != kh_end(origmap); ++i) {
        if (!kh_exist(origmap, i)) {
            continue;
        }

        origav = kh_key(origmap, i);

        /* If this vector was inactive for the entire interval,
         * skip it and remove it from the original vector map.
         */
        if (origav->latest_time.tv_sec < lastrot) {
            kh_del(av, origmap, i);
            attack_vector_free(origav);
            continue;
        }
        newav = attack_vector_init(1);

        newav->initial_packet_len = origav->initial_packet_len;
        newav->protocol = origav->protocol;
        newav->attacker_ip = origav->attacker_ip;
        newav->responder_ip = origav->responder_ip;
        newav->target_ip = origav->target_ip;
        newav->packet_cnt = origav->packet_cnt;
        newav->byte_cnt = origav->byte_cnt;
        newav->mismatches = origav->mismatches;
        newav->start_time = origav->start_time;
        newav->latest_time = origav->latest_time;
        newav->packet_timestamps = origav->packet_timestamps;
        newav->first_attack_port = origav->first_attack_port;
        newav->first_target_port = origav->first_target_port;
        newav->maxmind_continent = origav->maxmind_continent;
        newav->maxmind_country = origav->maxmind_country;

        newav->initial_packet = (uint8_t *)malloc(origav->initial_packet_len);
        memcpy(newav->initial_packet, origav->initial_packet,
                origav->initial_packet_len);

        attack_vector_update_ppm_window(conf, origav, &endtv, 1);
        newav->ppm_bucket_list = origav->ppm_bucket_list;

        copy_32hash(origav->attack_ip_hash, newav->attack_ip_hash);
        copy_32hash(origav->attack_port_hash, newav->attack_port_hash);
        copy_32hash(origav->target_port_hash, newav->target_port_hash);

        /* Clear the ppm bucket list */
        origav->ppm_bucket_list = NULL;
        origav->packet_timestamps = libtrace_list_init(sizeof(double));
        origav->ppm_window.window_start = endts;
        origav->ppm_window.buckets[0] = 0;

        origav->byte_cnt = 0;
        origav->packet_cnt = 0;
        origav->mismatches = 0;

        kh_clear(32xx, origav->attack_ip_hash);
        kh_clear(32xx, origav->attack_port_hash);
        kh_clear(32xx, origav->target_port_hash);

        kh_put(av, newmap, newav, &khret);
    }

    return newmap;
}

static struct corsaro_dos_state_t *copy_attack_state(corsaro_plugin_t *p,
        struct corsaro_dos_state_t *orig, uint32_t endts) {

    struct corsaro_dos_state_t *copy = NULL;
    corsaro_dos_config_t *conf = (corsaro_dos_config_t *)(p->config);

    copy = (struct corsaro_dos_state_t *)calloc(1,
            sizeof(struct corsaro_dos_state_t));
    if (copy == NULL) {
        corsaro_log(p->logger,
                "OOM while copying attack state in dos plugin.");
        return NULL;
    }

    copy->last_rotation = orig->last_rotation;
    copy->threadid = orig->threadid;
    copy->lastpktts = orig->lastpktts;

    copy->attack_hash_tcp = copy_attack_hash_table(conf, p->logger,
            orig->attack_hash_tcp, orig->last_rotation, endts);
    copy->attack_hash_udp = copy_attack_hash_table(conf, p->logger,
            orig->attack_hash_udp, orig->last_rotation, endts);
    copy->attack_hash_icmp = copy_attack_hash_table(conf, p->logger,
            orig->attack_hash_icmp, orig->last_rotation, endts);

    return copy;
}

void *corsaro_dos_end_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_end, uint8_t complete) {

    struct corsaro_dos_state_t *state, *deepcopy;

    state = (struct corsaro_dos_state_t *)local;

    if (state == NULL) {
        corsaro_log(p->logger,
                "corsaro_dos_end_interval: dos thread-local state is NULL!");
        return NULL;
    }

    deepcopy = copy_attack_state(p, state, int_end->time);
    if (deepcopy == NULL) {
        corsaro_log(p->logger,
                "corsaro_dos_end_interval: unable to deep copy current attack state");
        return NULL;
    }

    return (void *)deepcopy;
}

static inline void process_icmp_packet(libtrace_icmp_t *icmp_hdr,
        uint32_t remaining, uint32_t *targetip, uint16_t *attackport,
        uint16_t *targetport, uint32_t *inner_icmp_src, uint8_t *srcproto) {

    void *temp = NULL;
    libtrace_ip_t *inner_ip_hdr = NULL;

    /* borrowed from libtrace's protocols.h (used by trace_get_*_port) */
    struct ports_t {
        uint16_t src; /**< Source port */
        uint16_t dst; /**< Destination port */
    };

    if (remaining < 2) {
        return;
    }

    switch(icmp_hdr->type) {
        case 3:
        case 4:
        case 5:
        case 11:
        case 12:
            /* ICMP error, let's look at the IP header inside */
            temp = trace_get_payload_from_icmp(icmp_hdr, &remaining);
            break;
        default:
            goto boringicmp;
    }

    if (temp == NULL || remaining < 20) {
        /* Full IP header is not present :( */
        goto boringicmp;
    }

    inner_ip_hdr = (libtrace_ip_t *)temp;
    if (inner_ip_hdr->ip_v != 4) {
        /* Not IPv4 somehow? */
        goto boringicmp;
    }

    *inner_icmp_src = inner_ip_hdr->ip_src.s_addr;      // don't byteswap!
    *targetip = ntohl(inner_ip_hdr->ip_dst.s_addr);
    *srcproto = inner_ip_hdr->ip_p;

    /* Treat the first four bytes of post-IP payload as ports */
    temp = trace_get_payload_from_ip(inner_ip_hdr, NULL, &remaining);
    if (temp == NULL || remaining < 4) {
        return;
    }

    *attackport = ntohs(((struct ports_t *)temp)->src);
    *targetport = ntohs(((struct ports_t *)temp)->dst);
    return;

boringicmp:
    /* Not an interesting ICMP packet, just use code/type as ports */
    *attackport = ntohs(icmp_hdr->code);
    *targetport = ntohs(icmp_hdr->type);

    /* Somewhat of an assumption, but in the absence of any other useful
     * information... */
    *srcproto = TRACE_IPPROTO_ICMP;
    /* Ensure this is zero so our caller will populate with the original
     * source IP. */
    *targetip = 0;
}

/** Searches the hash table for an attack vector that matches the given
 *  packet. If no match is found, this function will create a new
 *  hash entry, insert it into the hash table and return a pointer to the
 *  new attack vector.
 */
static attack_vector_t *match_packet_to_vector(
        corsaro_logger_t *logger, libtrace_packet_t *packet,
        struct corsaro_dos_state_t *state, uint8_t srcproto,
        attack_vector_t *findme, struct timeval *tv,
        corsaro_packet_tags_t *tags) {

    int khret, rem;
    khiter_t khiter;
    attack_vector_t *vector = NULL;
    uint8_t *pkt_buf = NULL;
    libtrace_linktype_t linktype;
    kh_av_t *attack_hash;

    if (srcproto == TRACE_IPPROTO_ICMP) {
        attack_hash = state->attack_hash_icmp;
    } else if (srcproto == TRACE_IPPROTO_TCP) {
        attack_hash = state->attack_hash_tcp;
    } else if (srcproto == TRACE_IPPROTO_UDP) {
        attack_hash = state->attack_hash_udp;
    } else {
        return NULL;
    }

    if ((khiter = kh_get(av, attack_hash, findme)) != kh_end(attack_hash)) {
        /* the vector is in the hash */
        vector = kh_key(attack_hash, khiter);
        return vector;
    }

    vector = attack_vector_init(1);
    if (vector == NULL || !AV_INIT_SUCCESS(vector)) {
        if (vector) {
            attack_vector_free(vector);
        }
        corsaro_log(logger,
                "unable to allocate space for new dos attack vector");
        return NULL;
    }

    pkt_buf = trace_get_layer2(packet, &linktype, &rem);
    if (pkt_buf == NULL) {
        corsaro_log(logger,
                "dos plugin: error while extracting packet buffer");
        attack_vector_free(vector);
        return NULL;
    }

    vector->initial_packet_len = rem;
    if (vector->initial_packet_len > 10000) {
        corsaro_log(logger,
                "dos plugin: bogus packet capture length %u\n", rem);
        attack_vector_free(vector);
        return NULL;
    }

    vector->initial_packet = (uint8_t *)malloc(vector->initial_packet_len);
    if (vector->initial_packet == NULL) {
        corsaro_log(logger,
                "unable to allocate space for packet inside new dos attack vector");
        attack_vector_free(vector);
        return NULL;
    }

    memcpy(vector->initial_packet, pkt_buf, rem);
    vector->target_ip = findme->target_ip;
    vector->protocol = srcproto;
    vector->packet_timestamps = libtrace_list_init(sizeof(double));

    /* Will get populated on return */
    vector->attacker_ip = 0;
    vector->responder_ip = 0;

    vector->maxmind_continent = 0;
    vector->maxmind_country = 0;

    if (tags) {
        uint64_t providers = ntohl(tags->providers_used);

        if (providers & (1 << IPMETA_PROVIDER_MAXMIND)) {
            vector->maxmind_continent = tags->maxmind_continent;
            vector->maxmind_country = tags->maxmind_country;
        }
    }

    khiter = kh_put(av, attack_hash, vector, &khret);
    assert(khret != 0);
    return vector;
}

int corsaro_dos_process_packet(corsaro_plugin_t *p, void *local,
        libtrace_packet_t *packet, corsaro_packet_tags_t *tags) {

    corsaro_dos_config_t *conf;
    struct corsaro_dos_state_t *state;
    void *temp = NULL;
    uint8_t proto;
    uint8_t srcproto;
    uint32_t remaining;
    uint32_t inner_icmp_src = 0;

    libtrace_ip_t *ip_hdr = NULL;

    uint16_t attacker_port = 0;
    uint16_t target_port = 0;
    attack_vector_t findme, *vector;
    attack_flow_t thisflow;
    struct timeval tv;
    double tssecs;
    int khret;

    conf = (corsaro_dos_config_t *)(p->config);
    state = (struct corsaro_dos_state_t *)local;

    if (state == NULL) {
        corsaro_log(p->logger,
                "corsaro_dos_process_packet dos thread-local state is NULL!");
        return -1;
    }

    /* Only care about backscatter traffic in this plugin */
    if (!corsaro_is_backscatter_packet(packet, tags)) {
        return 0;
    }

    ip_hdr = trace_get_ip(packet);
    if (ip_hdr == NULL) {
        return 0;
    }

    temp = trace_get_transport(packet, &proto, &remaining);
    if (temp == NULL) {
        return 0;
    }

    findme.target_ip = 0;

    if (proto == TRACE_IPPROTO_ICMP) {
        process_icmp_packet((libtrace_icmp_t *)temp, remaining,
                &(findme.target_ip), &attacker_port, &target_port,
                &inner_icmp_src, &srcproto);
        if (findme.target_ip == 0) {
            findme.target_ip = ntohl(ip_hdr->ip_src.s_addr);
        }
    } else if (proto == TRACE_IPPROTO_TCP) {
        findme.target_ip = ntohl(ip_hdr->ip_src.s_addr);
        attacker_port = trace_get_destination_port(packet);
        target_port = trace_get_source_port(packet);
        srcproto = TRACE_IPPROTO_TCP;
    }

    if (findme.target_ip == 0) {
        /* Not a TCP or ICMP packet, skip it */

        /* TODO is there any desire to try and recognise UDP attack
         * backscatter?
         */
        return 0;
    }

    thisflow.attacker_ip = ntohl(ip_hdr->ip_dst.s_addr);
    thisflow.attacker_port = attacker_port;
    thisflow.target_port = target_port;
    thisflow.pkt_len = ntohs(ip_hdr->ip_len);

    tv = trace_get_timeval(packet);
    state->lastpktts = tv.tv_sec;
    vector = match_packet_to_vector(p->logger, packet, state, srcproto,
            &findme, &tv, tags);

    if (!vector) {
        return 0;
    }

    if (vector->attacker_ip == 0) {
        /* New vector, grab addresses from IP header */
        vector->attacker_ip = ntohl(ip_hdr->ip_dst.s_addr);
        vector->responder_ip = ntohl(ip_hdr->ip_src.s_addr);

        vector->start_time = tv;
        vector->first_attack_port = attacker_port;
        vector->first_target_port = target_port;

        /* Ensure our windows are aligned to the nearest "slide" interval */
        vector->ppm_window.window_start = state->last_rotation -
                (state->last_rotation % conf->ppm_window_slide);
    }

    if (proto == TRACE_IPPROTO_ICMP) {
        /* Check for mismatches */
        if (inner_icmp_src != 0 && inner_icmp_src != ip_hdr->ip_dst.s_addr) {
            vector->mismatches ++;
        }
    }

    vector->packet_cnt ++;
    vector->byte_cnt += thisflow.pkt_len;
    vector->latest_time = tv;

    tssecs = trace_get_seconds(packet);
    //libtrace_list_push_back(vector->packet_timestamps, &tssecs);
    attack_vector_update_ppm_window(conf, vector, &tv, 0);

    /* add the attacker ip to the hash */
    kh_put(32xx, vector->attack_ip_hash, thisflow.attacker_ip, &khret);

    /* add the ports to the hashes */
    kh_put(32xx, vector->attack_port_hash, attacker_port, &khret);
    kh_put(32xx, vector->target_port_hash, target_port, &khret);

    return 0;
}


/** ------------- MERGING API -------------------- */

static int write_attack_vectors(corsaro_logger_t *logger,
        corsaro_dos_merge_state_t *mstate, kh_av_t *attack_hash,
        uint32_t ts, corsaro_dos_config_t *conf) {


    khiter_t i;
    attack_vector_t *vec;
    avro_value_t *avro;
    double duration;
    struct timeval tvdiff;
    uint32_t thismaxppm = 0;

    for (i = kh_begin(attack_hash); i != kh_end(attack_hash); ++i) {
        if (!kh_exist(attack_hash, i)) {
            continue;
        }

        vec = kh_key(attack_hash, i);

        if (vec->latest_time.tv_sec < ts) {
            /* vector was inactive, delete it */
            kh_del(av, attack_hash, i);
            attack_vector_free(vec);
            continue;
        }

        thismaxppm = calculate_maximum_ppm(conf, &(vec->ppm_bucket_list), ts);
        if (thismaxppm > vec->maxppminterval) {
            vec->maxppminterval = thismaxppm;
        }
        vec->attimestamp = ts;
        vec->config = conf;

        if (vec->maxppminterval < conf->attack_min_ppm) {
            goto resetvec;
        }

        if (vec->packet_cnt < conf->attack_min_packets) {
            goto resetvec;
        }

        timersub(&vec->latest_time, &vec->start_time, &tvdiff);
        duration = tvdiff.tv_sec + ((double)(tvdiff.tv_usec) / 1000000);
        if (duration < conf->attack_min_duration) {
            goto resetvec;
        }

        avro = corsaro_populate_avro_item(mstate->mainwriter, vec, dos_to_avro);
        if (avro == NULL) {
            corsaro_log(logger,
                    "could not convert attack vector to Avro record");
            return -1;
        }

        if (corsaro_append_avro_writer(mstate->mainwriter, avro) < 0) {
            corsaro_log(logger,
                    "could not write attack vector to Avro output file.");
            return -1;
        }

resetvec:
        vec->thread_cnt = 0;
    }
    return 0;
}

void *corsaro_dos_init_merging(corsaro_plugin_t *p, int sources) {

    corsaro_dos_merge_state_t *m;
    m = (corsaro_dos_merge_state_t *)calloc(1,
            sizeof(corsaro_dos_merge_state_t));
    if (m == NULL) {
        return NULL;
    }

    m->mainwriter = corsaro_create_avro_writer(p->logger, DOS_RESULT_SCHEMA);

    if (m->mainwriter == NULL) {
        corsaro_log(p->logger,
                "error while creating main avro writer for dos plugin!");
        free(m);
        return NULL;
    }

    m->combined = calloc(1, sizeof(struct corsaro_dos_state_t));

    m->combined->attack_hash_tcp = kh_init(av);
    m->combined->attack_hash_udp = kh_init(av);
    m->combined->attack_hash_icmp = kh_init(av);
    return m;
}

int corsaro_dos_halt_merging(corsaro_plugin_t *p, void *local) {

    corsaro_dos_merge_state_t *m;

    m = (corsaro_dos_merge_state_t *)(local);
    if (m == NULL) {
         return 0;
    }

    if (m->mainwriter) {
        corsaro_destroy_avro_writer(m->mainwriter);
    }

    if (m->combined) {
        kh_free(av, m->combined->attack_hash_tcp, &attack_vector_free);
        kh_free(av, m->combined->attack_hash_udp, &attack_vector_free);
        kh_free(av, m->combined->attack_hash_icmp, &attack_vector_free);
        kh_destroy(av, m->combined->attack_hash_tcp);
        kh_destroy(av, m->combined->attack_hash_udp);
        kh_destroy(av, m->combined->attack_hash_icmp);
        free(m->combined);
    }

    free(m);
    return 0;
}

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

static int combine_ft_set(kh_ft_t *dest, kh_ft_t *src) {

    khiter_t i, find;
    attack_flow_t *toadd, *existing;
    int khret;

    for (i = kh_begin(src); i != kh_end(src); ++i) {
        if (!kh_exist(src, i)) {
            continue;
        }

        toadd = kh_key(src, i);
        find = kh_get(ft, dest, toadd);
        if (find == kh_end(dest)) {
            /* This flow doesn't exist, so just insert it */
            find = kh_put(ft, dest, toadd, &khret);

            /* Remove toadd from src so it persists once we
             * clear src later on.
             */
            kh_del(ft, src, i);
            continue;
        }

        existing = kh_key(dest, find);
        /* Flow already exists, so try to combine */
        existing->total_packet_count += toadd->total_packet_count;

        if (toadd->ts_sec < existing->ts_sec ||
                (toadd->ts_sec == existing->ts_sec &&
                 toadd->ts_usec < existing->ts_usec)) {

            /* toadd has the earliest packet, so use that timestamp
             * instead...
             */
            existing->ts_sec = toadd->ts_sec;
            existing->ts_usec = toadd->ts_usec;
        }

        if (toadd->latest_sec > existing->latest_sec ||
                (toadd->latest_sec == existing->latest_sec &&
                 toadd->latest_usec > existing->latest_usec)) {

            /* toadd has the most recent packet, so use that timestamp
             * instead...
             */
            existing->latest_sec = toadd->latest_sec;
            existing->latest_usec = toadd->latest_usec;
        }

        /* Don't need to remove toadd, as it'll get cleaned up when its
         * parent attack vector is freed.
         */
    }

    return 0;
}

static int combine_ppm_list(Pvoid_t *a, Pvoid_t *b) {

    PWord_t pval, found;
    Word_t index;

    index = 0;
    JLF(pval, *b, index);
    while (pval) {
        JLI(found, *a, index);
        *found += (*pval);
        JLN(pval, *b, index);
    }

    return 0;
}

static int combine_timestamp_lists(libtrace_list_t **dest, libtrace_list_t *src,
        corsaro_logger_t *logger) {

    libtrace_list_t *newlist = libtrace_list_init(sizeof(double));
    libtrace_list_node_t *a, *b;

    /* Not the most efficient approach, but will do for now... */

    if (dest) {
        a = (*dest)->head;
    } else {
        a = NULL;
    }

    if (src) {
        b = src->head;
    } else {
        b = NULL;
    }

    while (a || b) {
        double ats, bts;
        if (a != NULL) {
            ats = *((double *)(a->data));
        } else {
            ats = 0.0;
        }

        if (b != NULL) {
            bts = *((double *)(b->data));
        } else {
            bts = 0.0;
        }

        if (ats <= 0.0001 || (bts > 0.0001 && bts < ats)) {
            assert(bts >= 0.001);
            libtrace_list_push_back(newlist, &bts);
            b = b->next;
        } else {
            assert(ats >= 0.001);
            libtrace_list_push_back(newlist, &ats);
            a = a->next;
        }
    }

    libtrace_list_deinit(*dest);
    *dest = newlist;
    return 0;
}

static int combine_attack_vectors(kh_av_t *destmap, kh_av_t *srcmap,
        corsaro_logger_t *logger) {

    khiter_t i, find;
    attack_vector_t *existing, *toadd;
    int khret;

    for (i = kh_begin(srcmap); i != kh_end(srcmap); ++i) {
        if (!kh_exist(srcmap, i)) {
            continue;
        }

        toadd = kh_key(srcmap, i);
        find = kh_get(av, destmap, toadd);

        if (find == kh_end(destmap)) {
            /* Target is not already present, so we can just add it */
            find = kh_put(av, destmap, toadd, &khret);

            /* Remove toadd from srcmap so it doesn't get deleted when
             * we clear srcmap afterwards.
             */
            kh_del(av, srcmap, i);
            continue;
        }

        /* Target already exists in destmap, so we need to merge the
         * two results.
         */
        existing = kh_key(destmap, find);
        existing->thread_cnt ++;
        existing->packet_cnt += toadd->packet_cnt;
        existing->mismatches += toadd->mismatches;
        existing->byte_cnt += toadd->byte_cnt;

        if (toadd->start_time.tv_sec < existing->start_time.tv_sec ||
                (toadd->start_time.tv_sec == existing->start_time.tv_sec &&
                 toadd->start_time.tv_usec < existing->start_time.tv_usec)) {
            uint8_t *tmp;

            existing->start_time.tv_sec = toadd->start_time.tv_sec;
            existing->start_time.tv_usec = toadd->start_time.tv_usec;
            existing->first_attack_port = toadd->first_attack_port;
            existing->first_target_port = toadd->first_target_port;

            /* Replace initial packet too, since the "new" vector started
             * before the one we've already got. */
            tmp = existing->initial_packet;
            existing->initial_packet = toadd->initial_packet;
            existing->initial_packet_len = toadd->initial_packet_len;
            toadd->initial_packet = NULL;
            free(tmp);
        }

        if (toadd->latest_time.tv_sec > existing->latest_time.tv_sec ||
                (toadd->latest_time.tv_sec == existing->latest_time.tv_sec &&
                 toadd->latest_time.tv_usec > existing->latest_time.tv_usec)) {
            existing->latest_time.tv_sec = toadd->latest_time.tv_sec;
            existing->latest_time.tv_usec = toadd->latest_time.tv_usec;
        }

        if (toadd->packet_cnt > 0) {

            combine_32_hash(existing->attack_ip_hash, toadd->attack_ip_hash);
            combine_32_hash(existing->attack_port_hash, toadd->attack_port_hash);
            combine_32_hash(existing->target_port_hash, toadd->target_port_hash);

            if (existing->ppm_bucket_list == NULL) {
                existing->ppm_bucket_list = toadd->ppm_bucket_list;
                toadd->ppm_bucket_list = NULL;
            } else {
                combine_ppm_list(&existing->ppm_bucket_list,
                        &toadd->ppm_bucket_list);
            }

            /* expensive and results are not actually used (!) */
            /*
            combine_timestamp_lists(&(existing->packet_timestamps),
                    toadd->packet_timestamps, logger);
            */
        }

        kh_del(av, srcmap, i);
        attack_vector_free(toadd);
    }

    return 0;

}

static int update_combined_result(struct corsaro_dos_state_t *combined,
        struct corsaro_dos_state_t *next, corsaro_logger_t *logger) {

    int ret = 0;

    if (combined->lastpktts < next->lastpktts) {
        combined->lastpktts = next->lastpktts;
    }

    if (combine_attack_vectors(combined->attack_hash_tcp,
            next->attack_hash_tcp, logger) < 0) {
        corsaro_log(logger,
                "error while combining TCP attack vectors");
        ret = -1;
        goto endcombine;
    }

    if (combine_attack_vectors(combined->attack_hash_udp,
            next->attack_hash_udp, logger) < 0) {
        corsaro_log(logger,
                "error while combining UDP attack vectors");
        ret = -1;
        goto endcombine;
    }

    if (combine_attack_vectors(combined->attack_hash_icmp,
            next->attack_hash_icmp, logger) < 0) {
        corsaro_log(logger,
                "error while combining ICMP attack vectors");
        ret = -1;
        goto endcombine;
    }


endcombine:
    /* Free 'next' and everything in it */
    kh_free(av, next->attack_hash_tcp, &attack_vector_free);
    kh_free(av, next->attack_hash_udp, &attack_vector_free);
    kh_free(av, next->attack_hash_icmp, &attack_vector_free);
    kh_destroy(av, next->attack_hash_tcp);
    kh_destroy(av, next->attack_hash_udp);
    kh_destroy(av, next->attack_hash_icmp);
    free(next);

    return ret;

}

int corsaro_dos_merge_interval_results(corsaro_plugin_t *p, void *local,
        void **tomerge, corsaro_fin_interval_t *fin, void *tagsock) {

    corsaro_dos_merge_state_t *m;
    corsaro_dos_config_t *config;
    int i;
    int ret = 0;
    char *outname;

    m = (corsaro_dos_merge_state_t *)(local);
    if (m == NULL) {
        return -1;
    }

    config = (corsaro_dos_config_t *)(p->config);

    /* First step, open an output file if we need one */
    if (!corsaro_is_avro_writer_active(m->mainwriter)) {
        outname = p->derive_output_name(p, local, fin->timestamp, -1);
        if (outname == NULL) {
            return -1;
        }
        if (corsaro_start_avro_writer(m->mainwriter, outname, 0) == -1) {
            free(outname);
            return -1;
        }
        free(outname);
    }

    for (i = 0; i < fin->threads_ended; i++) {
        if (update_combined_result(m->combined,
                (struct corsaro_dos_state_t *)(tomerge[i]),
                p->logger) < 0) {
            corsaro_log(p->logger,
                    "error while merging results from thread %d", i);
            return -1;
        }
    }

    /* Dump combined to our avro file */
    if (write_attack_vectors(p->logger, m,
            m->combined->attack_hash_tcp, fin->timestamp, config) < 0) {
        ret = -1;
        goto endmerge;
    }

    if (write_attack_vectors(p->logger, m,
            m->combined->attack_hash_udp, fin->timestamp, config) < 0) {
        ret = -1;
        goto endmerge;
    }

    if (write_attack_vectors(p->logger, m,
            m->combined->attack_hash_icmp, fin->timestamp, config) < 0) {
        ret = -1;
        goto endmerge;
    }

endmerge:
    return ret;
}

int corsaro_dos_rotate_output(corsaro_plugin_t *p, void *local) {
    corsaro_dos_merge_state_t *m;

    m = (corsaro_dos_merge_state_t *)(local);
    if (m == NULL) {
        return -1;
    }

    if (m->mainwriter == NULL || corsaro_close_avro_writer(m->mainwriter) < 0)
    {
        return -1;
    }

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

