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
#include <libtrace/linked_list.h>

#include "khash.h"
#include "ksort.h"
#include "libcorsaro3_plugin.h"
#include "libcorsaro3_avro.h"
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

/** The length of time that must pass between each output phase */
#define CORSARO_DOS_DEFAULT_DUMP_FREQUENCY 300

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

/** The number of buckets in the sliding window */
/* TODO */

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

    /** All flows seen as part of this attack since the last interval */
    kh_ft_t *interval_flows;

    /** List containing all expired PPM buckets */
    libtrace_list_t *ppm_bucket_list;

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
    corsaro_avro_writer_t *ftwriter;
} corsaro_dos_merge_state_t;

/** Avro schema for the output from this plugin */
static const char DOS_FT_SCHEMA[] =
"{\"type\": \"record\",\
  \"namespace\": \"org.caida.corsaro\",\
  \"name\": \"dos-flowtuple\",\
  \"doc\": \"A Corsaro Dos Flowtuple record. All byte fields are in host \
             byte order.\",\
  \"fields\": [\
        {\"name\": \"target_ip\", \"type\": \"long\"}, \
        {\"name\": \"attacker_ip\", \"type\": \"long\"}, \
        {\"name\": \"attacker_port\", \"type\": \"int\"}, \
        {\"name\": \"target_port\", \"type\": \"int\"}, \
        {\"name\": \"packet_size\", \"type\": \"int\"}, \
        {\"name\": \"total_packets\", \"type\": \"long\"}, \
        {\"name\": \"bin_timestamp\", \"type\": \"long\"}]}";

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
        {\"name\":\"initial_packet\", \"type\": \"bytes\"}, \
        {\"name\":\"thread_cnt\", \"type\": \"int\"}, \
        ]}";


corsaro_plugin_t *corsaro_dos_alloc(void) {
    return &(corsaro_dos_plugin);
}

const char *corsaro_dos_get_avro_schema(void) {
    return DOS_RESULT_SCHEMA;
}

/** Convert the set of flowtuples associated with an attack vector into an
 *  AVRO array that is suitable for writing to an interim (i.e. pre-merge)
 *  output file.
 */
static inline int flow_list_to_avro(corsaro_logger_t *logger,
        avro_value_t *arrayf, attack_vector_t *vec) {

    avro_value_t flowrec, field;
    khiter_t i;
    attack_flow_t *flow;

    for (i = kh_begin(vec->interval_flows);
            i != kh_end(vec->interval_flows); ++i) {
        if (!kh_exist(vec->interval_flows, i)) {
            continue;
        }
        flow = kh_key(vec->interval_flows, i);
        if (avro_value_append(arrayf, &flowrec, NULL)) {
            corsaro_log(logger,
                    "unable to add new array element to 'observed_flows' in dos schema: %s",
                    avro_strerror());
            return -1;
        }

        CORSARO_AVRO_SET_FIELD(long, &flowrec, field, 0, "attacker_ip", "dos",
                flow->attacker_ip);
        CORSARO_AVRO_SET_FIELD(int, &flowrec, field, 1, "attacker_port", "dos",
                flow->attacker_port);
        CORSARO_AVRO_SET_FIELD(int, &flowrec, field, 2, "target_port", "dos",
                flow->target_port);
        CORSARO_AVRO_SET_FIELD(int, &flowrec, field, 3, "packet_size", "dos",
                flow->pkt_len);
        CORSARO_AVRO_SET_FIELD(long, &flowrec, field, 4, "total_packets", "dos",
                flow->total_packet_count);
        CORSARO_AVRO_SET_FIELD(long, &flowrec, field, 5, "start_sec", "dos",
                flow->ts_sec);
        CORSARO_AVRO_SET_FIELD(int, &flowrec, field, 6, "start_usec", "dos",
                flow->ts_usec);
    }

    return 0;
}

uint32_t calculate_maximum_ppm(corsaro_dos_config_t *conf,
        libtrace_list_t *buckets) {


    return 0;
}

/** Writes a single attack vector to an output file using the AVRO format.
 *
 */
static int dos_to_avro(corsaro_logger_t *logger, avro_value_t *av,
        void *vector) {

    attack_vector_t *vec = (attack_vector_t *)vector;
    avro_value_t field;
    avro_value_t arrayf;
    uint32_t maxppm = 0;

    CORSARO_AVRO_SET_FIELD(long, av, field, 0, "bin_timestamp", "dos",
            vec->attimestamp);
    CORSARO_AVRO_SET_FIELD(int, av, field, 1, "initial_packet_len", "dos",
            vec->initial_packet_len);
    CORSARO_AVRO_SET_FIELD(long, av, field, 2, "target_ip", "dos",
            vec->target_ip);
    CORSARO_AVRO_SET_FIELD(long, av, field, 3, "target_protocol", "dos",
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
    CORSARO_AVRO_SET_FIELD(long, av, field, 11, "start_time_sec", "dos",
            vec->start_time.tv_sec);
    CORSARO_AVRO_SET_FIELD(int, av, field, 12, "start_time_usec", "dos",
            vec->start_time.tv_usec);
    CORSARO_AVRO_SET_FIELD(long, av, field, 13, "latest_time_sec", "dos",
            vec->latest_time.tv_sec);
    CORSARO_AVRO_SET_FIELD(int, av, field, 14, "latest_time_usec", "dos",
            vec->latest_time.tv_usec);
    CORSARO_AVRO_SET_FIELD(int, av, field, 16, "thread_cnt", "dos",
            vec->thread_cnt);

    /* Write the saved bytes from the initial packet. */
    if (avro_value_get_by_index(av, 15, &field, NULL)) {
        corsaro_log(logger,
                "unable to find 'initial_packet' (id 15) in dos schema: %s",
                avro_strerror());
        return -1;
    }

    if (avro_value_set_bytes(&field, vec->initial_packet,
            vec->initial_packet_len)) {
        corsaro_log(logger,
                "unable to set 'initial_packet' (id 15) in dos schema: %s",
                avro_strerror());
        return -1;
    }

    /* Find the max PPM to put into max_ppm_interval */
    maxppm = calculate_maximum_ppm(vec->config, vec->ppm_bucket_list);
    CORSARO_AVRO_SET_FIELD(long, av, field, 10, "max_ppm_interval", "dos",
            maxppm);

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
    av->interval_flows = kh_init(ft);
    av->ppm_bucket_list = libtrace_list_init(sizeof(expired_ppm_bucket_t));
    av->ppm_window.buckets = (uint64_t *)calloc(ppmbuckets, sizeof(uint64_t));
    av->config = NULL;

    return av;
}

static void attack_vector_free(attack_vector_t *av) {

    attack_flow_t *f;
    khiter_t i;

    if (av == NULL) {
        return;
    }

    if (av->ppm_bucket_list) {
        libtrace_list_deinit(av->ppm_bucket_list);
    }

    if (av->ppm_window.buckets) {
        free(av->ppm_window.buckets);
    }

    if (av->initial_packet != NULL) {
        free(av->initial_packet);
    }

    if (av->interval_flows) {
        for (i = kh_begin(av->interval_flows);
                i != kh_end(av->interval_flows); ++i) {
            if (!kh_exist(av->interval_flows, i)) {
                continue;
            }
            f = kh_key(av->interval_flows, i);
            free(f);
        }
        kh_clear(ft, av->interval_flows);
        free(av->interval_flows);
    }
    if (av->attack_ip_hash) {
        free(av->attack_ip_hash);
    }
    if (av->attack_port_hash) {
        free(av->attack_port_hash);
    }
    if (av->target_port_hash) {
        free(av->target_port_hash);
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
                "Flowtuple plugin config should be a map.");
        free(conf);
        return -1;
    }

    for (pair = options->data.mapping.pairs.start;
            pair < options->data.mapping.pairs.top; pair ++) {

        char *val = (char *)value->data.scalar.value;
        key = yaml_document_get_node(doc, pair->key);
        value = yaml_document_get_node(doc, pair->value);

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
        corsaro_plugin_proc_options_t *stdopts) {

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
    free(state);

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

    if (state->last_rotation == 0) {
        state->last_rotation = int_start->time;
    }
    return 0;
}


static void attack_vector_update_ppm_window(corsaro_dos_config_t *conf,
        attack_vector_t *av, struct timeval *tv) {

    ppm_window_t *ppm = &(av->ppm_window);
    int buckoff = (tv->tv_sec - ppm->window_start) / conf->ppm_window_slide;
    expired_ppm_bucket_t exp;

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
        uint64_t topop = ppm->buckets[0];

        exp.ts = ppm->window_start;
        exp.count = topop;

        libtrace_list_push_back(av->ppm_bucket_list, &exp);

        buckoff --;
        ppm->window_start += conf->ppm_window_slide;
        ppm->buckets[0] = 0;
    }

    ppm->buckets[0] ++;
}

static inline void copy_ppm_buckets(attack_vector_t *origav,
        attack_vector_t *newav) {

    libtrace_list_node_t *n;
    expired_ppm_bucket_t *buck, buckcopy;

    n = origav->ppm_bucket_list->head;

    while (n) {
        buck = (expired_ppm_bucket_t *)(n->data);
        n = n->next;

        buckcopy.ts = buck->ts;
        buckcopy.count = buck->count;

        libtrace_list_push_back(newav->ppm_bucket_list, &buckcopy);
    }
}

static inline void copy_32hash(kh_32xx_t *orig, kh_32xx_t *copy) {

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

static inline void copy_flowtuples(kh_ft_t *orig, kh_ft_t *copy) {

    khiter_t i;
    int khret;
    attack_flow_t *flow, *newflow;

    for (i = kh_begin(orig); i != kh_end(orig); ++i) {
        if (!kh_exist(orig, i)) {
            continue;
        }

        /* We aren't going to need flow anymore in the processing path,
         * so just assign it to the copy table and clear orig when we're
         * done.
         */
        flow = kh_key(orig, i);
        kh_put(ft, copy, flow, &khret);

        free(flow);
    }
}

static kh_av_t *copy_attack_hash_table(corsaro_logger_t *logger,
        kh_av_t *origmap, uint32_t lastrot) {

    kh_av_t *newmap = NULL;
    khiter_t i;
    int khret;
    attack_vector_t *origav, *newav;

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

        newav->initial_packet = (uint8_t *)malloc(origav->initial_packet_len);
        memcpy(newav->initial_packet, origav->initial_packet,
                origav->initial_packet_len);

        copy_ppm_buckets(origav, newav);

        copy_32hash(origav->attack_ip_hash, newav->attack_ip_hash);
        copy_32hash(origav->attack_port_hash, newav->attack_port_hash);
        copy_32hash(origav->target_port_hash, newav->target_port_hash);

        copy_flowtuples(origav->interval_flows, newav->interval_flows);

        /* Reset the flow table, as this should only contain flows from the
         * current interval.
         */
        kh_clear(ft, origav->interval_flows);

        kh_put(av, newmap, newav, &khret);
    }

    return newmap;
}

static struct corsaro_dos_state_t *copy_attack_state(corsaro_plugin_t *p,
        struct corsaro_dos_state_t *orig) {

    struct corsaro_dos_state_t *copy = NULL;

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

    copy->attack_hash_tcp = copy_attack_hash_table(p->logger,
            orig->attack_hash_tcp, orig->last_rotation);
    copy->attack_hash_udp = copy_attack_hash_table(p->logger,
            orig->attack_hash_udp, orig->last_rotation);
    copy->attack_hash_icmp = copy_attack_hash_table(p->logger,
            orig->attack_hash_icmp, orig->last_rotation);

    return copy;
}

void *corsaro_dos_end_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_end) {

    corsaro_dos_config_t *conf;
    struct corsaro_dos_state_t *state, *deepcopy;

    conf = (corsaro_dos_config_t *)(p->config);
    state = (struct corsaro_dos_state_t *)local;

    if (state == NULL) {
        corsaro_log(p->logger,
                "corsaro_dos_end_interval: dos thread-local state is NULL!");
        return NULL;
    }

    deepcopy = copy_attack_state(p, state);
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

/** Updates the attack vector's flow table based on an observed packet.
 *
 * @param logger    pointer to the logger instance
 * @param vec       the attack vector which this packet has been matched to
 * @param lookup    the relevant details from the observed packet
 * @param tv        the timestamp from the packet
 */
static void update_flow_table(corsaro_logger_t *logger,
        attack_vector_t *vec, attack_flow_t *lookup, struct timeval *tv) {

    attack_flow_t *flow;
    int khret;
    khiter_t khiter;

    if ((khiter = kh_get(ft, vec->interval_flows, lookup)) !=
            kh_end(vec->interval_flows)) {
        /* There already exists a flow that matches this packet, just
         * need to increment packet count.
         */
        flow = kh_key(vec->interval_flows, khiter);
        flow->total_packet_count ++;
        flow->latest_sec = tv->tv_sec;
        flow->latest_usec = tv->tv_usec;
        return;
    }

    /* Not seen this flow before, create a new entry in the flow table */
    flow = (attack_flow_t *)calloc(1, sizeof(attack_flow_t));
    flow->total_packet_count = 1;
    flow->attacker_ip = lookup->attacker_ip;
    flow->attacker_port = lookup->attacker_port;
    flow->target_port = lookup->target_port;
    flow->pkt_len = lookup->pkt_len;
    flow->ts_sec = tv->tv_sec;
    flow->ts_usec = tv->tv_usec;
    flow->latest_sec = tv->tv_sec;
    flow->latest_usec = tv->tv_usec;

    khiter = kh_put(ft, vec->interval_flows, flow, &khret);

}

/** Searches the hash table for an attack vector that matches the given
 *  packet. If no match is found, this function will create a new
 *  hash entry, insert it into the hash table and return a pointer to the
 *  new attack vector.
 */
static inline attack_vector_t *match_packet_to_vector(
        corsaro_logger_t *logger, libtrace_packet_t *packet,
        struct corsaro_dos_state_t *state, uint8_t srcproto,
        attack_vector_t *findme, struct timeval *tv) {

    int khret;
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
        corsaro_log(logger,
                "dos: unexpected protocol in match_packet_to_vector: %u",
                srcproto);
        return NULL;
    }

    if ((khiter = kh_get(av, attack_hash, findme)) != kh_end(attack_hash)) {
        /* the vector is in the hash */
        vector = kh_key(attack_hash, khiter);
        return vector;
    }

    vector = attack_vector_init(1);
    if (vector == NULL || !AV_INIT_SUCCESS(vector)) {
        corsaro_log(logger,
                "unable to allocate space for new dos attack vector");
        return NULL;
    }

    vector->initial_packet_len = (uint32_t)trace_get_capture_length(packet);
    if (vector->initial_packet_len > 10000) {
        corsaro_log(logger,
                "dos plugin: bogus packet capture length %u\n",
                vector->initial_packet_len);
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

    pkt_buf = trace_get_packet_buffer(packet, &linktype, NULL);
    if (pkt_buf == NULL) {
        corsaro_log(logger,
                "dos plugin: error while extracting packet buffer");
        attack_vector_free(vector);
        return NULL;
    }

    memcpy(vector->initial_packet, pkt_buf, vector->initial_packet_len);
    vector->target_ip = findme->target_ip;
    vector->protocol = srcproto;

    /* Will get populated on return */
    vector->attacker_ip = 0;
    vector->responder_ip = 0;

    khiter = kh_put(av, attack_hash, vector, &khret);
    return vector;
}

int corsaro_dos_process_packet(corsaro_plugin_t *p, void *local,
        libtrace_packet_t *packet, corsaro_packet_state_t *pstate) {

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
    int khret;

    conf = (corsaro_dos_config_t *)(p->config);
    state = (struct corsaro_dos_state_t *)local;

    if (state == NULL) {
        corsaro_log(p->logger,
                "corsaro_dos_end_interval: dos thread-local state is NULL!");
        return -1;
    }

    /* Only care about backscatter traffic in this plugin */
    if (!corsaro_is_backscatter_packet(packet)) {
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
            &findme, &tv);

    if (vector->attacker_ip == 0) {
        /* New vector, grab addresses from IP header */
        vector->attacker_ip = ntohl(ip_hdr->ip_dst.s_addr);
        vector->responder_ip = ntohl(ip_hdr->ip_src.s_addr);

        vector->start_time = tv;

        /* Ensure our windows are aligned to the nearest "slide" interval */
        vector->ppm_window.window_start = state->last_rotation -
                (state->last_rotation % conf->ppm_window_slide);
    }

    if (proto == TRACE_IPPROTO_ICMP) {
        /* Check for mismatches */
        if (inner_icmp_src != ip_hdr->ip_dst.s_addr) {
            vector->mismatches ++;
        }
    }

    update_flow_table(p->logger, vector, &thisflow, &tv);

    vector->packet_cnt ++;
    vector->byte_cnt += thisflow.pkt_len;
    vector->latest_time = tv;
    attack_vector_update_ppm_window(conf, vector, &tv);

    /* add the attacker ip to the hash */
    kh_put(32xx, vector->attack_ip_hash, thisflow.attacker_ip, &khret);

    /* add the ports to the hashes */
    kh_put(32xx, vector->attack_port_hash, attacker_port, &khret);
    kh_put(32xx, vector->target_port_hash, target_port, &khret);

    return 0;
}


/** ------------- MERGING API -------------------- */

static int write_attack_vectors(corsaro_logger_t *logger,
        corsaro_avro_writer_t *writer, kh_av_t *attack_hash,
        uint32_t ts, corsaro_dos_config_t *conf) {


    khiter_t i;
    attack_vector_t *vec;
    avro_value_t *avro;

    for (i = kh_begin(attack_hash); i != kh_end(attack_hash); ++i) {
        if (!kh_exist(attack_hash, i)) {
            continue;
        }

        vec = kh_key(attack_hash, i);
        vec->attimestamp = ts;
        vec->config = conf;
        avro = corsaro_populate_avro_item(writer, vec, dos_to_avro);
        if (avro == NULL) {
            corsaro_log(logger,
                    "could not convert attack vector to Avro record");
            return -1;
        }

        if (corsaro_append_avro_writer(writer, avro) < 0) {
            corsaro_log(logger,
                    "could not write attack vector to Avro output file.");
            return -1;
        }
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

    m->ftwriter = corsaro_create_avro_writer(p->logger, DOS_FT_SCHEMA);

    if (m->ftwriter == NULL) {
        corsaro_log(p->logger,
                "error while creating flowtuple avro writer for dos plugin!");
        corsaro_destroy_avro_writer(m->mainwriter);
        free(m);
        return NULL;
    }

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
    if (m->ftwriter) {
        corsaro_destroy_avro_writer(m->ftwriter);
    }

    return 0;
}

static inline int combine_32_hash(kh_32xx_t *dest, kh_32xx_t *src) {

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
        find = kh_get(ft, dest, existing);
        if (find == kh_end(dest)) {
            /* This flow doesn't exist, so just insert it */
            find = kh_put(ft, dest, toadd, &khret);

            /* Remove toadd from src so it persists once we
             * clear src later on.
             */
            kh_del(ft, src, i);
            continue;
        }

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

static int combine_ppm_list(libtrace_list_t *a, libtrace_list_t *b) {

    libtrace_list_node_t *m, *n;
    expired_ppm_bucket_t *bucka, *buckb;

    m = a->head;
    n = b->head;

    while (m != NULL && n != NULL) {
        bucka = (expired_ppm_bucket_t *)(m->data);
        buckb = (expired_ppm_bucket_t *)(n->data);

        printf("%u %lu       %u %lu\n", bucka->ts, bucka->count,
                buckb->ts, buckb->count);

        m = m->next;
        n = n->next;
    }
    printf("***\n");

    assert(m == NULL && n == NULL);
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
        find = kh_get(av, destmap, existing);

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

            /* Replace initial packet too, since the "new" vector started
             * before the one we've already got. */
            tmp = existing->initial_packet;
            existing->initial_packet = toadd->initial_packet;
            existing->initial_packet_len = toadd->initial_packet_len;
            free(tmp);
        }

        combine_32_hash(existing->attack_ip_hash, toadd->attack_ip_hash);
        combine_32_hash(existing->attack_port_hash, toadd->attack_port_hash);
        combine_32_hash(existing->target_port_hash, toadd->target_port_hash);

        combine_ft_set(existing->interval_flows, toadd->interval_flows);

        combine_ppm_list(existing->ppm_bucket_list, toadd->ppm_bucket_list);

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
    free(next);

    return ret;

}

int corsaro_dos_merge_interval_results(corsaro_plugin_t *p, void *local,
        void **tomerge, corsaro_fin_interval_t *fin) {

    corsaro_dos_merge_state_t *m;
    corsaro_dos_config_t *config;
    int i;
    struct corsaro_dos_state_t *combined;
    int ret = 0;

    m = (corsaro_dos_merge_state_t *)(local);
    if (m == NULL) {
        return -1;
    }

    config = (corsaro_dos_config_t *)(p->config);

    /* First step, open an output file if we need one */
    if (!corsaro_is_avro_writer_active(m->mainwriter)) {
        char *outname = p->derive_output_name(p, local, fin->timestamp, -1);
        if (outname == NULL) {
            return -1;
        }
        if (corsaro_start_avro_writer(m->mainwriter, outname) == -1) {
            free(outname);
            return -1;
        }
        free(outname);
    }

    combined = (struct corsaro_dos_state_t *)(tomerge[0]);

    /* Use tomerge[0] as the "combined" result */
    for (i = 1; i < fin->threads_ended; i++) {
        if (update_combined_result(combined,
                (struct corsaro_dos_state_t *)(tomerge[i]),
                p->logger) < 0) {
            corsaro_log(p->logger,
                    "error while merging results from thread %d", i);
            return -1;
        }

    }

    /* Dump combined to our avro file */
    if (write_attack_vectors(p->logger, m->mainwriter,
            combined->attack_hash_tcp, fin->timestamp, config) < 0) {
        ret = -1;
        goto endmerge;
    }

    if (write_attack_vectors(p->logger, m->mainwriter,
            combined->attack_hash_udp, fin->timestamp, config) < 0) {
        ret = -1;
        goto endmerge;
    }

    if (write_attack_vectors(p->logger, m->mainwriter,
            combined->attack_hash_icmp, fin->timestamp, config) < 0) {
        ret = -1;
        goto endmerge;
    }

endmerge:
    /* Free the attack vector maps associated with 'combined' */
    kh_free(av, combined->attack_hash_tcp, &attack_vector_free);
    kh_free(av, combined->attack_hash_udp, &attack_vector_free);
    kh_free(av, combined->attack_hash_icmp, &attack_vector_free);
    free(combined);

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

    if (m->ftwriter == NULL || corsaro_close_avro_writer(m->ftwriter) < 0)
    {
        return -1;
    }

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

