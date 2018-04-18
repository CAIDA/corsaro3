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

struct corsaro_dos_merge_state_t {
    /** Hash tables for storing the possible attack vectors */
    khash_t(av) *attack_hash_tcp;
    khash_t(av) *attack_hash_udp;
    khash_t(av) *attack_hash_icmp;
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


/** Avro schema for the output from this plugin */
static const char DOS_RESULT_SCHEMA[] =
"{\"type\": \"record\",\
  \"namespace\": \"org.caida.corsaro\",\
  \"name\": \"dos\",\
  \"doc\": \"A Corsaro Dos record. All byte fields are in host byte order,\
             except for the initial packet which is as it appeared on the \
             wire.\",\
  \"fields\": [\
        {\"name\":\"at_timestamp\", \"type\": \"long\"}, \
        {\"name\":\"initial_packet_len\", \"type\": \"int\"}, \
        {\"name\":\"target_ip\", \"type\": \"long\"}, \
        {\"name\":\"target_protocol\", \"type\": \"int\"}, \
        {\"name\":\"attacker_ip_cnt\", \"type\": \"long\"}, \
        {\"name\":\"attack_port_cnt\", \"type\": \"long\"}, \
        {\"name\":\"target_port_cnt\", \"type\": \"long\"}, \
        {\"name\":\"packet_cnt\", \"type\": \"long\"}, \
        {\"name\":\"icmp_mismatches\", \"type\": \"long\"}, \
        {\"name\":\"byte_cnt\", \"type\": \"long\"}, \
        {\"name\":\"max_ppm\", \"type\": \"long\"}, \
        {\"name\":\"max_ppm_interval\", \"type\": \"long\"}, \
        {\"name\":\"start_time_sec\", \"type\": \"long\"}, \
        {\"name\":\"start_time_usec\", \"type\": \"int\"}, \
        {\"name\":\"latest_time_sec\", \"type\": \"long\"}, \
        {\"name\":\"latest_time_usec\", \"type\": \"int\"}, \
        {\"name\":\"initial_packet\", \"type\": \"bytes\"}, \
        \
        {\"name\":\"observed_ppms\", \"type\": { \
            \"type\": \"array\", \"items\": { \
                \"name\": \"bucket\", \"type\":\"record\", \
                \"fields\": [\
                    {\"name\": \"timestamp\", \"type\": \"long\"}, \
                    {\"name\": \"packets\", \"type\": \"long\"}]}}},\
        \
        {\"name\":\"observed_flows\", \"type\": { \
            \"type\": \"array\", \"items\": { \
                \"name\": \"flow\", \"type\":\"record\", \
                \"fields\": [\
                    {\"name\": \"attacker_ip\", \"type\": \"long\"}, \
                    {\"name\": \"attacker_port\", \"type\": \"int\"}, \
                    {\"name\": \"target_port\", \"type\": \"int\"}, \
                    {\"name\": \"packet_size\", \"type\": \"int\"}, \
                    {\"name\": \"total_packets\", \"type\": \"long\"}, \
                    {\"name\": \"start_sec\", \"type\": \"long\"}, \
                    {\"name\": \"start_usec\", \"type\": \"int\"}]}}},\
        \
        {\"name\":\"attack_ips\", \"type\": { \
            \"type\": \"array\", \"items\": \
                {\"name\": \"aip\", \"type\": \"long\"}}}, \
        \
        {\"name\":\"attack_ports\", \"type\": { \
            \"type\": \"array\", \"items\": \
                {\"name\": \"aport\", \"type\": \"long\"}}}, \
        \
        {\"name\":\"target_ports\", \"type\": { \
            \"type\": \"array\", \"items\": \
                {\"name\": \"tport\", \"type\": \"long\"}}}, \
        \
        {\"name\":\"thread_cnt\", \"type\": \"int\"}, \
        ]}";


corsaro_plugin_t *corsaro_dos_alloc(void) {
    return &(corsaro_dos_plugin);
}

const char *corsaro_dos_get_avro_schema(void) {
    return DOS_RESULT_SCHEMA;
}

/** Convert the PPM bucket list for an attack vector into an AVRO array
 *  suitable for writing to an interim (i.e. pre-merge) output file.
 */
static inline int ppmarray_to_avro(corsaro_logger_t *logger,
        avro_value_t *arrayf, attack_vector_t *vec) {

    avro_value_t ppmrec;
    avro_value_t field;
    libtrace_list_node_t *n;
    expired_ppm_bucket_t *bkt;

    n = vec->ppm_bucket_list->head;
    while (n) {
        bkt = (expired_ppm_bucket_t *)(n->data);
        n = n->next;

        if (avro_value_append(arrayf, &ppmrec, NULL)) {
            corsaro_log(logger,
                    "unable to add new array element to 'observed_ppms' in dos schema: %s",
                    avro_strerror());
            return -1;
        }

        CORSARO_AVRO_SET_FIELD(long, &ppmrec, field, 0, "timestamp", "dos",
                bkt->ts);
        CORSARO_AVRO_SET_FIELD(long, &ppmrec, field, 1, "packets", "dos",
                bkt->count);

    }

    return 0;
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

/** Convert a set of IPv4 addresses or port numbers into an AVRO array that
 *  is suitable for writing to an interim (i.e. pre-merge) output file.
 */
static inline int kh32hash_to_avro(corsaro_logger_t *logger,
        avro_value_t *arrayf, kh_32xx_t *hmap, const char *name) {

    avro_value_t entry;
    khiter_t i;
    uint32_t kval;

    for (i = kh_begin(hmap); i != kh_end(hmap); ++i) {
        if (!kh_exist(hmap, i)) {
            continue;
        }
        kval = kh_key(hmap, i);
        if (avro_value_append(arrayf, &entry, NULL)) {
            corsaro_log(logger,
                    "unable to add new array element to '%s' in dos schema: %s",
                    name, avro_strerror());
            return -1;
        }

        if (avro_value_set_long(&entry, (int64_t)kval)) {
            corsaro_log(logger,
                    "unable to populate '%s' array in dos schema: %s",
                    name, avro_strerror());
            return -1;
        }
    }

    return 0;
}

/** Writes a single attack vector to an interim (pre-merge) output file
 *  using the AVRO format.
 *
 *  Note that we don't write *all* of the fields in the AVRO schema. This
 *  is because some of those fields will only be derived when the interim
 *  output files are merged.
 */
static int dos_to_avro_intermediate(corsaro_logger_t *logger, avro_value_t *av,
        void *vector) {

    attack_vector_t *vec = (attack_vector_t *)vector;
    avro_value_t field;
    avro_value_t arrayf;

    /* Skip the aggregate stat fields for now, as we'll need to use the
     * full combined hash tables / ppm history from all processing
     * threads to produce an accurate number anyway.
     */
    CORSARO_AVRO_SET_FIELD(long, av, field, 0, "attimestamp", "dos",
            vec->attimestamp);
    CORSARO_AVRO_SET_FIELD(int, av, field, 1, "initial_packet_len", "dos",
            vec->initial_packet_len);
    CORSARO_AVRO_SET_FIELD(long, av, field, 2, "target_ip", "dos",
            vec->target_ip);
    CORSARO_AVRO_SET_FIELD(long, av, field, 3, "target_protocol", "dos",
            vec->protocol);
    CORSARO_AVRO_SET_FIELD(long, av, field, 7, "packet_cnt", "dos",
            vec->packet_cnt);
    CORSARO_AVRO_SET_FIELD(long, av, field, 8, "icmp_mismatches", "dos",
            vec->mismatches);
    CORSARO_AVRO_SET_FIELD(long, av, field, 9, "byte_cnt", "dos",
            vec->byte_cnt);
    CORSARO_AVRO_SET_FIELD(long, av, field, 12, "start_time_sec", "dos",
            vec->start_time.tv_sec);
    CORSARO_AVRO_SET_FIELD(int, av, field, 13, "start_time_usec", "dos",
            vec->start_time.tv_usec);
    CORSARO_AVRO_SET_FIELD(long, av, field, 14, "latest_time_sec", "dos",
            vec->latest_time.tv_sec);
    CORSARO_AVRO_SET_FIELD(int, av, field, 15, "latest_time_usec", "dos",
            vec->latest_time.tv_usec);
    CORSARO_AVRO_SET_FIELD(int, av, field, 22, "thread_cnt", "dos",
            vec->thread_cnt);

    /* Build the more complex structures -- this code is a bit lengthy :/ */
    if (avro_value_get_by_index(av, 16, &field, NULL)) {
        corsaro_log(logger,
                "unable to find 'initial_packet' (id 16) in dos schema: %s",
                avro_strerror());
        return -1;
    }

    if (avro_value_set_bytes(&field, vec->initial_packet,
            vec->initial_packet_len)) {
        corsaro_log(logger,
                "unable to set 'initial_packet' (id 16) in dos schema: %s",
                avro_strerror());
        return -1;
    }

    if (avro_value_get_by_index(av, 17, &arrayf, NULL)) {
        corsaro_log(logger,
                "unable to find 'observed_ppms' (id 17) in dos schema: %s",
                avro_strerror());
        return -1;
    }

    if (ppmarray_to_avro(logger, &arrayf, vec)) {
        corsaro_log(logger,
                "unable to populate 'observed_ppms' (id 17) in dos schema");
        return -1;
    }

    if (avro_value_get_by_index(av, 18, &arrayf, NULL)) {
        corsaro_log(logger,
                "unable to find 'observed_flows' (id 18) in dos schema: %s",
                avro_strerror());
        return -1;
    }

    if (flow_list_to_avro(logger, &arrayf, vec)) {
        corsaro_log(logger,
                "unable to populate 'observed_flows' (id 18) in dos schema");
        return -1;
    }


    if (avro_value_get_by_index(av, 19, &arrayf, NULL)) {
        corsaro_log(logger,
                "unable to find 'attack_ips' (id 19) in dos schema: %s",
                avro_strerror());
        return -1;
    }

    if (kh32hash_to_avro(logger, &arrayf, vec->attack_ip_hash, "attack_ips")) {
        return -1;
    }

    if (avro_value_get_by_index(av, 20, &arrayf, NULL)) {
        corsaro_log(logger,
                "unable to find 'attack_ports' (id 20) in dos schema: %s",
                avro_strerror());
        return -1;
    }

    if (kh32hash_to_avro(logger, &arrayf, vec->attack_port_hash,
            "attack_ports")) {
        return -1;
    }

    if (avro_value_get_by_index(av, 21, &arrayf, NULL)) {
        corsaro_log(logger,
                "unable to find 'target_ports' (id 21) in dos schema: %s",
                avro_strerror());
        return -1;
    }

    if (kh32hash_to_avro(logger, &arrayf, vec->target_port_hash,
            "target_ports")) {
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
    av->interval_flows = kh_init(ft);
    av->ppm_bucket_list = libtrace_list_init(sizeof(expired_ppm_bucket_t));
    av->ppm_window.buckets = (uint64_t *)malloc(sizeof(uint64_t) * ppmbuckets);

    return av;
}

static void attack_vector_free(attack_vector_t *av) {

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

/** Resets any per-interval statistics / properties for an attack vector.
 *
 */
static void attack_vector_reset(attack_vector_t *av) {
    if (av == NULL) {
        return;
    }

    /* Flow table is per-interval, so we need to clear the flow map */
    kh_clear(ft, av->interval_flows);
}


#if 0
/** Writes all of the attack vectors in a given hash map to the currently
 *  open output file.
 */
static int write_all_vectors(corsaro_logger_t *logger,
        struct corsaro_dos_state_t *state, kh_av_t *attack_hash,
        uint32_t ts) {

    khiter_t i;
    attack_vector_t *vec;
    avro_value_t *avro;

    for (i = kh_begin(attack_hash);
            i != kh_end(attack_hash); ++i) {
        if (!kh_exist(attack_hash, i)) {
            continue;
        }

        vec = kh_key(attack_hash, i);

        /* If there have been no new packets for this vector since the last
         * dump, we can probably remove it from the hash table. */
        if (vec->latest_time.tv_sec < state->last_rotation) {
            kh_del(av, attack_hash, i);
            attack_vector_free(vec);
            vec = NULL;
            continue;
        }
        vec->attimestamp = ts;
        avro = corsaro_populate_avro_item(state->writer, vec,
                dos_to_avro_intermediate);
        if (avro == NULL) {
            corsaro_log(logger,
                    "could not convert attack vector to Avro record");
            return -1;
        }

        if (corsaro_append_avro_writer(state->writer, avro) < 0) {
            corsaro_log(logger,
                    "could not write attack vector to Avro output file.");
            return -1;
        }

        attack_vector_reset(vec);
    }

    return 0;
}

/** Writes all of the currently active attack vectors out to an
 *  output file.
 */
static int dump_attack_state(corsaro_plugin_t *p, void *local,
        struct corsaro_dos_state_t *state, uint32_t endtime) {

    if (!corsaro_is_avro_writer_active(state->writer)) {
        /* Open a new output file */
        char *outname = NULL;
        outname = corsaro_dos_derive_output_name(p, local,
                state->last_rotation, state->threadid);
        if (outname == NULL) {
            return -1;
        }
        if (corsaro_start_avro_writer(state->writer, outname) < 0) {
            corsaro_log(p->logger,
                    "failed to open dos output file %s", outname);
            free(outname);
            return -1;
        }

        free(outname);
    }

    if (write_all_vectors(p->logger, state, state->attack_hash_tcp,
            endtime) < 0) {
        corsaro_log(p->logger,
                "error while dumping TCP vectors to dos output file");
        return -1;
    }
    if (write_all_vectors(p->logger, state, state->attack_hash_udp,
            endtime) < 0) {
        corsaro_log(p->logger,
                "error while dumping UDP vectors to dos output file");
        return -1;
    }
    if (write_all_vectors(p->logger, state, state->attack_hash_icmp,
            endtime) < 0) {
        corsaro_log(p->logger,
                "error while dumping ICMP vectors to dos output file");
        return -1;
    }

    return 0;
}
#endif


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
 *  Will also enforce a dump if none have ever occurred -- this ensures that
 *  you will get at least some output, even if your dump interval is longer
 *  than the duration of the capture.
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

        flow = kh_key(orig, i);
        newflow = (attack_flow_t *)calloc(1, sizeof(attack_flow_t));

        /* All static types so I can just do a bulk memcpy */
        memcpy(newflow, flow, sizeof(attack_flow_t));
        kh_put(ft, copy, newflow, &khret);
    }
}

static kh_av_t *copy_attack_hash_table(corsaro_logger_t *logger,
        kh_av_t *origmap) {

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
            orig->attack_hash_tcp);
    copy->attack_hash_udp = copy_attack_hash_table(p->logger,
            orig->attack_hash_udp);
    copy->attack_hash_icmp = copy_attack_hash_table(p->logger,
            orig->attack_hash_icmp);

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

void *corsaro_dos_init_merging(corsaro_plugin_t *p, int sources) {

    return NULL;
}

int corsaro_dos_halt_merging(corsaro_plugin_t *p, void *local) {

    return 0;
}

int corsaro_dos_merge_interval_results(corsaro_plugin_t *p, void *local,
        void **tomerge, corsaro_fin_interval_t *fin) {

    return 0;
}

int corsaro_dos_rotate_output(corsaro_plugin_t *p, void *local) {

    return 0;
}


#if 0
static inline int avro_to_ppmarray(corsaro_logger_t *logger,
        attack_vector_t *vec, avro_value_t *arrayf, size_t arraysize) {

    int i;
    avro_value_t avvalue;
    int64_t avlong;

    for (i = 0; i < arraysize; i++) {
        expired_ppm_bucket_t bkt;

        if (avro_value_get_by_index(arrayf, (size_t)i, &avvalue, NULL)) {
            corsaro_log(logger,
                    "unable to get value at index %d in observed_ppms array (dos plugin)",
                    i);
            return -1;
        }

        if (corsaro_get_avro_long(&avvalue, &avlong, "timestamp",
                    "dos:observed_ppms", logger)) {
            return -1;
        }
        bkt.ts = (uint32_t)(avlong);

        if (corsaro_get_avro_long(&avvalue, &avlong, "packets",
                    "dos:observed_ppms", logger)) {
            return -1;
        }
        bkt.count = (uint32_t)(avlong);

        libtrace_list_push_back(vec->ppm_bucket_list, &bkt);
    }
    return 0;

}

static inline int avro_to_kh32hash(corsaro_logger_t *logger,
        kh_32xx_t *hmap, avro_value_t *arrayf, size_t arraysize,
        const char *arrayname) {

    int i;
    avro_value_t avvalue;
    int64_t avlong;

    for (i = 0; i < arraysize; i++) {
        int khret;
        uint32_t val;

        if (avro_value_get_by_index(arrayf, (size_t)i, &avvalue, NULL)) {
            corsaro_log(logger,
                    "unable to get value at index %d in %s array (dos plugin)",
                    i, arrayname);
            return -1;
        }

        if (avro_value_get_long(&avvalue, &avlong)) {
            corsaro_log(logger,
                    "unable to extract int64 from %s array (dos plugin)",
                    arrayname);
            return -1;
        }
        val = (uint32_t)(avlong);
        kh_put(32xx, hmap, val, &khret);
    }

    return 0;
}

static inline int avro_to_flow_list(corsaro_logger_t *logger,
        attack_vector_t *vec, avro_value_t *arrayf, size_t arraysize) {

    int i;
    avro_value_t avvalue;
    int64_t avlong;
    int32_t avint;

    for (i = 0; i < arraysize; i++) {
        attack_flow_t *flow;
        khiter_t khiter;
        int khret;

        if (avro_value_get_by_index(arrayf, (size_t)i, &avvalue, NULL)) {
            corsaro_log(logger,
                    "unable to get value at index %d in observed_flows array (dos plugin)",
                    i);
            return -1;
        }

        flow = (attack_flow_t *)calloc(1, sizeof(attack_flow_t));

        if (corsaro_get_avro_long(&avvalue, &avlong, "attacker_ip",
                "dos:observed_flows", logger)) {
            return -1;
        }
        flow->attacker_ip = (uint32_t)avlong;

        if (corsaro_get_avro_int(&avvalue, &avint, "attacker_port",
                "dos:observed_flows", logger)) {
            return -1;
        }
        flow->attacker_port = (uint16_t)avint;

        if (corsaro_get_avro_int(&avvalue, &avint, "target_port",
                "dos:observed_flows", logger)) {
            return -1;
        }
        flow->target_port = (uint16_t)avint;

        if (corsaro_get_avro_int(&avvalue, &avint, "packet_size",
                "dos:observed_flows", logger)) {
            return -1;
        }
        flow->pkt_len = (uint16_t)avint;

        if (corsaro_get_avro_long(&avvalue, &avlong, "total_packets",
                "dos:observed_flows", logger)) {
            return -1;
        }
        flow->total_packet_count = (uint64_t)avlong;

        if (corsaro_get_avro_long(&avvalue, &avlong, "start_sec",
                "dos:observed_flows", logger)) {
            return -1;
        }
        flow->ts_sec = (uint32_t)avlong;

        if (corsaro_get_avro_int(&avvalue, &avint, "start_usec",
                "dos:observed_flows", logger)) {
            return -1;
        }
        flow->ts_usec = (uint32_t)avint;

        khiter = kh_put(ft, vec->interval_flows, flow, &khret);
    }
    return 0;

}

static attack_vector_t *avro_to_vector(corsaro_logger_t *logger,
        avro_value_t *av) {

    attack_vector_t *avec = NULL;
    avro_value_t avvalue, avcomp;
    int64_t avlong;
    int32_t avint;
    size_t compsize;
    void *pktbytes = NULL;

    /* This function is so long that it hurts */

    avec = attack_vector_init(1);

    /* Start with the basic integer fields */

    if (corsaro_get_avro_long(av, &avlong, "at_timestamp", "dos", logger)) {
        goto fail;
    }
    avec->attimestamp = (uint32_t)(avlong);

    if (corsaro_get_avro_int(av, &avint, "initial_packet_len", "dos", logger)) {
        goto fail;
    }
    avec->initial_packet_len = (uint32_t)(avint);

    if (corsaro_get_avro_long(av, &avlong, "target_ip", "dos", logger)) {
        goto fail;
    }
    avec->target_ip = (uint32_t)(avlong);

    if (corsaro_get_avro_long(av, &avlong, "target_protocol", "dos", logger)) {
        goto fail;
    }
    avec->protocol = (uint8_t)(avlong);

    if (corsaro_get_avro_long(av, &avlong, "packet_cnt", "dos", logger)) {
        goto fail;
    }
    avec->packet_cnt = (uint64_t)(avlong);

    if (corsaro_get_avro_long(av, &avlong, "icmp_mismatches", "dos", logger)) {
        goto fail;
    }
    avec->mismatches = (uint32_t)(avlong);

    if (corsaro_get_avro_long(av, &avlong, "byte_cnt", "dos", logger)) {
        goto fail;
    }
    avec->byte_cnt = (uint64_t)(avlong);

    if (corsaro_get_avro_long(av, &avlong, "start_time_sec", "dos", logger)) {
        goto fail;
    }
    avec->start_time.tv_sec = (uint32_t)(avlong);

    if (corsaro_get_avro_int(av, &avint, "start_time_usec", "dos", logger)) {
        goto fail;
    }
    avec->start_time.tv_usec = (uint32_t)(avint);

    if (corsaro_get_avro_long(av, &avlong, "latest_time_sec", "dos", logger)) {
        goto fail;
    }
    avec->latest_time.tv_sec = (uint32_t)(avlong);

    if (corsaro_get_avro_int(av, &avint, "latest_time_usec", "dos", logger)) {
        goto fail;
    }
    avec->latest_time.tv_usec = (uint32_t)(avint);

    if (corsaro_get_avro_int(av, &avint, "thread_cnt", "dos", logger)) {
        goto fail;
    }
    avec->thread_cnt = (uint32_t)(avint);

    if (corsaro_get_avro_bytes(av, &pktbytes, "initial_packet", "dos", logger))
    {
        goto fail;
    }
    avec->initial_packet = (uint8_t *)(pktbytes);

    /* Now deal with the compound structures */

    if (corsaro_get_avro_array(av, &avcomp, &compsize, "observed_ppms", "dos",
            logger)) {
        goto fail;
    }

    if (avro_to_ppmarray(logger, avec, &avcomp, compsize)) {
        goto fail;
    }

    if (corsaro_get_avro_array(av, &avcomp, &compsize, "observed_flows", "dos",
            logger)) {
        goto fail;
    }

    if (avro_to_flow_list(logger, avec, &avcomp, compsize)) {
        goto fail;
    }

    if (corsaro_get_avro_array(av, &avcomp, &compsize, "attack_ips", "dos",
            logger)) {
        goto fail;
    }

    if (avro_to_kh32hash(logger, avec->attack_ip_hash, &avcomp, compsize,
            "attack_ips")) {
        goto fail;
    }

    if (corsaro_get_avro_array(av, &avcomp, &compsize, "attack_ports", "dos",
            logger)) {
        goto fail;
    }

    if (avro_to_kh32hash(logger, avec->attack_port_hash, &avcomp, compsize,
            "attack_ports")) {
        goto fail;
    }

    if (corsaro_get_avro_array(av, &avcomp, &compsize, "target_ports", "dos",
            logger)) {
        goto fail;
    }

    if (avro_to_kh32hash(logger, avec->target_port_hash, &avcomp, compsize,
            "target_ports")) {
        goto fail;
    }

    return avec;

fail:
    if (avec) {
        attack_vector_free(avec);
    }
    return NULL;
}

static int combine_attack_vectors(attack_vector_t *avec, attack_vector_t *ext)
{
    
    avec->packet_cnt += ext->packet_cnt;
    avec->mismatches += ext->mismatches;
    avec->byte_cnt += ext->byte_cnt;

    if (ext->start_time.tv_sec < avec->start_time.tv_sec ||
            (ext->start_time.tv_sec == avec->start_time.tv_sec &&
             ext->start_time.tv_usec < avec->start_time.tv_usec)) {
        uint8_t *tmp;

        ext->start_time.tv_sec = avec->start_time.tv_sec;
        ext->start_time.tv_usec = avec->start_time.tv_usec;

        /* Replace initial packet too, since the "new" vector started
         * before the one we've already got. */
        tmp = ext->initial_packet;
        ext->initial_packet = avec->initial_packet;
        ext->initial_packet_len = avec->initial_packet_len;
        free(tmp);
    }


}

void *corsaro_dos_init_reading(corsaro_plugin_t *p, int sources) {

    struct corsaro_dos_merge_state_t *state;

    state = (struct corsaro_dos_merge_state_t *)malloc(
            sizeof(struct corsaro_dos_merge_state_t));
    if (state == NULL) {
        corsaro_log(p->logger,
                "failed to allocate thread-local merge state in dos plugin.");
        return NULL;
    }

    state->attack_hash_tcp = kh_init(av);
    state->attack_hash_udp = kh_init(av);
    state->attack_hash_icmp = kh_init(av);
    return state;
}

int corsaro_dos_halt_reading(corsaro_plugin_t *p, void *local) {
    struct corsaro_dos_merge_state_t *state;

    state = (struct corsaro_dos_merge_state_t *)local;
    if (state == NULL) {
        return 0;
    }

    kh_free(av, state->attack_hash_tcp, &attack_vector_free);
    kh_free(av, state->attack_hash_udp, &attack_vector_free);
    kh_free(av, state->attack_hash_icmp, &attack_vector_free);
    free(state);
    return 0;
}

int corsaro_dos_compare_results(corsaro_plugin_t *p, void *local,
        corsaro_plugin_result_t *res1, corsaro_plugin_result_t *res2) {

    if (res1->pluginfmt == NULL) {
        res1->pluginfmt = (void *)avro_to_vector(p->logger, res1->avrofmt);
    }
    if (res2->pluginfmt == NULL) {
        res2->pluginfmt = (void *)avro_to_vector(p->logger, res2->avrofmt);
    }

    if (((attack_vector_t *)(res1->pluginfmt))->target_ip <
            ((attack_vector_t *)(res2->pluginfmt))->target_ip) {
        return -1;
    }

    return (((attack_vector_t *)(res1->pluginfmt))->target_ip >
        ((attack_vector_t *)(res2->pluginfmt))->target_ip);
}

void corsaro_dos_release_result(corsaro_plugin_t *p, void *local,
        corsaro_plugin_result_t *res) {

    if (res->pluginfmt) {
        attack_vector_free((attack_vector_t *)res->pluginfmt);
    }

    res->type = CORSARO_RESULT_TYPE_BLANK;
    res->pluginfmt = NULL;
    res->avrofmt = NULL;

}

int corsaro_dos_update_merge(corsaro_plugin_t *p, void *local,
        corsaro_plugin_result_t *res) {

    struct corsaro_dos_merge_state_t *state;
    attack_vector_t *avec = NULL;
    attack_vector_t *existing = NULL;
    kh_av_t *hashmap = NULL;
    khiter_t khiter;
    int khret;

    state = (struct corsaro_dos_merge_state_t *)local;
    if (state == NULL) {
        return -1;
    }


    if (res->pluginfmt == NULL) {
        res->pluginfmt = (void *)avro_to_vector(p->logger, res->avrofmt);
    }

    avec = (attack_vector_t *)(res->pluginfmt);
    if (avec == NULL) {
        corsaro_log(p->logger, "dos plugin cannot merge NULL attack vector!");
        return -1;
    }

    switch(avec->protocol) {
        case TRACE_IPPROTO_ICMP:
            hashmap = state->attack_hash_icmp;
            break;
        case TRACE_IPPROTO_TCP:
            hashmap = state->attack_hash_tcp;
            break;
        case TRACE_IPPROTO_UDP:
            hashmap = state->attack_hash_udp;
            break;
        default:
            hashmap = NULL;
    }

    if (hashmap == NULL) {
        return 1;
    }

    /* Is this target in our hash maps? If not, just straight up add it */
    if ((khiter = kh_get(av, hashmap, avec)) == kh_end(hashmap)) {
        khiter = kh_put(av, hashmap, avec, &khret);
        /* Prevent the vector from being freed by the release callback */
        res->pluginfmt = NULL;
        return 0;
    }

    /* Otherwise, we'll have to combine two attack vectors */
    existing = kh_key(hashmap, khiter);
    if (combine_attack_vectors(existing, avec) < 0) {
        corsaro_log(p->logger,
                "dos plugin was unable to combine two attack vectors for target IP %u",
                avec->target_ip);
        return -1;
    }

    return 1;
}

int corsaro_dos_get_merged_result(corsaro_plugin_t *p, void *local,
        corsaro_plugin_result_t *res) {

    /* Don't forget to check minimum packet counts, rates, durations etc
     * before returning a vector as a result!
     */

    return 0;
}
#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

