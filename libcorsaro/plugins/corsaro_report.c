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
#include <libipmeta.h>
#include <libtrace/message_queue.h>
#include <errno.h>
#include <math.h>
#include <zmq.h>
#include <Judy.h>

#include "libcorsaro.h"
#include "libcorsaro_plugin.h"
#include "libcorsaro_common.h"
#include "libcorsaro_avro.h"
#include "libcorsaro_libtimeseries.h"
#include "corsaro_report.h"
#include "utils.h"

/** Broad overview of this whole plugin, since it is a *bit* complicated.
 *
 *  Our goal is to count the number of packets, bytes, source IPs and
 *  dest IPs observed per minute for each supported metric.
 *
 *  The IP counting is the challenging part, as we need to keep track of
 *  which IPs we've seen already so as not to count them twice, but we also
 *  need to account for the possibility that an IP can appear on multiple
 *  processing threads.
 *  Also, on the telescope we can end up seeing a LOT of unique IPs even in
 *  the space of a minute so we have to be careful about both memory usage and
 *  CPU time efficiency.
 *
 *  Here's how it all works out:
 *  We start with N packet processing threads, as with any other plugin.
 *  We use parallel libtrace to funnel packets to each thread using our
 *  standard hashing approach.
 *
 *  We also create a set of IP tracker threads (4 by default). Each of
 *  the IP tracker threads has a queue associated with it and the queues
 *  are available to the packet processing threads.
 *
 *  For each packet received by a packet processing thread, we...
 *    - grab the source IP address
 *    - map that IP address to one of the IP tracker threads using a
 *      consistent deterministic function.
 *    - update an internal map (keyed by the IP address) that keeps track
 *      of each tag observed for that address and increment the number of
 *      packets and bytes seen for each IP + tag combination that applies
 *      to this packet. There is one map per tracker thread.
 *    - repeat for the destination address, but do NOT increment packets
 *      or bytes for each metric (otherwise we count the packet twice).
 *    - when we have either a decent number of IP addresses in a map, or
 *      a single IP address accumulates a large number of tags, create a
 *      message to send to the corresponding IP tracker containing all of
 *      the IPs, their tags and the packet/byte counts for each tag. Send
 *      the message and reset the map for that tracker thread.
 *
 *  At the end of the interval, our packet processing thread pushes on an
 *  "interval" message to each IP tracker thread to signal that it has sent
 *  all of the packets for that interval.
 *
 *  At the same time, an IP tracker thread continuously reads messages from
 *  its queue. Update messages are used to update the thread's internal
 *  record of all observed IPs, the metrics that apply to each IP and the
 *  byte, IP and packet tallies for each metric. When an interval message
 *  has been received from all processing threads, the final tally for the
 *  tracker thread is confirmed and the "last" interval timestamp is updated
 *  to signify that the tally is complete.
 *
 *  Finally, the merge thread waits for an interval end trigger from the
 *  processing loop. Once received, it will poll until all of the tracker
 *  threads have signalled that their tally for that interval is complete.
 *  As tallies become available, the merge thread simply adds them together
 *  since there should be no tallies containing overlapping IPs (because of
 *  the hash of IP address to IP tracker thread). Once all tallies have been
 *  received, the combined tally is turned into Avro records and written to
 *  the results file.
 */



/** The magic number for this plugin - "REPT" */
#define CORSARO_REPORT_MAGIC 0x52455054

/** The name for this plugin */
#define PLUGIN_NAME "report"

/** An upper bound on the number of possible ports */
#define METRIC_PORT_MAX (65536)
/** An upper bound on the number of ICMP message types and codes */
#define METRIC_ICMP_MAX (256)
/** An upper bound on the number of post-IP protocols */
#define METRIC_IPPROTOS_MAX (256)

/** Maximum number of IP tracker threads allowed */
#define CORSARO_REPORT_MAX_IPTRACKERS (8)

/* Note: these pre-defined alpha-2 codes are used to bootstrap the
 * results data so that we can reliably report 0 values for countries
 * that do not appear in a given interval, even if we've never seen that
 * country code before.
 * The list does not have to be exhaustive -- country codes that appear
 * but are not in the list below will begin to be reported as soon as they
 * are observed and all subsequent intervals should include results for
 * the 'new' code even if the packet count was zero. It is only intervals
 * prior to the country code being observed by the running instance of the
 * report plugin that will have missing values (in that case).
 */

/* Pre-defined alpha-2 codes for continents */
#define CORSAROTRACE_NUM_CONTINENTS (8)
const char *alpha2_continents[] = {
    "??", "AF", "AN", "AS", "EU", "NA", "OC", "SA",
};

/* Pre-defined alpha-2 codes for countries */
#define CORSAROTRACE_NUM_COUNTRIES (255)
const char *alpha2_countries[] = {
    "??", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS",
    "AT", "AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH",
    "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV", "BW",
    "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM",
    "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK",
    "DM", "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ",
    "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI",
    "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK",
    "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ",
    "IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM",
    "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR",
    "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH",
    "MK", "ML", "MM", "MN", "MO", "MP", "MQ" ,"MR", "MS", "MT", "MU", "MV",
    "MW", "MX", "MY", "MZ", "NA", "NC" ,"NE", "NF", "NG", "NI", "NL", "NO",
    "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL",
    "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU",
    "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL",
    "SM", "SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD",
    "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR", "TT", "TV",
    "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG",
    "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW",
    "A1", "A2", "O1", "AP", "EU",
};

/** Common plugin information and function callbacks */
static corsaro_plugin_t corsaro_report_plugin = {
    PLUGIN_NAME,
    CORSARO_PLUGIN_ID_REPORT,
    CORSARO_REPORT_MAGIC,
    CORSARO_PLUGIN_GENERATE_BASE_PTRS(corsaro_report),
    CORSARO_PLUGIN_GENERATE_TRACE_PTRS(corsaro_report),
    CORSARO_PLUGIN_GENERATE_MERGE_PTRS(corsaro_report),
    CORSARO_PLUGIN_GENERATE_TAIL
};

/** Metrics that are supported by the report plugin */
typedef enum {
    CORSARO_METRIC_CLASS_COMBINED,
    CORSARO_METRIC_CLASS_MAXMIND_CONTINENT,
    CORSARO_METRIC_CLASS_MAXMIND_COUNTRY,
    CORSARO_METRIC_CLASS_NETACQ_CONTINENT,
    CORSARO_METRIC_CLASS_NETACQ_COUNTRY,
    CORSARO_METRIC_CLASS_PREFIX_ASN,
    CORSARO_METRIC_CLASS_TCP_SOURCE_PORT,
    CORSARO_METRIC_CLASS_TCP_DEST_PORT,
    CORSARO_METRIC_CLASS_UDP_SOURCE_PORT,
    CORSARO_METRIC_CLASS_UDP_DEST_PORT,
    CORSARO_METRIC_CLASS_IP_PROTOCOL,
    CORSARO_METRIC_CLASS_ICMP_CODE,
    CORSARO_METRIC_CLASS_ICMP_TYPE,
} corsaro_report_metric_class_t;

/** Types of messages that can be sent to the IP tracker threads */
enum {
    CORSARO_IP_MESSAGE_HALT,        /**< Halt tracker thread */
    CORSARO_IP_MESSAGE_UPDATE,      /**< Message contains new stats */
    CORSARO_IP_MESSAGE_INTERVAL,    /**< Interval has ended, begin tally */
    CORSARO_IP_MESSAGE_RESET        /**< Force tallies to be reset */
};

/** Structure describing an IP address that has been observed by an IP
 *  tracker thread.
 *
 *  Unlike all other hashed structures, this one is more efficient to
 *  manage using uthash rather than khash.
 */
typedef struct corsaro_ip_hash {

    /** The IP address as a 32 bit integer */
    uint32_t ipaddr;

    /** Number of metrics associated with this IP. */
    uint32_t metriccount;

    /** Judy array used to store associated metrics */
    Pvoid_t metricsseen;
} PACKED corsaro_ip_hash_t;


/** Structure used to store the tallied statistics for a single metric */
typedef struct corsaro_metric_ip_hash_t {

    /** The metric ID -- upper 32 bits are the metric type, lower 32 bits
     *  are the metric value. */
    uint64_t metricid;

    /** Number of unique source IPs associated with this metric */
    uint32_t srcips;

    /** Number of unique destination IPs associated with this metric */
    uint32_t destips;

    /** Number of packets that were tagged with this metric */
    uint32_t packets;

    /** Number of IP-layer bytes in packets that were tagged with this metric */
    uint64_t bytes;

} PACKED corsaro_metric_ip_hash_t;

/** Structure used to keep track of which processing threads have ended
 *  an interval and which ones we are still waiting on.
 */
typedef struct corsaro_report_outstanding_interval {
    /** The timestamp for the interval in question */
    uint32_t interval_ts;

    /** Array of binary flags that indicate whether the thread at index i
     *  has sent us an interval end message or not. */
    uint8_t reports_recvd[256];

    /** Total number of interval end messages received for this interval */
    uint8_t reports_total;
} corsaro_report_out_interval_t;

/** Structure for keeping track of missing messages between a processing
 *  thread and an IP tracker thread.
 */
typedef struct corsaro_report_iptracker_source {
    uint32_t expected;      /**< Expected sequence number of the next message */
    uint32_t lost;          /**< Total messages lost since last interval */
} corsaro_report_iptracker_source_t;

/** Structure to store state for an IP tracker thread */
typedef struct corsaro_report_iptracker {

    /** The queue for reading incoming messages from the processing threads */
    void *incoming;

    /** ZeroMQ context for creating queues */
    void *zmq_ctxt;

    /** The timestamp of the interval that our most recent complete tally
     *  belongs to.
     */
    uint32_t lastresultts;

    /** The number of processing threads that are able to send messages to this
     *  IP tracker thread.
     */
    uint8_t sourcethreads;

    /** Tracks whether an IP tracker thread is ready to halt */
    uint8_t haltphase;

    /** Thread ID for this IP tracker thread */
    pthread_t tid;

    /** Mutex used to protect the most recent complete tally */
    pthread_mutex_t mutex;

    /** Hash map of all IP addresses observed for the current interval */
    Pvoid_t knownips;

    /** Hash map of all IP addresses observed that should be counted towards
     *  the next interval.
     */
    Pvoid_t knownips_next;

    /** Hash map containing the most recent complete metric tallies */
    Pvoid_t lastresult;

    /** Hash map containing the ongoing tallies for the current interval */
    Pvoid_t currentresult;

    /** Hash map containing the ongoing tallies for tags that should be
     *  counted towards the next interval. */
    Pvoid_t nextresult;

    /** Reference to a corsaro logger for logging error messages etc. */
    corsaro_logger_t *logger;

    /** List of intervals for which not all processing threads have sent
     *  us an interval end message.
     */
    libtrace_list_t *outstanding;

    /** Expected sequence numbers and loss counts for each source feeding
     *  into this tracker thread.
     */
    corsaro_report_iptracker_source_t *sourcetrack;

} corsaro_report_iptracker_t;

/** Structure describing configuration specific to the report plugin */
typedef struct corsaro_report_config {

    /** Standard options, e.g. template */
    corsaro_plugin_proc_options_t basic;

    /** Additional labelling to attach to every avro record -- useful for
     *  distinguishing between different inputs, for instance */
    char *outlabel;

    /** Number of IP tracker threads to create */
    int tracker_count;

    /** Output format */
    corsaro_output_format_t outformat;

    /** Array of operational IP tracker threads -- included in here because
     *  the merge thread needs to be able to access the thread structures and
     *  this was a relatively easy place to put them.
     */
    corsaro_report_iptracker_t *iptrackers;

    /** ZeroMQ queues that are used to communicate between processing threads
     *  and IP tracker threads.
     */
    void **tracker_queues;

    /** Flag that can be used to disable making queries to the tagger for
     *  fully qualified metric labels, especially for geo-tagging metrics.
     *  Intended as a transitional feature until all existing taggers are
     *  updated to support these queries -- having this enabled when
     *  receiving packets from a tagger that does not support it can lead to
     *  a failure to produce merged output if the tagger is under load.
     *
     *  TODO remove this option once it is no longer needed
     */
    uint8_t query_tagger_labels;
} corsaro_report_config_t;

/** The statistics for a single IP + tag within an IP tracker update message */
typedef struct corsaro_report_msg_tag {
    /** Unique ID for the tag -- upper 32 bits are tag class, lower 32 bits
     *  are the tag value.
     */
    uint64_t tagid;

    /** Number of bytes sent by this IP address matching this tag */
    uint64_t bytes;

    /** Number of packets sent by this IP address matching this tag */
    uint32_t packets;
} PACKED corsaro_report_msg_tag_t;

/** Structure describing all of the metrics that apply to an IP that was
 *  observed within a libtrace packet.
 */
typedef struct corsaro_report_msg_body {

    /** The IP address itself */
    uint32_t ipaddr;

    /** Flag indicating whether the IP was observed as a source IP */
    uint8_t issrc;

    /** The number of metric tags that are in this message */
    uint16_t numtags;

    /** The number of IP-layer bytes that were in the packet. */
    uint32_t size;

    /** Flag indicating whether this IP address has been seen since the
     *  last interval boundary.
     */
    uint8_t seenthisinterval;

    /** Map containing the metric IDs for all of the tags that were
     *  seen matching this address.
     */
    Pvoid_t tags;

} corsaro_report_msg_body_t;

/* XXX could make this configurable? */
/** The number of IP tag updates to include in a single enqueued message
 *  to an IP tracker thread. */
#define REPORT_BATCH_SIZE (10000)

/** A message sent from a packet processing thread to an IP tracker thread */
typedef struct corsaro_report_ip_message {

    /** The type of message being sent, e.g. update, interval end or halt */
    uint8_t msgtype;

    /** The thread ID of the processing thread that is sending the message */
    uint8_t sender;

    /** The timestamp of the interval that is ending (interval end msg only) */
    uint32_t timestamp;

    /** The number of IP + tag updates included in this message */
    uint32_t bodycount;

    /** The sequence number for this message, used to detect loss within
     *  ZeroMQ */
    uint32_t seqno;

} PACKED corsaro_report_ip_message_t;

/** Structure for maintaining state for each IP tracker thread that a
 *  packet processing thread will be sending updates to.
 */
typedef struct corsaro_report_tracker_state {

    /** Hashmap of all IPs -> observed tags that will hash to this IP tracker */
    Pvoid_t ipmetrics;

    /** Number of IP addresses in the ipmetrics map */
    uint32_t ipcount;

    /** Sequence number to assign to the next message sent to the tracker */
    uint32_t seqno;

    /** ZeroMQ queue that links this processing thread with the IP tracker
     *  thread.
     */
    void *tracker_queue;

} corsaro_report_tracker_state_t;

/** Packet processing thread state for the report plugin */
typedef struct corsaro_report_state {

    /** State for building and sending IP->tag updates to each of the
     *  IP tracker threads.
     */
    corsaro_report_tracker_state_t *totracker;

    /** An identifier for this packet processing thread */
    int threadid;

    /** Timestamp of the most recent interval */
    uint32_t current_interval;

    /** Number of times that we've been unable to push a message on an IP
     *  tracker message queue due to the queue being full -- used for
     *  performance evaluation.
     */
    int queueblocks;
} corsaro_report_state_t;

/** Merge thread state for the report plugin */
typedef struct corsaro_report_merge_state {

    /** ZeroMQ socket used for requesting IPmeta labels from the tagger */
    void *zmq_taggersock;

    /** A writer instance used for writing output in the Avro format */
    corsaro_avro_writer_t *writer;

    /** Libtimeseries state variable */
    timeseries_t *timeseries;

    /** Libtimeseries key package for writing output as time series */
    timeseries_kp_t *kp;

    /** Judy array containing all of the keys that we have added to our
     *  libtimeseries instance.
     */
    Pvoid_t metrickp_keys;

    /** Timestamp from the last label update that we received successfully
     *  from the tagger.
     */
    uint32_t last_label_update;

    /** Map of country IDs to FQ country labels */
    Pvoid_t country_labels;

    /** Map of region IDs to FQ region labels */
    Pvoid_t region_labels;
} corsaro_report_merge_state_t;


/** Structure containing data that is to be transferred from a packet
 *  processing thread to the merge thread when an interval ends.
 */
typedef struct corsaro_report_interim {

    /** Global configuration for the processing threads */
    corsaro_report_config_t *baseconf;
} corsaro_report_interim_t;

/** Structure containing the final combined tally for a single metric within
 *  an interval.
 */
typedef struct corsaro_report_result {
    /** The metric ID -- upper 32 bits are the metric type, lower 32 bits
     *  are the metric value. */
    uint64_t metricid;

    /** Total number of packets tagged with this metric */
    uint64_t pkt_cnt;

    /** Total number of IP-layer bytes in packets tagged with this metric */
    uint64_t bytes;

    /** Total number of unique source IPs that sent packets tagged with this
     *  metric */
    uint32_t uniq_src_ips;

    /** Total number of unique destination IPs that received packets tagged
     *  with this metric */
    uint32_t uniq_dst_ips;

    /** The timestamp of the interval that this tally applies to */
    uint32_t attimestamp;

    /** An user-defined identifying label to include with this result */
    char *label;

    /** A string representation of the metric class */
    char metrictype[256];

    /** A string representation of the metric value */
    char metricval[128];

} PACKED corsaro_report_result_t;

/** Avro schema for report plugin results */
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


/** Allows external access to the report plugin definition and callbacks */
corsaro_plugin_t *corsaro_report_alloc(void) {
    return &(corsaro_report_plugin);
}

/** Converts a report result into an Avro value
 *
 *  @return a populated avro_value_t that contains the labels, tallies, etc.
 *          from the given result structure.
 */
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
            res->bytes);
    return 0;
}

/** Parses the YAML configuration specific to the report plugin
 *
 *  @param p        A pointer to an instance of the report plugin.
 *  @param doc      A reference to the YAML document being parsed.
 *  @param options  A reference to the report plugin config section from the
 *                  YAML document.
 *  @return 0 if the report plugin config was parsed without problems, -1 if
 *            an error occurred.
 */
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
    conf->outformat = CORSARO_OUTPUT_AVRO;
    conf->tracker_count = 4;
    conf->query_tagger_labels = 1;

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

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                    && strcmp((char *)key->data.scalar.value,
                    "iptracker_threads") == 0) {

            conf->tracker_count = strtol((char *)value->data.scalar.value,
                    NULL, 0);
            if (conf->tracker_count < 1) {
                conf->tracker_count = 1;
            }
            if (conf->tracker_count > CORSARO_REPORT_MAX_IPTRACKERS) {
                corsaro_log(p->logger, "report plugin: iptracker thread count is currently capped at %d", CORSARO_REPORT_MAX_IPTRACKERS);
                conf->tracker_count = CORSARO_REPORT_MAX_IPTRACKERS;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                    && strcmp((char *)key->data.scalar.value,
                    "querytaggerlabels") == 0) {

            if (parse_onoff_option(p->logger, (char *)value->data.scalar.value,
                    &(conf->query_tagger_labels), "query_tagger_labels") < 0) {
                corsaro_log(p->logger, "setting query_tagger_labels to disabled");
                conf->query_tagger_labels = 0;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value,
                    "output_format") == 0) {
           if (strcmp((char *)value->data.scalar.value, "avro") == 0) {
                conf->outformat = CORSARO_OUTPUT_AVRO;
           } else if (strcmp((char *)value->data.scalar.value,
                    "libtimeseries") == 0) {
                conf->outformat = CORSARO_OUTPUT_LIBTIMESERIES;
           } else {
                corsaro_log(p->logger, "output format '%s' is not supported by the report plugin.",
                        (char *)value->data.scalar.value);
                corsaro_log(p->logger, "falling back to avro output.");
                conf->outformat = CORSARO_OUTPUT_AVRO;
           }
        }
    }

    p->config = conf;

    return 0;
}

/** Finds the entry for a given IP address in an IP tracker hash map. If
 *  the IP is not present in the map, creates and inserts a new entry which
 *  is then returned.
 *
 *  @param track        The state for the IP tracker thread.
 *  @param knownips     The hash map to search.
 *  @param ipaddr       The IP address to search the hash map for.
 *  @return a pointer to an IP hash entry corresponding to the given IP
 *          address.
 */
static corsaro_ip_hash_t *update_iphash(corsaro_report_iptracker_t *track,
        Pvoid_t *knownips, uint32_t ipaddr) {

    corsaro_ip_hash_t *iphash;
    PWord_t pval;

    JLG(pval, *knownips, (Word_t)ipaddr);
    if (pval == NULL) {
        /* New IP, so create a new entry in our map */
        iphash = calloc(1, sizeof(corsaro_ip_hash_t));
        JLI(pval, *knownips, (Word_t)ipaddr);
        iphash->ipaddr = ipaddr;
        iphash->metricsseen = NULL;
        iphash->metriccount = 0;
        *pval = (Word_t)(iphash);
    } else {
        /* IP exists in the map, return the existing entry */
        iphash = (corsaro_ip_hash_t *)(*pval);
    }

    return iphash;

}

/** Searches and updates the map of metrics associated with a single IP
 *  address. If the metric has not been associated with the IP previously,
 *  a new entry is created for that metric.
 *
 *  Also update the unique source or dest IP tally for the metric if this
 *  is the first time that IP has been seen in that context.
 *
 *  @param iphash       The IP hash entry to be updated.
 *  @param metricid     The ID of the metric.
 *  @param issrc        Set to 1 if the IP was seen as a source IP, 0 if
 *                      the IP was seen as a destination IP.
 *  @param m            The current tallies for the given metric.
 */
static inline void update_metric_map(corsaro_ip_hash_t *iphash,
        uint64_t metricid, uint8_t issrc, corsaro_metric_ip_hash_t *m) {

    uint8_t metval;
    PWord_t pval;

    JLG(pval, iphash->metricsseen, (Word_t)metricid);
    if (pval == NULL) {
        /* metricid was not in the metric hash for this IP */
        JLI(pval, iphash->metricsseen, (Word_t)metricid);
        *pval = 0;
        iphash->metriccount ++;
    }

    /* metval is a simple bitmask that indicates whether we've seen this
     * IP + metric combination before, either as a source IP, destination IP
     * or both.
     * bit 1 (0b0000001) = seen as source
     * bit 2 (0b0000010) = seen as dest
     *
     * If we set a bit for the first time, we can also increment our combined
     * tally of source or dest IPs for this metric.
     */
    metval = (uint8_t) (*pval);
    if (issrc && !(metval & 0x01)) {
        metval |= 0x01;
        *pval = metval;
        m->srcips ++;
    } else if (!issrc && !(metval & 0x02)) {
        metval |= 0x02;
        *pval = metval;
        m->destips ++;
    }
}

/** Updates the tallies for a single observed IP + metric combination.
 *
 *  @param track        The state for this IP tracker thread
 *  @param metricid     The ID of the metric that was observed
 *  @param iphash       The IP hash map entry for the observed IP
 *  @param issrc        Set to 1 if the IP was seen as a source IP, 0 if
 *                      the IP was seen as a destination IP.
 *  @param iplen        The number of IP-layer bytes to add to the tally.
 *  @param metrictally  The hash map containing the metric tallies to be
 *                      updated.
 */

static void update_knownip_metric(corsaro_report_iptracker_t *track,
        corsaro_report_msg_tag_t *tagptr, corsaro_ip_hash_t *iphash,
        uint8_t issrc, Pvoid_t *metrictally) {

    corsaro_metric_ip_hash_t *m;
    uint64_t metricid = tagptr->tagid;

    PWord_t pval;

    JLG(pval, *metrictally, (Word_t)metricid);
    if (pval != NULL) {
        m = (corsaro_metric_ip_hash_t *)(*pval);
    } else {
        m = (corsaro_metric_ip_hash_t *)calloc(1,
                sizeof(corsaro_metric_ip_hash_t));

        JLI(pval, *metrictally, (Word_t)metricid);
        m->metricid = metricid;
        m->srcips = 0;
        m->destips = 0;
        m->packets = 0;
        m->bytes = 0;
        *pval = (Word_t)(m);
    }

    /* An IP length of zero == the packet has already been tallied for
     * this metric, just update IP tallies only. */
    if (issrc) {
        m->packets += tagptr->packets;
        m->bytes += tagptr->bytes;
    }

    update_metric_map(iphash, metricid, issrc, m);
}

/** Frees an entire metric tally hash map.
 *
 *  @param track        The state for this IP tracker thread
 *  @param methash      The hash map to be destroyed
 */
static void free_metrichash(corsaro_report_iptracker_t *track,
        Pvoid_t methash) {
    corsaro_metric_ip_hash_t *ipiter;
    Word_t index = 0, ret;
    PWord_t pval;

    JLF(pval, methash, index);
    while (pval) {
        ipiter = (corsaro_metric_ip_hash_t *)(*pval);
        free(ipiter);
        JLN(pval, methash, index);
    }
    JLFA(ret, methash);

}

/** Frees an entire IP hash map.
 *
 *  @param track        The state for this IP tracker thread
 *  @param knownips     The IP hash map to be destroyed
 */
static void free_knownips(corsaro_report_iptracker_t *track,
        Pvoid_t knownips) {
    corsaro_ip_hash_t *ipiter;
    Word_t index = 0, ret;
    PWord_t pval;

    JLF(pval, knownips, index);
    while (pval) {
        ipiter = (corsaro_ip_hash_t *)(*pval);
        JLFA(ret, ipiter->metricsseen);
        free(ipiter);

        JLN(pval, knownips, index);
    }
    JLFA(ret, knownips);
}

/** Checks if a packet processing thread has already sent us an interval end
 *  message for the current interval.
 *
 *  If so, any observed metric tags and IPs need to be applied to the *next*
 *  interval instead.
 *
 *  @param outl     The list of incomplete intervals for this IP tracker.
 *  @param sender   The thread ID of the packet processing thread.
 *
 *  @return 1 if the processing thread has ended the interval, 0 if it has not.
 */
static inline int sender_in_outstanding(libtrace_list_t *outl, uint8_t sender) {

    libtrace_list_node_t *n;
    corsaro_report_out_interval_t *o;

    n = outl->head;
    while (n) {
        o = (corsaro_report_out_interval_t *)(n->data);
        n = n->next;

        if (o->reports_recvd[sender]) {
            return 1;
        }
    }
    return 0;
}

/** Macro that will check if there are more parts remaining in a zeromq
 *  multipart message -- assumes "int more" and "size_t moresize" are in
 *  scope, as well as a corsaro_report_iptracker_t * instance called 'track'.
 */
#define ZEROMQ_CHECK_MORE \
    moresize = sizeof(moresize); \
    if (zmq_getsockopt(track->incoming, ZMQ_RCVMORE, &more, &moresize) < 0) { \
        corsaro_log(track->logger, "error checking if there are more parts to a received ip tracker message: %s", strerror(errno)); \
        goto trackerover; \
    }

/** Macro that will read and ignore any remaining parts in a zeromq
 *  multipart message. Useful for bailing out of a message processing
 *  function due to a bogus message, while still leaving the socket in
 *  a readable state. Assumes "int more" and "size_t moresize" are in
 *  scope, as well as a corsaro_report_iptracker_t * instance called 'track'.
 */
#define ZEROMQ_CONSUME_MORE \
    moresize = sizeof(moresize); \
    do { \
        if (zmq_getsockopt(track->incoming, ZMQ_RCVMORE, &more, \
                &moresize) < 0) { \
            corsaro_log(track->logger, "error checking if there are more parts to a received ip tracker message: %s", strerror(errno)); \
            goto trackerover; \
        } \
        if (more) { \
            char consbuf[2048]; \
            if (zmq_recv(track->incoming, consbuf, 2048, 0) < 0) { \
                corsaro_log(track->logger, "error consuming rest of multi-part IP tracker message: %s", strerror(errno)); \
                goto trackerover; \
            }\
        }\
    } while (more != 0);


/** Parses and actions an update message for a single IP that has been
 *  received by an IP tracker thread.
 *
 *  @param track        The state for this IP tracker thread
 *  @param sender       The thread ID of the processing thread that sent the
 *                      message.
 *  @return -1 if an error occurs, otherwise the number of tags for the IP
 *  that were in the message.
 */
static int process_msg_body(corsaro_report_iptracker_t *track, uint8_t sender) {

    int i;
    Pvoid_t *knownip = NULL;
    Pvoid_t *knowniptally = NULL;
    corsaro_ip_hash_t *thisip = NULL;
    corsaro_report_msg_body_t ipdetails;
    corsaro_report_msg_tag_t *tagptr;
    char *buffer = NULL;
    int more, blobsize;
    size_t moresize;

    if (zmq_recv(track->incoming, &ipdetails, sizeof(ipdetails), 0) < 0) {
        return -1;
    }

    /* figure out if our sender has finished the interval already; if
     * so, we need to update the next interval not the current one.
     */
    if (libtrace_list_get_size(track->outstanding) == 0) {
        knownip = &(track->knownips);
        knowniptally = &(track->currentresult);
    } else if (sender_in_outstanding(track->outstanding, sender)) {
        knownip = &(track->knownips_next);
        knowniptally = &(track->nextresult);
    } else {
        knownip = &(track->knownips);
        knowniptally = &(track->currentresult);
    }

    /* Header tells us how many tags to expect, so we can allocate a
     * sufficiently large buffer and read the whole lot in at once.
     */

    ZEROMQ_CHECK_MORE
    buffer = calloc(ipdetails.numtags, sizeof(corsaro_report_msg_tag_t));

    if (more == 0) {
        corsaro_log(track->logger,
                "unexpected end of ip tracker message");
        free(buffer);
        return -1;
    }

    blobsize = zmq_recv(track->incoming, buffer,
            ipdetails.numtags * sizeof(corsaro_report_msg_tag_t), 0);
    if (blobsize < 0) {
        free(buffer);
        return -1;
    }

    if (blobsize < ipdetails.numtags * sizeof(corsaro_report_msg_tag_t)) {
        corsaro_log(track->logger,
                "received unexpected amount of tag metrics in ip tracker -- expected %u, got %d",
                ipdetails.numtags * sizeof(corsaro_report_msg_tag_t), blobsize);
        free(buffer);
        return -1;
    }
    tagptr = (corsaro_report_msg_tag_t *)buffer;

    for (i = 0; i < ipdetails.numtags; i++) {
        /* Combined (which has a metric ID of 0) should always be the first
         * tag we see. */

        /* Save the IP hash map entry, so we don't end up trying to do
         * a hash lookup for every tag. */
        if (!thisip) {
            thisip = update_iphash(track, knownip, ipdetails.ipaddr);
        }
        update_knownip_metric(track, tagptr, thisip,
                ipdetails.issrc, knowniptally);
        tagptr ++;
    }
    free(buffer);
    return ipdetails.numtags;

trackerover:
    return -1;
}

/** Updates an IP tracker thread's list of processing threads that have
 *  ended an interval, following receipt of an interval end from a packet
 *  processing thread.
 *
 *  @param outl         The list of incomplete intervals for this IP tracker.
 *  @param ts           The timestamp of the interval to update.
 *  @param limit        The total number of packet processing threads.
 *  @param sender       The thread ID of the packet processing thread that
 *                      has just sent us an interval message.
 *  @return the timestamp of the interval if this was the last thread that
 *          we were waiting on, 0 otherwise.
 */
static uint32_t update_outstanding(libtrace_list_t *outl, uint32_t ts,
        uint8_t limit, uint8_t sender) {

    libtrace_list_node_t *n;
    corsaro_report_out_interval_t *o, newentry;
    uint32_t toret = 0;

    assert(outl);
    n = outl->head;

    while (n) {
        o = (corsaro_report_out_interval_t *)(n->data);
        if (o->interval_ts == ts) {
            if (o->reports_recvd[sender] == 0) {
                o->reports_recvd[sender] = 1;
                o->reports_total ++;
            }
            if (o->reports_total == limit) {
                /* All threads have ended for this interval */
                toret = ts;
                break;
            } else {
                return 0;
            }
        }
        n = n->next;
    }

    if (toret > 0) {
        /* An interval has completed */

        /* Intervals *should* complete in order, but I'm still going
         * to prune any incomplete preceding incomplete intervals just to
         * be safe -- we're unlikely to ever get the missing messages that
         * we're waiting for now anyway.
         */
        corsaro_report_out_interval_t popped;
        while (libtrace_list_pop_front(outl, (void *)((&popped))) > 0) {
            if (popped.interval_ts == toret) {
                break;
            }
        }
        return toret;
    }

    /* This is a new interval, add it to our list */
    if (outl->tail) {
        /* sanity check that our intervals are ending in order */
        o = (corsaro_report_out_interval_t *)(outl->tail->data);
        assert(o->interval_ts < ts);
    }

    /* Only one processing thread, no need to wait */
    if (limit == 1) {
        return ts;
    }

    memset(&(newentry.reports_recvd), 0, sizeof(newentry.reports_recvd));
    newentry.reports_recvd[sender] = 1;
    newentry.reports_total = 1;
    newentry.interval_ts = ts;
    libtrace_list_push_back(outl, (void *)(&newentry));
    return 0;

}

/** Processes and acts upon an "Interval" or "Reset" message received
 *  by an IP tracker thread.
 *
 *  @param track        The IP tracker thread that received the message
 *  @param msg          The message that was received.
 */
static void process_interval_reset_message(corsaro_report_iptracker_t *track,
        corsaro_report_ip_message_t *msg) {

    uint32_t complete;
    uint64_t totallost = 0;
    int i;

    pthread_mutex_lock(&(track->mutex));
    if (msg->timestamp == 0) {
        pthread_mutex_unlock(&(track->mutex));
        return;
    }

    if (msg->timestamp <= track->lastresultts) {
        pthread_mutex_unlock(&(track->mutex));
        return;
    }

    /* update our record of which processing threads have
     * completed intervals. */
    complete = update_outstanding(track->outstanding, msg->timestamp,
            track->sourcethreads, msg->sender);
    if (complete == 0) {
        /* still waiting on at least one more thread */
        pthread_mutex_unlock(&(track->mutex));
        return;
    }

    pthread_mutex_unlock(&(track->mutex));

    /* End of interval, take final tally and update lastresults */

    /* First, make sure that the merging thread has finished with the
     * previous result we gave it...
     */
    do {
        pthread_mutex_lock(&(track->mutex));
        if (track->lastresult == NULL) {
            break;
        }
        pthread_mutex_unlock(&(track->mutex));
        /* TODO use a proper condition variable here */
        sleep(1);
    } while (1);

    if (msg->msgtype == CORSARO_IP_MESSAGE_INTERVAL) {
        track->lastresult = track->currentresult;
        track->lastresultts = complete;
    } else {
        free_metrichash(track, (track->currentresult));
    }

    if (track->haltphase == 1) {
        track->haltphase = 2;
    }
    pthread_mutex_unlock(&(track->mutex));

    for (i = 0; i < track->sourcethreads; i++) {
        totallost += track->sourcetrack[i].lost;
        track->sourcetrack[i].lost = 0;
    }

    if (totallost > 0) {
        corsaro_log(track->logger, "IP tracker thread missed %lu messages from incoming queue", totallost);
    }

    /* Reset IP and metric tally hash maps -- don't forget we may
     * already have some valid info in the "next" interval maps.
     */
    free_knownips(track, track->knownips);
    track->knownips = track->knownips_next;
    track->currentresult = track->nextresult;
    track->knownips_next = NULL;
    track->nextresult = NULL;;
}

/** Processes and acts upon an update message that has been received
 *  by an IP tracker thread.
 *
 *  @param track        The IP tracker thread that received the message
 *  @param msg          The message that was received.
 */
static int process_iptracker_update_message(corsaro_report_iptracker_t *track,
        corsaro_report_ip_message_t *msg) {

    int i;
    int more;
    size_t moresize;

    /* This is an update message with a batch of IP + metric tag
     * observations. */
    for (i = 0; i < msg->bodycount; i++) {
        ZEROMQ_CHECK_MORE
        if (more == 0) {
            corsaro_log(track->logger, "missing ip tracker message parts? header suggests %u, but we have only got as far as %d", msg->bodycount, i);
            return -1;
        }

        if (process_msg_body(track, msg->sender) < 0) {
            return -1;
        }
    }

    /* Read the trailer from the multi-part message */
    ZEROMQ_CHECK_MORE
    if (more == 0) {
        corsaro_log(track->logger, "missing ip tracker message parts? trailer appears to be missing?");
    } else {
        uint32_t trailer;
        if (zmq_recv(track->incoming, &trailer, sizeof(trailer), 0) < 0) {

            corsaro_log(track->logger,
                    "error receiving trailer on tracker pull socket: %s",
                    strerror(errno));
            return -1;
        }

        if (trailer != msg->bodycount) {
            corsaro_log(track->logger,
                    "incorrect trailer value in ip tracker message: got %u, expected %u", trailer, msg->bodycount);
        }

        /* Now we should have no more parts to the message... */
        ZEROMQ_CHECK_MORE
        if (more) {
            corsaro_log(track->logger, "expected end of ip tracker message but zeromq says there are more parts to come?");
            return -1;
        }
    }
    return 0;

trackerover:
    return -1;
}

/** Routine for the IP tracker threads
 *
 * @param tdata     The state for this IP tracker thread (initialised).
 * @return NULL via pthread_exit()
 */
static void *start_iptracker(void *tdata) {
    corsaro_report_iptracker_t *track;
    corsaro_report_ip_message_t msg;
    int i;
    int more;
    size_t moresize;
    corsaro_report_iptracker_source_t *src;


    track = (corsaro_report_iptracker_t *)tdata;

    /* haltphases:
     * 0 = running
     * 1 = seen halt message, waiting for outstanding intervals to complete
     * 2 = seen halt message, no more outstanding intervals so can exit
     */

    while (track->haltphase != 2) {
        if (zmq_recv(track->incoming, &msg, sizeof(msg), 0) < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }
            corsaro_log(track->logger,
                    "error receiving message on tracker pull socket: %s",
                    strerror(errno));
            pthread_mutex_lock(&(track->mutex));
            track->haltphase = 2;
            pthread_mutex_unlock(&(track->mutex));
            break;
        }

        if (msg.sender >= track->sourcethreads) {
            corsaro_log(track->logger,
                    "invalid sender %u in message received by IP tracker, skipping",
                    msg.sender);
            ZEROMQ_CONSUME_MORE
            continue;
        }

        if (msg.msgtype == CORSARO_IP_MESSAGE_HALT) {
            pthread_mutex_lock(&(track->mutex));
            track->haltphase = 2;
            pthread_mutex_unlock(&(track->mutex));

            break;
        }

        /* Check if this message has the expected sequence number. If not,
         * figure out how many have gone missing */
        src = &(track->sourcetrack[msg.sender]);

        if (src->expected != msg.seqno) {
            src->lost += (msg.seqno - src->expected);
        }
        src->expected = msg.seqno + 1;

        if (msg.msgtype == CORSARO_IP_MESSAGE_INTERVAL ||
                msg.msgtype == CORSARO_IP_MESSAGE_RESET) {

            process_interval_reset_message(track, &msg);
            continue;
        }

        if (process_iptracker_update_message(track, &msg) < 0) {
            pthread_mutex_lock(&(track->mutex));
            track->haltphase = 2;
            pthread_mutex_unlock(&(track->mutex));
            break;
        }
    }

trackerover:
    /* Thread is ending, tidy up everything */
    free_metrichash(track, (track->currentresult));
    free_metrichash(track, (track->nextresult));
    free_knownips(track, track->knownips);
    free_knownips(track, track->knownips_next);
    pthread_exit(NULL);
}

/** Complete configuration for the report plugin and assign default values
 *  to any unconfigured options.
 *
 *  This function also initialises and starts the IP tracker threads, so that
 *  they are up and running as soon as we start processing packets.
 *
 *  @param p        A reference to the running instance of the report plugin
 *  @param stdopts  The set of global-level options that are common to every
 *                  plugin
 *  @param zmq_ctxt A ZeroMQ contect for the entire process that can be
 *                  used to create new messaging sockets
 *  @return 0 if successful, -1 if an error occurred.
 */
int corsaro_report_finalise_config(corsaro_plugin_t *p,
        corsaro_plugin_proc_options_t *stdopts, void *zmq_ctxt) {

    corsaro_report_config_t *conf;
    int i, j, ret = 0, rto=10, hwm=50;
    char sockname[40];

    conf = (corsaro_report_config_t *)(p->config);
    conf->basic.template = stdopts->template;
    conf->basic.monitorid = stdopts->monitorid;
    conf->basic.procthreads = stdopts->procthreads;
    conf->basic.libtsascii = stdopts->libtsascii;
    conf->basic.libtskafka = stdopts->libtskafka;
    conf->basic.libtsdbats = stdopts->libtsdbats;

    if (conf->outlabel == NULL) {
        conf->outlabel = strdup("unlabeled");
    }

    corsaro_log(p->logger,
            "report plugin: labeling all output rows with '%s'",
            conf->outlabel);

    if (conf->outformat == CORSARO_OUTPUT_AVRO) {
        corsaro_log(p->logger,
                "report plugin: writing output to avro files");
    } else if (conf->outformat == CORSARO_OUTPUT_LIBTIMESERIES) {
        corsaro_log(p->logger,
                "report plugin: writing output using libtimeseries");
        display_libts_ascii_options(p->logger, conf->basic.libtsascii,
                "report plugin");
        display_libts_kafka_options(p->logger, conf->basic.libtskafka,
                "report plugin");
        display_libts_dbats_options(p->logger, conf->basic.libtsdbats,
                "report plugin");
    } else {
        corsaro_log(p->logger,
                "report plugin: invalid value for output format (?)");
    }

    corsaro_log(p->logger,
            "report plugin: starting %d IP tracker threads",
            conf->tracker_count);
    if (conf->query_tagger_labels == 0) {
        corsaro_log(p->logger,
                "report plugin: NOT querying the tagger for FQ geo-location labels");
    }

    /* Create and start the IP tracker threads.
     *
     * We include the tracker thread references in the config, because
     * that is easily available in both the packet processing and
     * merging threads.
     */
    conf->iptrackers = (corsaro_report_iptracker_t *)calloc(
            conf->tracker_count, sizeof(corsaro_report_iptracker_t));
    conf->tracker_queues = calloc(conf->tracker_count * conf->basic.procthreads,
		sizeof(void *));

    for (i = 0; i < conf->tracker_count; i++) {

        pthread_mutex_init(&(conf->iptrackers[i].mutex), NULL);
        conf->iptrackers[i].lastresultts = 0;

        conf->iptrackers[i].knownips = NULL;
        conf->iptrackers[i].knownips_next = NULL;
        conf->iptrackers[i].lastresult = NULL;
        conf->iptrackers[i].currentresult = NULL;
        conf->iptrackers[i].nextresult = NULL;
        conf->iptrackers[i].logger = p->logger;
        conf->iptrackers[i].sourcethreads = stdopts->procthreads;
        conf->iptrackers[i].haltphase = 0;
        conf->iptrackers[i].outstanding = libtrace_list_init(
               sizeof(corsaro_report_out_interval_t));

        conf->iptrackers[i].sourcetrack = calloc(stdopts->procthreads,
                sizeof(corsaro_report_iptracker_source_t));

        snprintf(sockname, 40, "inproc://reporttracker%d", i);

        conf->iptrackers[i].incoming = zmq_socket(zmq_ctxt, ZMQ_PULL);
        if (zmq_setsockopt(conf->iptrackers[i].incoming, ZMQ_RCVTIMEO, &rto,
                    sizeof(rto)) < 0) {
            corsaro_log(p->logger,
                    "error while configuring ip tracker %d pull socket: %s", i,
                    strerror(errno));
            ret = -1;
        }

        if (zmq_setsockopt(conf->iptrackers[i].incoming, ZMQ_RCVHWM, &hwm,
                    sizeof(hwm)) < 0) {
            corsaro_log(p->logger,
                    "error while configuring ip tracker %d pull socket: %s", i,
                    strerror(errno));
            ret = -1;
        }

        if (zmq_bind(conf->iptrackers[i].incoming, sockname) < 0) {
            corsaro_log(p->logger,
                    "error while binding ip tracker %d pull socket: %s", i,
                    strerror(errno));
            ret = -1;
        }

        /* Each processing thread needs a queue for it to send messages to
         * each of the IP tracking threads, so we need m * n queues (where
         * m = num proc threads and n = num tracker threads).
         *
         * Lay them out in such a way that the proc threads can easily
         * identify "their" queues.
         */
        for (j = 0; j < conf->basic.procthreads; j++) {
            int tq_id = i * conf->basic.procthreads + j;
            conf->tracker_queues[tq_id] = zmq_socket(zmq_ctxt, ZMQ_PUSH);
            if (zmq_setsockopt(conf->tracker_queues[tq_id], ZMQ_SNDHWM, &hwm,
                        sizeof(hwm)) < 0) {
                corsaro_log(p->logger,
                        "error while configuring ip tracker %d push socket: %s", tq_id,
                        strerror(errno));
                ret = -1;
            }

            if (zmq_connect(conf->tracker_queues[tq_id], sockname) < 0) {
                corsaro_log(p->logger,
                        "error while connecting ip tracker %d-%d push socket: %s",
                        i, j, strerror(errno));
                ret = -1;
            }
        }


        pthread_create(&(conf->iptrackers[i].tid), NULL,
                start_iptracker, &(conf->iptrackers[i]));
    }

    return ret;
}

/** Tidies up all memory allocated by this instance of the report plugin.
 *
 *  @param p    A reference to the running instance of the report plugin
 */
void corsaro_report_destroy_self(corsaro_plugin_t *p) {
    int i, j;
    if (p->config) {
        corsaro_report_config_t *conf;
        conf = (corsaro_report_config_t *)(p->config);
        if (conf->outlabel) {
            free(conf->outlabel);
        }

        /* Hopefully the tracker threads have joined by this point... */
        if (conf->iptrackers) {
            for (i = 0; i < conf->tracker_count; i++) {
                pthread_mutex_destroy(&(conf->iptrackers[i].mutex));

                zmq_close(conf->iptrackers[i].incoming);
                for (j = 0; j < conf->basic.procthreads; j++) {
                    zmq_close(conf->tracker_queues[
                            i * conf->basic.procthreads + j]);
                }
                free(conf->iptrackers[i].sourcetrack);
                libtrace_list_deinit(conf->iptrackers[i].outstanding);
            }
            free(conf->iptrackers);
            free(conf->tracker_queues);
        }

        free(p->config);
    }
    p->config = NULL;

}

/** ------------------ PACKET PROCESSING API -------------------*/

/** Creates and initialises packet processing thread state for the report
 *  plugin. This state must be passed into all subsequent packet processing
 *  and interval boundary callbacks for the report plugin.
 *
 *  @param p        A reference to the running instance of the report plugin
 *  @param threadid A unique number identifying the packet processing thread
 *                  that has called this callback.
 *  @return A pointer to the newly created plugin-processing state.
 */
void *corsaro_report_init_processing(corsaro_plugin_t *p, int threadid) {

    corsaro_report_state_t *state;
    corsaro_report_config_t *conf;
    int i;

    conf = (corsaro_report_config_t *)(p->config);
    state = (corsaro_report_state_t *)malloc(sizeof(corsaro_report_state_t));

    state->current_interval = 0;
    state->threadid = threadid;
    state->queueblocks = 0;
    state->totracker = (corsaro_report_tracker_state_t *)calloc(
            conf->tracker_count, sizeof(corsaro_report_tracker_state_t));

    /* Maintain state for each of the IP tracker threads. As we
     * process packets, we'll fill each of the metric maps depending on which
     * IPs are seen in the processed packets. Once we have enough data, the
     * map contents will be pushed to the appropriate IP tracker thread and
     * we will start accumulating data afresh.
     */
    for (i = 0; i < conf->tracker_count; i++) {
        state->totracker[i].ipmetrics = NULL;
        state->totracker[i].ipcount = 0;
        state->totracker[i].seqno = 0;
        state->totracker[i].tracker_queue =
            conf->tracker_queues[i * conf->basic.procthreads + state->threadid];
    }


    return state;
}

/** Removes all entries from an IP metrics array
 *
 *  @param tracker      The IP tracker state which needs its array cleared
 */
static void clean_ipmetrics_array(corsaro_report_tracker_state_t *tracker) {

    PWord_t pval;
    Word_t index = 0;
    Word_t rcword;

    JLF(pval, tracker->ipmetrics, index);
    while (pval) {
        corsaro_report_msg_body_t *body;

        body = (corsaro_report_msg_body_t *)(*pval);
        free(body);
        JLN(pval, tracker->ipmetrics, index);
    }

    JLFA(rcword, tracker->ipmetrics);
}

/** Constructs an update message to send to an IP tracker thread
 *
 *  @param state    The state for this packet processing thread
 *  @param logger   A corsaro logger instance for error reporting
 *  @param tracker  The local state for the IP tracker thread that we are
 *                  going to send an update message to.
 *  @return -1 if an error occurs, otherwise the number of IPs which are
 *  described in the message we just sent.
 */
static int send_iptracker_message(corsaro_report_state_t *state,
        corsaro_logger_t *logger, corsaro_report_tracker_state_t *tracker) {

    corsaro_report_ip_message_t msg;
    PWord_t pval;
    PWord_t inval;
    Word_t index;
    Word_t rcword;
    Word_t in_index;
    int iserr = 0;
    char *blob;
    int blobsize = 0;

    msg.msgtype = CORSARO_IP_MESSAGE_UPDATE;
    msg.sender = state->threadid;
    msg.bodycount = 0;
    msg.timestamp = 0;
    msg.seqno = tracker->seqno;

    msg.bodycount = tracker->ipcount;

    /* send "msg" with SNDMORE */
    if (zmq_send(tracker->tracker_queue, (void *)(&msg), sizeof(msg),
            ZMQ_SNDMORE) < 0) {
        iserr = 1;
    }

    index = 0;
    JLF(pval, tracker->ipmetrics, index);
    blob = calloc(CORSARO_MAX_SUPPORTED_TAGS, sizeof(corsaro_report_msg_tag_t));
    blobsize = CORSARO_MAX_SUPPORTED_TAGS;

    while (pval) {
        corsaro_report_msg_body_t *body;
        Pvoid_t saved;
        corsaro_report_msg_tag_t *tagptr;
        corsaro_report_msg_tag_t *result;

        /* "body" describes a single IP within the IP metric map */
        body = (corsaro_report_msg_body_t *)(*pval);

        if (!(body->seenthisinterval)) {
            if (body->tags) {
                corsaro_log(logger, "should this really happen?");
            }
            free(body);
            JLD(rcword, tracker->ipmetrics, index);
            JLN(pval, tracker->ipmetrics, index);
            continue;
        }

        saved = body->tags;

        body->tags = NULL;
        /* send "body" with SNDMORE */
        if (!iserr) {
            if (zmq_send(tracker->tracker_queue, (void *)body,
                    sizeof(corsaro_report_msg_body_t), ZMQ_SNDMORE) < 0) {
                iserr = 1;
            }
        }
        /* Send all of the tags that we've stored against "body" */
        in_index = 0;
        JLF(inval, saved, in_index);

        /* The number of tags can exceed CORSARO_MAX_SUPPORTED_TAGS as we
         * only check this limit once per packet (and a packet can introduce
         * multiple tags, so be prepared to resize the blob if necessary.
         */
        if (body->numtags > blobsize) {
            blobsize = body->numtags;
            blob = realloc(blob, blobsize * sizeof(corsaro_report_msg_tag_t));
        }

        if (!iserr) {
            /* form tags into a single memory blob and send with SNDMORE */
            tagptr = (corsaro_report_msg_tag_t *)blob;

            while (inval) {
                result = (corsaro_report_msg_tag_t *)(*inval);

                tagptr->tagid = (uint64_t)in_index;
                tagptr->packets = result->packets;
                tagptr->bytes = result->bytes;
                tagptr ++;

                result->packets = 0;
                result->bytes = 0;
                free(result);

                JLN(inval, saved, in_index);
            }
            if (zmq_send(tracker->tracker_queue, (void *)blob,
                    (((char *)tagptr) - blob), ZMQ_SNDMORE) < 0) {
                iserr = 1;
            }
        }
        JLFA(rcword, saved);

        body->numtags = 0;
        body->size = 0;
        body->seenthisinterval = 0;
        JLN(pval, tracker->ipmetrics, index);
    }

    free(blob);

    tracker->ipcount = 0;

    /* send final counter as a trailer to finish the message */
    if (!iserr) {
        if (zmq_send(tracker->tracker_queue, (void *)&(msg.bodycount),
                sizeof(msg.bodycount), 0) < 0) {
            return -1;
        }
    } else {
        return -1;
    }

    tracker->seqno ++;
    return msg.bodycount;
}

/** Tidies up packet processing thread state for the report plugin and
 *  halts the IP tracker threads.
 *
 *  @param p        A reference to the running instance of the report plugin
 *  @param local    The packet processing thread state for this plugin.
 *  @return 0 if successful, -1 if an error occurred.
 */
int corsaro_report_halt_processing(corsaro_plugin_t *p, void *local) {

    corsaro_report_state_t *state;
    corsaro_report_ip_message_t msg;
    corsaro_report_config_t *conf;
    int i;

    conf = (corsaro_report_config_t *)(p->config);
    state = (corsaro_report_state_t *)local;

    if (state == NULL) {
        return 0;
    }

    /* Tell all of the IP tracker threads to halt */
    memset(&msg, 0, sizeof(msg));
    msg.msgtype = CORSARO_IP_MESSAGE_HALT;
    msg.sender = state->threadid;
    msg.seqno = 0;

    for (i = 0; i < conf->tracker_count; i++) {
        /* If there are any outstanding updates, send those first */
        if (state->totracker[i].ipcount > 0) {

            if (send_iptracker_message(state, p->logger,
                    &(state->totracker[i])) < 0) {

                corsaro_log(p->logger,
                        "error while pushing final IP result to tracker thread %d: %s",
                        i, strerror(errno));
            }
        }

        /* Send the halt message */
        if (zmq_send(state->totracker[i].tracker_queue,
                (void *)(&msg), sizeof(corsaro_report_ip_message_t), 0) < 0) {
            corsaro_log(p->logger,
                    "error while pushing halt to tracker thread %d: %s",
                    i, strerror(errno));
        }

        clean_ipmetrics_array(&(state->totracker[i]));
    }

    /* Wait for the tracker threads to stop */
    for (i = 0; i < conf->tracker_count; i++) {
        if (conf->iptrackers[i].tid != 0) {
            pthread_join(conf->iptrackers[i].tid, NULL);
            conf->iptrackers[i].tid = 0;
        }
    }

    free(state->totracker);
    free(state);

    return 0;
}

/** Given a timestamp and processing thread ID, generate an appropriate
 *  Avro output filename using the pre-configured output file template.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param local        The packet processing thread state for this plugin.
 *  @param timestamp    The timestamp of the first interval covered by this
 *                      output file.
 *  @param threadid     The processing thread that is creating this file. Set
 *                      to -1 if the merge thread is calling this function.
 *  @return A malloc'd string containing the filename that should be used
 *          when creating an output file. Returns NULL if an error occurs.
 *
 *  @note It is the caller's responsibility to free the returned string when
 *        they are finished with opening the file.
 */
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

/** Updates the report plugin state in response to the commencement of
 *  a new interval.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param local        The packet processing thread state for this plugin.
 *  @param int_start    The details of the interval that has now started.
 *  @return 0 if successful, -1 if an error occurs.
 */
int corsaro_report_start_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_start) {

    corsaro_report_state_t *state;

    state = (corsaro_report_state_t *)local;
    if (state != NULL) {
        /* Save the interval start time, since this is what we will send
         * to the IP tracker threads once the interval ends.
         */
        state->current_interval = int_start->time;
    }
    return 0;
}

/** Updates the report plugin state in response to the ending of an interval
 *  and returns any saved data that needs to be passed on to the merging
 *  thread so it can correctly combine the results for all of the processing
 *  threads.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param local        The packet processing thread state for this plugin.
 *  @param int_end      The details of the interval that has now ended.
 *  @param complete     Flag indicating whether the interval was a complete
 *                      one or a partial one.
 *  @return A pointer to an interim result structure that is to be combined
 *          with the corresponding interim results produced by the other
 *          packet processing threads, or NULL if there are no useful results
 *          for this interval.
 */
void *corsaro_report_end_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_end, uint8_t complete) {

    corsaro_report_config_t *conf;
    corsaro_report_state_t *state;
    corsaro_report_interim_t *interim;
    corsaro_report_ip_message_t msg;
    int i;

    conf = (corsaro_report_config_t *)(p->config);
    state = (corsaro_report_state_t *)local;

    if (state == NULL) {
        corsaro_log(p->logger,
                "corsaro_report_end_interval: report thread-local state is NULL!");
        return NULL;
    }


    /* Tell the IP tracker threads that there will be no more updates
     * coming from this processing thread for this interval.
     */
    memset(&msg, 0, sizeof(msg));

    if (complete) {
        msg.msgtype = CORSARO_IP_MESSAGE_INTERVAL;
        interim = (corsaro_report_interim_t *)malloc(
                sizeof(corsaro_report_interim_t));
        interim->baseconf = conf;
    } else {
        msg.msgtype = CORSARO_IP_MESSAGE_RESET;
        interim = NULL;
    }

    msg.timestamp = state->current_interval;
    msg.sender = state->threadid;

    for (i = 0; i < conf->tracker_count; i++) {
        if (state->totracker[i].ipcount > 0) {
            if (send_iptracker_message(state, p->logger,
                    &(state->totracker[i])) < 0) {
                corsaro_log(p->logger,
                        "error while pushing end-interval result to tracker thread %d: %s",
                        i, strerror(errno));
            }
        }

        msg.seqno = state->totracker[i].seqno;
        state->totracker[i].seqno ++;
        if (zmq_send(state->totracker[i].tracker_queue,
                (void *)(&msg), sizeof(corsaro_report_ip_message_t), 0) < 0) {
            corsaro_log(p->logger,
                    "error while pushing end-interval to tracker thread %d: %s",
                    i, strerror(errno));
        }
    }

    state->queueblocks = 0;

    return (void *)interim;
}

/** Helper function to quickly find the IP addresses from a libtrace packet.
 *  Also extracts the IP length from the IP header as well.
 *
 *  @param packet           The libtrace packet to get IP addresses from.
 *  @param srcaddr          Pointer to a location to write the source IP into
 *  @param dstaddr          Pointer to a location to write the dest IP into
 *  @param iplen            Pointer to a location to write the IP length into.
 *  @return 0 if successful, -1 if this is not an IPv4 packet or some of the
 *          IP header is missing.
 *  @note This function works for IPv4 only!
 */
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

/** Check if the basic tags (port, protocol, etc) are valid for a tag set.
 *
 *  @param tags         The set of tags to evaluate.
 *  @return 1 if the basic tags are valid, 0 if they are not.
 */
static inline int basic_tagged(corsaro_packet_tags_t *tags) {
    if (tags->providers_used & 0x01) {
        return 1;
    }
    return 0;
}

/** Check if the maxmind geo-location tags are valid for a tag set.
 *
 *  @param tags         The set of tags to evaluate.
 *  @return 1 if the maxmind tags are valid, 0 if they are not.
 */
static inline int maxmind_tagged(corsaro_packet_tags_t *tags) {
    if (tags->providers_used & (1 << IPMETA_PROVIDER_MAXMIND)) {
        return 1;
    }
    return 0;
}

/** Check if the netacq-edge geo-location tags are valid for a tag set.
 *
 *  @param tags         The set of tags to evaluate.
 *  @return 1 if the netacq-edge tags are valid, 0 if they are not.
 */
static inline int netacq_tagged(corsaro_packet_tags_t *tags) {
    if (tags->providers_used & (1 << IPMETA_PROVIDER_NETACQ_EDGE)) {
        return 1;
    }
    return 0;
}

/** Check if the prefix2asn tags are valid for a tag set.
 *
 *  @param tags         The set of tags to evaluate.
 *  @return 1 if the prefix2asn tags are valid, 0 if they are not.
 */
static inline int pfx2as_tagged(corsaro_packet_tags_t *tags) {
    if (tags->providers_used & (1 << IPMETA_PROVIDER_PFX2AS)) {
        return 1;
    }
    return 0;
}

/** Convert a metric class into a printable string representation.
 *
 *  @param class        The metric class to convert into a string
 *  @return a string containing a name that describes the metric class.
 *
 *  @note The returned string is on the stack, rather than allocated.
 *        Either use it immediately or copy it somewhere more persistent.
 *        Do NOT free the returned string.
 */
static char *metclasstostr(corsaro_report_metric_class_t class) {

    switch(class) {
        case CORSARO_METRIC_CLASS_COMBINED:
            return "combined";
        case CORSARO_METRIC_CLASS_IP_PROTOCOL:
            return "IP protocol";
        case CORSARO_METRIC_CLASS_ICMP_TYPE:
            return "ICMP type";
        case CORSARO_METRIC_CLASS_ICMP_CODE:
            return "ICMP code";
        case CORSARO_METRIC_CLASS_TCP_SOURCE_PORT:
            return "TCP source port";
        case CORSARO_METRIC_CLASS_TCP_DEST_PORT:
            return "TCP dest port";
        case CORSARO_METRIC_CLASS_UDP_SOURCE_PORT:
            return "UDP source port";
        case CORSARO_METRIC_CLASS_UDP_DEST_PORT:
            return "UDP dest port";
        case CORSARO_METRIC_CLASS_MAXMIND_CONTINENT:
            return "Maxmind continent";
        case CORSARO_METRIC_CLASS_MAXMIND_COUNTRY:
            return "Maxmind country";
        case CORSARO_METRIC_CLASS_NETACQ_CONTINENT:
            return "Netacq continent";
        case CORSARO_METRIC_CLASS_NETACQ_COUNTRY:
            return "Netacq country";
        case CORSARO_METRIC_CLASS_PREFIX_ASN:
            return "pfx2as ASN";
    }

    return "unknown";

}

/** Macro function for converting a metric class and value into a 64 bit
 *  number that we can use as a numeric hash key.
 */
#define GEN_METRICID(class, val) \
    ((((uint64_t) class) << 32) + ((uint64_t)val))


/** Adds a new metric tag to an IP update message.
 *
 *  @param class        The class of the metric that we are adding
 *  @param tagval       The value for the metric that we are adding
 *  @param maxtagval    The maximum allowable value for this metric class.
 *                      If 0, there is no upper limit.
 *  @param state        The packet processing thread state for this plugin
 *  @param body         The IP update that the tag is being added to
 *  @param logger       A reference to a corsaro logger for error reporting
 */
static inline void process_single_tag(corsaro_report_metric_class_t class,
        uint32_t tagval, uint32_t maxtagval,
        corsaro_report_state_t *state, corsaro_report_msg_body_t *body,
        corsaro_logger_t *logger, uint16_t pktbytes) {

    uint64_t metricid;
    PWord_t pval;
    corsaro_report_msg_tag_t *tag;

    /* Sanity checking for metrics that have clearly defined bounds */
    if (maxtagval > 0 && tagval >= maxtagval) {
        corsaro_log(logger, "Invalid %s tag: %u", metclasstostr(class),
                tagval);
        return;
    }

    metricid = GEN_METRICID(class, tagval);

    JLG(pval, body->tags, metricid);

    if (pval == NULL) {
        tag = calloc(1, sizeof(corsaro_report_msg_tag_t));

        tag->tagid = metricid;
        tag->packets = 1;
        tag->bytes = pktbytes;

        JLI(pval, body->tags, metricid);
        *pval = (Word_t)tag;
        body->numtags ++;
    } else {
        tag = (corsaro_report_msg_tag_t *)(*pval);
        tag->packets ++;
        tag->bytes += pktbytes;
    }

}


/** Insert all of the tags in a tag set into an IP update message that will
 *  be forwarded to an IP tracker thread.
 *
 *  All of the tags in the tag set should be derived from the same packet.
 *
 *  @param tags         The set of tags to insert into the IP update
 *  @param iplen        The number of IP-layer bytes in the original packet
 *  @param body         The IP update message to insert the tags into
 *  @param state        The packet processing thread state for this plugin
 *  @param logger       A reference to a corsaro logger for error reporting
 *  @param addr         An IP address from the original packet
 *  @param issrc        Set to 1 if 'addr' is the source IP address, 0 if
 *                      'addr' is the destination IP address.
 */
static void process_tags(corsaro_packet_tags_t *tags, uint16_t iplen,
        corsaro_report_msg_body_t *body, corsaro_report_state_t *state,
        corsaro_logger_t *logger, uint32_t addr) {

    /* "Combined" is simply a total across all metrics, i.e. the total
     * number of packets, source IPs etc. Every IP packet should add to
     * the combined tally.
     */

    process_single_tag(CORSARO_METRIC_CLASS_COMBINED, 0, 0, state, body,
            logger, iplen);

    if (!tags || tags->providers_used == 0) {
        return;
    }

    process_single_tag(CORSARO_METRIC_CLASS_IP_PROTOCOL, tags->protocol,
            METRIC_IPPROTOS_MAX, state, body, logger, iplen);

    if (tags->protocol == TRACE_IPPROTO_ICMP) {
        process_single_tag(CORSARO_METRIC_CLASS_ICMP_TYPE, tags->src_port,
                METRIC_ICMP_MAX, state, body, logger, iplen);
        process_single_tag(CORSARO_METRIC_CLASS_ICMP_CODE, tags->dest_port,
                METRIC_ICMP_MAX, state, body, logger, iplen);

    } else if (tags->protocol == TRACE_IPPROTO_TCP) {
        process_single_tag(CORSARO_METRIC_CLASS_TCP_SOURCE_PORT, tags->src_port,
                METRIC_PORT_MAX, state, body, logger, iplen);
        process_single_tag(CORSARO_METRIC_CLASS_TCP_DEST_PORT, tags->dest_port,
                METRIC_PORT_MAX, state, body, logger, iplen);
    } else if (tags->protocol == TRACE_IPPROTO_UDP) {
        process_single_tag(CORSARO_METRIC_CLASS_UDP_SOURCE_PORT, tags->src_port,
                METRIC_PORT_MAX, state, body, logger, iplen);
        process_single_tag(CORSARO_METRIC_CLASS_UDP_DEST_PORT, tags->dest_port,
                METRIC_PORT_MAX, state, body, logger, iplen);
    }

    if (maxmind_tagged(tags)) {
        process_single_tag(CORSARO_METRIC_CLASS_MAXMIND_CONTINENT,
                tags->maxmind_continent, 0, state, body, logger, iplen);
        process_single_tag(CORSARO_METRIC_CLASS_MAXMIND_COUNTRY,
                tags->maxmind_country, 0, state, body, logger, iplen);
    }

    if (netacq_tagged(tags)) {
        process_single_tag(CORSARO_METRIC_CLASS_NETACQ_CONTINENT,
                tags->netacq_continent, 0, state, body, logger, iplen);
        process_single_tag(CORSARO_METRIC_CLASS_NETACQ_COUNTRY,
                tags->netacq_country, 0, state, body, logger, iplen);
    }

    if (pfx2as_tagged(tags)) {
        process_single_tag(CORSARO_METRIC_CLASS_PREFIX_ASN,
                tags->prefixasn, 0, state, body, logger, iplen);
    }

}

/** Form an IP update message for a set of tags and ensure that it is queued
 *  for the correct IP tracker thread.
 *
 *  All of the tags in the tag set should be derived from the same packet.
 *
 *  @param conf         The global configuration for this plugin
 *  @param state        The packet processing thread state for this plugin
 *  @param addr         An IP address from the original packet
 *  @param issrc        Set to 1 if 'addr' is the source IP address, 0 if
 *                      'addr' is the destination IP address.
 *  @param iplen        The number of IP-layer bytes in the original packet
 *  @param tags         The set of tags to insert into the IP update
 *  @param logger       A reference to a corsaro logger for error reporting
 */
static inline void update_metrics_for_address(corsaro_report_config_t *conf,
        corsaro_report_state_t *state, uint32_t addr, uint8_t issrc,
        uint16_t iplen, corsaro_packet_tags_t *tags, corsaro_logger_t *logger) {

    corsaro_report_msg_body_t *body;
    corsaro_report_ip_message_t *msg;
    int trackerhash;
    PWord_t pval;
    Word_t index;
    uint64_t key;

    /* Hash IPs to IP tracker threads based on the suffix octet of the IP
     * address -- should be reasonably balanced + easy to calculate.
     */
    trackerhash = (addr >> 24) % conf->tracker_count;

    /* Add the IP and its tagged metrics to the next IP update message that
     * we are sending to the IP tracker thread. */

    if (issrc) {
        key = (uint64_t)addr;
    } else {
        key = ((uint64_t)addr | 0x100000000);
    }

    index = addr;
    JLG(pval, state->totracker[trackerhash].ipmetrics, key);
    if (pval == NULL) {
        JLI(pval, state->totracker[trackerhash].ipmetrics, key);
        body = calloc(1, sizeof(corsaro_report_msg_body_t));
        *pval = (Word_t)body;

        body->ipaddr = addr;
        body->issrc = issrc;
        body->numtags = 0;
        body->size = 0;
        body->tags = NULL;
        body->seenthisinterval = 1;
        state->totracker[trackerhash].ipcount ++;
    } else {
        body = (corsaro_report_msg_body_t *)*pval;

        if (body->seenthisinterval == 0) {
            body->seenthisinterval = 1;
            state->totracker[trackerhash].ipcount ++;
        }
    }

    process_tags(tags, iplen, body, state, logger, addr);

    /* Putting messages onto a queue is moderately expensive so it is better
     * for us to enqueue messages that contain multiple IP updates. That
     * allows us to do 1 queue operation for every REPORT_BATCH_SIZE updates,
     * just have to be careful about ensuring unfinished batches still get
     * pushed through when necessary (i.e. the end of an interval).
     *
     * To make life easier for the tracker threads receiving our messages,
     * we'll also automatically send the message as soon as we see a whole
     * bunch of tags for a single address -- this means we don't have to
     * worry about our tags map being stupidly large and difficult to receive.
     */
    if (body->numtags < CORSARO_MAX_SUPPORTED_TAGS &&
            state->totracker[trackerhash].ipcount < REPORT_BATCH_SIZE) {
        return;
    }

    if (send_iptracker_message(state, logger, &(state->totracker[trackerhash]))
            < 0) {
        corsaro_log(logger,
                "error while pushing result to tracker thread %d: %s",
                trackerhash, strerror(errno));
    }

}

/** Update the reported metrics based on the content of a single packet.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param local        The packet processing thread state for this plugin.
 *  @param packet       The packet that is being used to update the metrics.
 *  @param tags         The tags associated with this packet by the libcorsaro
 *                      tagging component.
 *  @return 0 if the packet was successfully processed, -1 if an error occurs.
 */
int corsaro_report_process_packet(corsaro_plugin_t *p, void *local,
        libtrace_packet_t *packet, corsaro_packet_tags_t *tags) {

    corsaro_report_state_t *state;
    uint16_t iplen;
    uint32_t srcaddr, dstaddr;
    corsaro_report_config_t *conf;

    conf = (corsaro_report_config_t *)(p->config);
    state = (corsaro_report_state_t *)local;

    if (state == NULL) {
        corsaro_log(p->logger,
                "corsaro_report_process_packet: report thread-local state is NULL!");
        return -1;
    }

    if (extract_addresses(packet, &srcaddr, &dstaddr, &iplen) != 0) {
        return 0;
    }
    /* Update our metrics observed for the source address */
    update_metrics_for_address(conf, state, srcaddr, 1, iplen, tags, p->logger);
    /* Update our metrics observed for the destination address */
    update_metrics_for_address(conf, state, dstaddr, 0, iplen, tags, p->logger);
    return 0;
}

/** ------------- MERGING API -------------------- */

/** Creates and initialises the internal state required by the merging thread
 *  when using the report plugin.
 *
 *  @param p        A reference to the running instance of the report plugin
 *  @param sources  The number of packet processing threads that will be
 *                  feeding into the merging thread.
 *  @param tagsock  A zeromq socket for sending label update requests to
 *                  the tagger.
 *  @return A pointer to the newly create report merging state.
 */
void *corsaro_report_init_merging(corsaro_plugin_t *p, int sources,
        void *tagsock) {

    corsaro_report_merge_state_t *m;
    corsaro_report_config_t *conf;

    conf = (corsaro_report_config_t *)(p->config);

    m = (corsaro_report_merge_state_t *)calloc(1,
            sizeof(corsaro_report_merge_state_t));
    if (m == NULL) {
        corsaro_log(p->logger,
                "corsaro_report_init_merging: out of memory while allocating merge state.");
        return NULL;
    }

    m->zmq_taggersock = tagsock;
    m->last_label_update = 0;

    if (conf->outformat == CORSARO_OUTPUT_AVRO) {
        m->writer = corsaro_create_avro_writer(p->logger, REPORT_RESULT_SCHEMA);
        if (m->writer == NULL) {
            corsaro_log(p->logger,
                    "error while creating avro writer for report plugin!");
            free(m);
            return NULL;
        }
    } else {
        m->writer = NULL;
    }

    if (conf->outformat == CORSARO_OUTPUT_LIBTIMESERIES) {
        m->timeseries = timeseries_init();
        if (m->timeseries == NULL) {
            corsaro_log(p->logger,
                    "unable to initialize libtimeseries");
            free(m);
            return NULL;
        }

        if (enable_libts_ascii_backend(p->logger, m->timeseries,
                conf->basic.libtsascii)) {
            corsaro_log(p->logger, "skipping libtimeseries ascii output");
        }
        if (enable_libts_kafka_backend(p->logger, m->timeseries,
                conf->basic.libtskafka)) {
            corsaro_log(p->logger, "skipping libtimeseries kafka output");
        }
        if (enable_libts_dbats_backend(p->logger, m->timeseries,
                conf->basic.libtsdbats)) {
            corsaro_log(p->logger, "skipping libtimeseries DBATS output");
        }

        m->kp = timeseries_kp_init(m->timeseries, TIMESERIES_KP_RESET);
        if (m->kp == NULL) {
            corsaro_log(p->logger,
                    "unable to initialize libtimeseries key package");
            timeseries_free(&(m->timeseries));
            free(m);
            return NULL;
        }

    } else {
        m->timeseries = NULL;
        m->kp = NULL;
    }

    m->metrickp_keys = (Pvoid_t) NULL;
    m->country_labels = (Pvoid_t) NULL;
    m->region_labels = (Pvoid_t) NULL;

    return m;
}

/** Tidies up the internal state used by the merging thread to combine
 *  results from the report plugin.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param local        The merge thread state for this plugin
 *  @return 0 if successful, -1 if an error occurs.
 */
int corsaro_report_halt_merging(corsaro_plugin_t *p, void *local) {
    corsaro_report_merge_state_t *m;
    Word_t judyret;

    m = (corsaro_report_merge_state_t *)local;
    if (m == NULL) {
        return 0;
    }

    if (m->writer) {
        corsaro_destroy_avro_writer(m->writer);
    }

    if (m->kp) {
        timeseries_kp_free(&(m->kp));
    }

    if (m->timeseries) {
        timeseries_free(&(m->timeseries));
    }

    JLFA(judyret, m->metrickp_keys);
    corsaro_free_ipmeta_label_map(m->country_labels, 1);
    corsaro_free_ipmeta_label_map(m->region_labels, 1);

    free(m);
    return 0;
}

#define AVRO_CONVERSION_FAILURE -1
#define AVRO_WRITE_FAILURE -2

#define LOOKUP_COUNTRY_CONTINENT(contmap, metricid) \
    lookup = metricid & 0xffffffff; \
    JLF(pval, contmap, lookup); \
    if (pval == NULL) { \
        contkey = "notfound"; \
    } else { \
        contkey = (const char *)*pval; \
    }

#define STRIP_METRIC_VALUE(foundkey, dest, len) \
    { \
        char *rstr = strrchr(foundkey, '.'); \
        if (rstr == NULL || rstr - foundkey >= len) { \
            memcpy(dest, foundkey, len - 1); \
            metrickey[len - 1] = '\0'; \
        } else { \
            memcpy(dest, foundkey, rstr - foundkey); \
            metrickey[rstr - foundkey] = '\0'; \
        } \
    }

/** Produce fully-qualified labels for both the metric class and the
 *  metric value for a given result.
 *
 */
static inline void metric_to_strings(corsaro_report_merge_state_t *m,
        corsaro_report_result_t *res) {

    Word_t *pval;
    const char *contkey = NULL;
    char metrickey[128];
    uint64_t lookup;

    /* Convert the 64 bit metric ID into printable strings that we can
     * put in our result output.
     *
     * Hopefully, these will match the strings that were used by
     * previous instances of this plugin...
     */
    switch(res->metricid >> 32) {
        case CORSARO_METRIC_CLASS_COMBINED:
            strncpy(res->metrictype, "overall", 128);
            res->metricval[0] = '\0';
            break;
        case CORSARO_METRIC_CLASS_IP_PROTOCOL:
            strncpy(res->metrictype, "traffic.protocol", 128);
            snprintf(res->metricval, 128, "%lu", res->metricid & 0xffffffff);
            break;
        case CORSARO_METRIC_CLASS_ICMP_CODE:
            strncpy(res->metrictype, "traffic.icmp.code", 128);
            snprintf(res->metricval, 128, "%lu", res->metricid & 0xffffffff);
            break;
        case CORSARO_METRIC_CLASS_ICMP_TYPE:
            strncpy(res->metrictype, "traffic.icmp.type", 128);
            snprintf(res->metricval, 128, "%lu", res->metricid & 0xffffffff);
            break;
        case CORSARO_METRIC_CLASS_TCP_SOURCE_PORT:
            strncpy(res->metrictype, "traffic.port.tcp.src_port", 128);
            snprintf(res->metricval, 128, "%lu", res->metricid & 0xffffffff);
            break;
        case CORSARO_METRIC_CLASS_TCP_DEST_PORT:
            strncpy(res->metrictype, "traffic.port.tcp.dst_port", 128);
            snprintf(res->metricval, 128, "%lu", res->metricid & 0xffffffff);
            break;
        case CORSARO_METRIC_CLASS_UDP_SOURCE_PORT:
            strncpy(res->metrictype, "traffic.port.udp.src_port", 128);
            snprintf(res->metricval, 128, "%lu", res->metricid & 0xffffffff);
            break;
        case CORSARO_METRIC_CLASS_UDP_DEST_PORT:
            strncpy(res->metrictype, "traffic.port.udp.dst_port", 128);
            snprintf(res->metricval, 128, "%lu", res->metricid & 0xffffffff);
            break;
        case CORSARO_METRIC_CLASS_MAXMIND_CONTINENT:
            strncpy(res->metrictype, "geo.maxmind", 128);
            snprintf(res->metricval, 128, "%c%c", (int)(res->metricid & 0xff),
                    (int)((res->metricid >> 8) & 0xff));
            break;
        case CORSARO_METRIC_CLASS_MAXMIND_COUNTRY:
            LOOKUP_COUNTRY_CONTINENT(m->country_labels, res->metricid)
            STRIP_METRIC_VALUE(contkey, metrickey, 128);
            snprintf(res->metrictype, 256, "geo.maxmind.%s", metrickey);
            snprintf(res->metricval, 128, "%c%c", (int)(res->metricid & 0xff),
                    (int)((res->metricid >> 8) & 0xff));
            break;
        case CORSARO_METRIC_CLASS_NETACQ_CONTINENT:
            strncpy(res->metrictype, "geo.netacuity", 128);
            snprintf(res->metricval, 128, "%c%c", (int)(res->metricid & 0xff),
                    (int)((res->metricid >> 8) & 0xff));
            break;
        case CORSARO_METRIC_CLASS_NETACQ_COUNTRY:
            LOOKUP_COUNTRY_CONTINENT(m->country_labels, res->metricid)
            STRIP_METRIC_VALUE(contkey, metrickey, 128);
            snprintf(res->metrictype, 256, "geo.netacuity.%s", metrickey);
            snprintf(res->metricval, 128, "%c%c", (int)(res->metricid & 0xff),
                    (int)((res->metricid >> 8) & 0xff));
            break;
        case CORSARO_METRIC_CLASS_PREFIX_ASN:
            strncpy(res->metrictype , "routing.asn", 128);
            snprintf(res->metricval, 128, "%lu", res->metricid & 0xffffffff);
            break;
    }
}

/** Given a report result, determines the base name for the corresponding
 *  libtimeseries key for lookup in our "known keys" map.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param m            The local state for the merging thread.
 *  @param keyspace     A string buffer that we can write the key name into
 *  @param keylen       The size of the keyspace buffer
 *  @param res          A single report plugin result which we need the key
 *                      name for.
 *
 *  @return the length of the resulting key string.
 */
static inline int derive_libts_keyname(corsaro_plugin_t *p,
        corsaro_report_merge_state_t *m,
        char *keyspace, int keylen, corsaro_report_result_t *res) {

    int ret;
    corsaro_report_config_t *config = (corsaro_report_config_t *)p->config;

    metric_to_strings(m, res);
    /* 'overall' metrics have no suitable metric value, so we need to
     * account for this case.
     */
    if (strlen(res->metricval) > 0) {
        ret = snprintf(keyspace, keylen, "%s.%s.%s",
                config->outlabel, res->metrictype, res->metricval);
    } else {
        ret = snprintf(keyspace, keylen, "%s.%s",
                config->outlabel, res->metrictype);
    }

    if (ret >= keylen) {
        corsaro_log(p->logger,
                "truncated libtimeseries key basename to '%s', output_row_label is too long",
                keyspace);
        ret = keylen - 1;
    }

    return ret;
}

/** Convert a report result into an Avro record and write it to the Avro
 *  output file.
 *
 *  @param logger       A reference to a corsaro logger for error reporting
 *  @param writer       The corsaro Avro writer that will be writing the output
 *  @param res          The report plugin result to be written.
 *  @return 0 if the write is successful, -1 if an error occurs.
 */
static int write_single_metric_avro(corsaro_report_merge_state_t *m,
        corsaro_logger_t *logger,
        corsaro_avro_writer_t *writer, corsaro_report_result_t *res) {

    avro_value_t *avro;

    metric_to_strings(m, res);
    avro = corsaro_populate_avro_item(writer, res, report_result_to_avro);
    if (avro == NULL) {
        corsaro_log(logger,
                "could not convert report result to Avro record");
        return AVRO_CONVERSION_FAILURE;
    }

    if (corsaro_append_avro_writer(writer, avro) < 0) {
        corsaro_log(logger,
                "could not write report result to Avro output file");
        return AVRO_WRITE_FAILURE;
    }
    return 0;
}

/** Writes the combined tallies for each metric to an Avro output file
 *
 *  @param logger       A reference to a corsaro logger for error reporting.
 *  @param writer       The corsaro Avro writer that will be writing the output.
 *  @param resultmap    The hash map containing the combined metric tallies.
 *  @param m            The local state for the merging thread.
 *  @param subtreemask  A bitmask showing which metric classes were actively
 *                      measured during the last interval
 *  @return 0 if successful, -1 if an error occurred.
 */

static int write_all_metrics_avro(corsaro_logger_t *logger,
        corsaro_avro_writer_t *writer, Pvoid_t *resultmap,
        corsaro_report_merge_state_t *m, uint32_t subtreemask) {

    corsaro_report_result_t *r, *tmpres;
    int writeret = 0;
    int stopwriting = 0;
    int haderror = 0;
    Word_t index = 0, judyret;
    PWord_t pval;

    JLF(pval, *resultmap, index);
    while (pval) {
        r = (corsaro_report_result_t *)(*pval);

        /* Don't write metrics for sub-trees that have never been
         * looked at by the upstream tagger, e.g. if we have no
         * maxmind tagging, don't write a bunch of 0s for each
         * country.
         */
        if ((subtreemask & (1 << (r->metricid >> 32))) == 0) {
            free(r);
            JLN(pval, *resultmap, index);
            continue;
        }

        /* If we run into an error while writing, maybe don't try to write
         * anymore.
         */
        if (!stopwriting) {
            writeret = write_single_metric_avro(m, logger, writer, r);
            if (writeret == AVRO_WRITE_FAILURE) {
                stopwriting = 1;
            }
            if (writeret < 0) {
                haderror = 1;
            }
        }
        free(r);

        JLN(pval, *resultmap, index);
    }

    JLFA(judyret, *resultmap);
    return haderror;

}

#define ADD_TIMESERIES_KEY(metric) \
    snprintf(fullkeyname, 5000, "%s.%s", keyname, metric); \
    keyid = timeseries_kp_add_key(m->kp, fullkeyname); \
    if (keyid == -1) { \
        corsaro_log(p->logger, \
                "error adding %s to timeseries key package", fullkeyname); \
        return -1; \
    }


/** Writes the combined tallies for each metric using libtimeseries.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param m            The merge thread state for this plugin
 *  @param timestamp    The timestamp for the interval that the tallies
 *                      correspond to
 *  @param results      A Judy array containing the tallies
 *  @param subtreemask  A bitmask showing which metric classes were actively
 *                      measured during the last interval
 *
 *  @return -1 if an error occurs, 0 if successful
 */
static int report_write_libtimeseries(corsaro_plugin_t *p,
        corsaro_report_merge_state_t *m, uint32_t timestamp, Pvoid_t *results,
        uint32_t subtreemask)
{
    corsaro_report_result_t *r;
    Word_t index = 0, judyret;
    PWord_t pval;

    JLF(pval, *results, index);

    /* Iterate over all of the metrics in our array */
    while (pval) {
        r = (corsaro_report_result_t *)(*pval);

        /* Don't write metrics for sub-trees that have never been
         * looked at by the upstream tagger, e.g. if we have no
         * maxmind tagging, don't write a bunch of 0s for each
         * country.
         */
        if ((subtreemask & (1 << (r->metricid >> 32))) == 0) {
            free(r);
            JLN(pval, *results, index);
            continue;
        }

        JLG(pval, m->metrickp_keys, r->metricid);
        if (pval == NULL) {
            /* This is a metric ID that we haven't seen before so we need
             * to create a new 'key' in libtimeseries for it.
             */
            char keyname[4096];
            char fullkeyname[5000];
            int keyid = -1;

            if (derive_libts_keyname(p, m, keyname, 4096, r) <= 0) {
                corsaro_log(p->logger,
                        "error deriving suitable keyname from metricid %lu",
                        r->metricid);
                return -1;
            }

            /* We'll need a separate key for each of our tallies */
            ADD_TIMESERIES_KEY("uniq_src_ip");

            /* Do the JLI here, as we only want to add the first of the
             * four keys to our metrickp_keys array */
            JLI(pval, m->metrickp_keys, r->metricid);
            *pval = (Word_t)keyid;

            ADD_TIMESERIES_KEY("uniq_dst_ip");
            ADD_TIMESERIES_KEY("pkt_cnt");
            ADD_TIMESERIES_KEY("ip_len");
        }

        /* *pval contains the key ID for uniq_src_ip, but keys are
         * assigned sequentially so we can use that to derive the key IDs
         * for the other tallies. */
        timeseries_kp_set(m->kp, *pval, r->uniq_src_ips);
        timeseries_kp_set(m->kp, (*pval) + 1, r->uniq_dst_ips);
        timeseries_kp_set(m->kp, (*pval) + 2, r->pkt_cnt);
        timeseries_kp_set(m->kp, (*pval) + 3, r->bytes);

        free(r);
        JLN(pval, *results, index);
    }

    /* Flush all of our results for this interval to the backends */
    timeseries_kp_flush(m->kp, timestamp);
    JLFA(judyret, *results);
    return 0;
}

static void clean_result_map(Pvoid_t *resultmap) {

    corsaro_report_result_t *r;
    Word_t index = 0, judyret;
    PWord_t pval;

    JLF(pval, *resultmap, index);
    while (pval) {
        r = (corsaro_report_result_t *)(*pval);
        free(r);
        JLN(pval, *resultmap, index);
    }

    JLFA(judyret, *resultmap);
}

/** Allocate and initialise a new report plugin result.
 *
 *  @param metricid         The ID of the metric that this result is for
 *  @param outlabel         The additional label to append to this result.
 *  @param ts               The timestamp of the interval that this result will
 *                          belong to.
 *  @return a pointer to a freshly created report plugin result.
 */
static inline corsaro_report_result_t *new_result(uint64_t metricid,
        char *outlabel, uint32_t ts) {

    corsaro_report_result_t *r;

    r = (corsaro_report_result_t *)calloc(1, sizeof(corsaro_report_result_t));
    r->metricid = metricid;
    r->pkt_cnt = 0;
    r->bytes = 0;
    r->uniq_src_ips = 0;
    r->uniq_dst_ips = 0;
    r->attimestamp = ts;
    r->label = outlabel;
    r->metrictype[0] = '\0';
    r->metricval[0] = '\0';
    return r;
}

/** Update the merged result set for an interval with a set of completed
 *  tallies from an IP tracker thread.
 *
 *  @param results          The hash map containing the combined metric tallies.
 *  @param tracker          The IP tracker thread which is providing new
 *                          tallies for our merged result.
 *  @param ts               The timestamp of the interval which this tally
 *                          applies to.
 *  @param conf             The global configuration for this report plugin.
 *  @param logger       A reference to a corsaro logger for error reporting.
 */
static void update_tracker_results(Pvoid_t *results,
        corsaro_report_iptracker_t *tracker, uint32_t ts,
        corsaro_report_config_t *conf,  uint32_t *subtrees_seen,
        corsaro_logger_t *logger) {

    corsaro_report_result_t *r;
    corsaro_metric_ip_hash_t *iter;
    PWord_t pval, pval2;
    Word_t index = 0, ret;

    /* Simple loop over all metrics in the tracker tally and update our
     * combined metric map.
     */

    JLF(pval, tracker->lastresult, index);
    while (pval) {
        iter = (corsaro_metric_ip_hash_t *)(*pval);

        *subtrees_seen = (*subtrees_seen) | (1 << (iter->metricid >> 32));

        JLG(pval2, *results, iter->metricid);
        if (pval2 == NULL) {
            /* This is a new metric, add it to our result hash map */
            r = new_result(iter->metricid, conf->outlabel, ts);
            JLI(pval2, *results, iter->metricid);
            *pval2 = (Word_t)r;
        } else {
            r = (corsaro_report_result_t *)(*pval2);
        }

        r->uniq_src_ips += iter->srcips;
        r->uniq_dst_ips += iter->destips;
        r->pkt_cnt += iter->packets;
        r->bytes += iter->bytes;

        /* Don't forget to release the metric tally back to the IP tracker */
        free(iter);

        JLN(pval, tracker->lastresult, index);
    }

    JLFA(ret, tracker->lastresult);
    tracker->lastresult = NULL;
}

/** Writes the combined tallies for each metric using a corsaro avro writer.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param m            The merge thread state for this plugin
 *  @param timestamp    The timestamp for the interval that the tallies
 *                      correspond to
 *  @param results      A Judy array containing the tallies
 *  @param subtreemask  A bitmask showing which metric classes were actively
 *                      measured during the last interval
 *
 *  @return -1 if an error occurs, 0 if successful
 */
static int report_write_avro_output(corsaro_plugin_t *p,
        corsaro_report_merge_state_t *m, uint32_t timestamp,
        Pvoid_t *results, uint32_t subtreemask) {

    char *outname;

    /* Make sure we've got a valid Avro writer ready to go */
    if (!corsaro_is_avro_writer_active(m->writer)) {
        outname = p->derive_output_name(p, m, timestamp, -1);
        if (outname == NULL) {
            return -1;
        }
        if (corsaro_start_avro_writer(m->writer, outname) == -1) {
            free(outname);
            return -1;
        }
        free(outname);
    }

    if (write_all_metrics_avro(p->logger, m->writer, results,
                m, subtreemask) < 0) {
        return -1;
    }

    return 0;
}

#define ADD_EMPTY_RESULT(metricclass, metricval) \
    metricid = GEN_METRICID(metricclass, metricval); \
    r = new_result(metricid, conf->outlabel, ts); \
    JLI(pval, *results, (Word_t)metricid); \
    *pval = (Word_t)r;


/** Initialises a results array with zeroes for as many metrics as
 *  we can, so we are still able to write a valid value even if the metric
 *  is not observed within an interval.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param results      The Judy array that will be used to store the tallies
 *  @param ts           The timestamp for the current interval
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static int initialise_results(corsaro_plugin_t *p, Pvoid_t *results,
        uint32_t ts) {

    uint64_t metricid, i;
    Word_t *pval;
    corsaro_report_result_t *r;
    corsaro_report_config_t *conf;
    int mm_country_count;
    const char **mm_country_list;

    conf = (corsaro_report_config_t *)(p->config);

    ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_COMBINED, 0);

    /* IP protocols, ICMP codes and types */
    for (i = 0; i < METRIC_ICMP_MAX; i++) {
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_IP_PROTOCOL, i);
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_ICMP_CODE, i);
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_ICMP_TYPE, i);
    }

    /* TCP and UDP ports */
    for (i = 0; i < METRIC_PORT_MAX; i++) {
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_TCP_SOURCE_PORT, i);
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_TCP_DEST_PORT, i);
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_UDP_SOURCE_PORT, i);
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_UDP_DEST_PORT, i);
    }

    /* ASNs are too sparse? */

    /* Continents */
    for (i = 0; i < CORSAROTRACE_NUM_CONTINENTS; i++) {
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_MAXMIND_CONTINENT,
                (((uint64_t)alpha2_continents[i][0]) |
                 ((uint64_t)alpha2_continents[i][1]) << 8));
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_NETACQ_CONTINENT,
                (((uint64_t)alpha2_continents[i][0]) |
                 ((uint64_t)alpha2_continents[i][1]) << 8));
    }

    /* Countries */
    for (i = 0; i < CORSAROTRACE_NUM_COUNTRIES; i++) {
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_MAXMIND_COUNTRY,
                (((uint64_t)alpha2_countries[i][0]) |
                 ((uint64_t)alpha2_countries[i][1]) << 8));
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_NETACQ_COUNTRY,
                (((uint64_t)alpha2_countries[i][0]) |
                 ((uint64_t)alpha2_countries[i][1]) << 8));
    }


    return 0;
}

#define INSERT_IPMETA_LABEL(labelmap, index, labelstr) \
    { \
    PWord_t pval; \
    JLI(pval, labelmap, index); \
    if ((char *)(*pval) != NULL) { \
        free((char *)(*pval)); \
    } \
    *pval = (Word_t)labelstr; \
    }

/** Asks the tagger for an updated set of FQ labels for each geo-tagged
 *  country, region and polygon.
 *
 *  @param state    Local state for the merging thread
 *  @param logger   A reference to a corsaro logger for error reporting.
 *
 *  @return -1 if an error occurs, 1 otherwise.
 */
static int update_ipmeta_labels(corsaro_report_merge_state_t *state,
        corsaro_logger_t *logger) {

    corsaro_tagger_control_request_t req;
    corsaro_tagger_control_reply_t *reply;
    zmq_msg_t frame;
    char *buffer;
    int buflen;
    int firstpass = 1;
    int iserr = 0;
    uint32_t tocome = 0;
    int more;
    size_t more_size;
    int attempts = 0;

    req.request_type = TAGGER_REQUEST_IPMETA_UPDATE;
    req.data.last_version = htonl(state->last_label_update);

    if (zmq_send(state->zmq_taggersock, &req, sizeof(req), 0) < 0) {
        corsaro_log(logger, "unable to send IPmeta update request to corsarotagger: %s", strerror(errno));
        return -1;
    }

    while (!iserr) {
        zmq_msg_init(&frame);

        /* If we don't get a response within a second, assume the tagger is
         * too busy -- skip the update and try again next time.
         */
        while (attempts < 10) {
            if (zmq_msg_recv(&frame, state->zmq_taggersock, ZMQ_DONTWAIT) < 0) {
                if (errno == EAGAIN) {
                    attempts ++;
                    usleep(100000);
                    continue;
                }

                corsaro_log(logger, "unable to receive IPmeta update from corsarotagger: %s", strerror(errno));
                zmq_msg_close(&frame);
                return -1;
            }
            break;
        }

        if (attempts >= 10) {
            corsaro_log(logger, "failed to get ipmeta label response in reasonable time frame");
            zmq_msg_close(&frame);
            return -1;
        }

        buffer = zmq_msg_data(&frame);
        buflen = zmq_msg_size(&frame);

        /* Reply may be spread over multiple messages... */
        if (firstpass) {
            reply = (corsaro_tagger_control_reply_t *)buffer;

            state->last_label_update = ntohl(reply->ipmeta_version);
            tocome = ntohl(reply->label_count);
            firstpass = 0;

            buffer += sizeof(corsaro_tagger_control_reply_t);
            buflen -= sizeof(corsaro_tagger_control_reply_t);
        }

        while (buflen > 0) {
            corsaro_tagger_label_hdr_t *hdr;
            char *labelstr;
            uint16_t labellen;
            uint32_t index;

            if (buflen < sizeof(corsaro_tagger_label_hdr_t)) {
                corsaro_log(logger, "parsing error in received IPmeta update -- %d bytes left over in message, need at least %d",
                        buflen, sizeof(corsaro_tagger_label_hdr_t));
                goto drainmessage;
            }

            hdr = (corsaro_tagger_label_hdr_t *)buffer;
            labellen = ntohs(hdr->label_len);
            labelstr = calloc(labellen + 1, sizeof(char));

            if (buflen < sizeof(corsaro_tagger_label_hdr_t) + labellen) {
                corsaro_log(logger, "parsing error in received IPmeta update -- %d bytes left over in message, need at least %d",
                        buflen, sizeof(corsaro_tagger_label_hdr_t) + labellen);
                goto drainmessage;
            }

            /* TODO actually make this work for regions and/or polygons */
            memcpy(labelstr, buffer + sizeof(corsaro_tagger_label_hdr_t),
                    labellen);

            index = ntohl(hdr->subject_id);

            if (hdr->subject_type == TAGGER_LABEL_COUNTRY) {
                INSERT_IPMETA_LABEL(state->country_labels, index, labelstr);
            }
            if (hdr->subject_type == TAGGER_LABEL_REGION) {
                INSERT_IPMETA_LABEL(state->region_labels, index, labelstr);
            }

            buffer += (sizeof(corsaro_tagger_label_hdr_t) + labellen);
            buflen -= (sizeof(corsaro_tagger_label_hdr_t) + labellen);

        }

        more_size = sizeof(more);
        if (zmq_getsockopt(state->zmq_taggersock, ZMQ_RCVMORE, &more,
                    &more_size) < 0) {
            corsaro_log(logger, "error while checking for more IPmeta update content: %s", strerror(errno));
            return -1;
        }

        zmq_msg_close(&frame);
        if (more == 0) {
            break;
        }
    }

    return 1;

drainmessage:
    /* Something went wrong with our IPmeta label parsing, so try to drain
     * any remaining message parts from the queue before returning an error
     * code.
     */

    zmq_msg_close(&frame);
    if (zmq_getsockopt(state->zmq_taggersock, ZMQ_RCVMORE, &more,
                &more_size) < 0) {
        corsaro_log(logger, "error while draining bad IPmeta update content: %s", strerror(errno));
        return -1;
    }

    while (more) {
        zmq_msg_init(&frame);
        if (zmq_msg_recv(state->zmq_taggersock, &frame, 0) < 0) {
            corsaro_log(logger, "unable to receive IPmeta update from corsarotagger: %s", strerror(errno));
            break;
        }

        if (zmq_getsockopt(state->zmq_taggersock, ZMQ_RCVMORE, &more,
                    &more_size) < 0) {
            corsaro_log(logger, "error while draining bad IPmeta update content: %s", strerror(errno));
            break;
        }
    }
    zmq_msg_close(&frame);
    return -1;
}

/** Merge the metric tallies for a given interval into a single combined
 *  result and write it to our Avro output file.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param local        The merge thread state for this plugin
 *  @param tomerge      An array of interim results from each of the packet
 *                      processing threads.
 *  @param fin          The interval that has just been completed.
 *  @return 0 if the merge is successful, -1 if an error occurs.
 */
int corsaro_report_merge_interval_results(corsaro_plugin_t *p, void *local,
        void **tomerge, corsaro_fin_interval_t *fin) {

    corsaro_report_config_t *conf, *procconf;
    corsaro_report_merge_state_t *m;
    int i;
    Pvoid_t results = NULL;
    uint8_t *trackers_done;
    uint8_t totaldone = 0, skipresult = 0;

    uint32_t subtrees_seen = 0;

    m = (corsaro_report_merge_state_t *)local;
    if (m == NULL) {
        return -1;
    }

    /* Plugin result data is NULL, must be a partial interval */
    if (tomerge[0] == NULL) {
        return 0;
    }

    conf = (corsaro_report_config_t *)(p->config);
    /* Now would be a good time to make sure we have a copy of all of the
     * IPmeta labels that we need...
     */
    if (conf->query_tagger_labels && update_ipmeta_labels(m, p->logger) < 0) {
        corsaro_log(p->logger, "unable to fetch labels for IPmeta metrics: metric names may not be up to date...");
    }

    /* All of the interim results should point at the same config, so we
     * only care about tomerge[0].
     *
     * Note that we can't use p->config to get at the IP trackers because
     * the plugin instance 'p' does NOT point at the same plugin instance
     * that was used to run the processing threads.
     */
    procconf = ((corsaro_report_interim_t *)(tomerge[0]))->baseconf;

    trackers_done = (uint8_t *)calloc(procconf->tracker_count, sizeof(uint8_t));

    if (initialise_results(p, &results, fin->timestamp) < 0) {
        return -1;
    }

    do {
        /* The IP tracker threads may not have finished processing all of their
         * outstanding updates for the interval just yet, so we need to
         * keep polling until all of the trackers have finalised their
         * results for this interval.
         */
        for (i = 0; i < procconf->tracker_count; i++) {
            if (trackers_done[i]) {
                continue;
            }

            /* If we can't get the lock, try another tracker thread */
            if (pthread_mutex_trylock(&(procconf->iptrackers[i].mutex)) == 0) {
                if (procconf->iptrackers[i].lastresultts > fin->timestamp) {
                    trackers_done[i] = 1;
                    totaldone ++;
                    skipresult = 1;
                } else if (procconf->iptrackers[i].lastresultts ==
                        fin->timestamp) {
                    update_tracker_results(&results, &(procconf->iptrackers[i]),
                            fin->timestamp, conf, &subtrees_seen, p->logger);
                    trackers_done[i] = 1;
                    totaldone ++;
                } else if (procconf->iptrackers[i].haltphase == 2) {
                    /* Tracker thread has been halted, no new results are
                     * coming... */
                    trackers_done[i] = 1;
                    totaldone ++;
                    skipresult = 1;
                }
                pthread_mutex_unlock(&(procconf->iptrackers[i].mutex));
            }
        }
        /* Some tracker threads were either busy or still waiting for
         * an interval end message, take a quick break then try again.
         */
        if (totaldone < procconf->tracker_count) {
            usleep(100);
        }
    } while (totaldone < procconf->tracker_count);

    free(trackers_done);

    if (skipresult) {
        /* This result is invalid because not all of the tracker threads
         * were able to produce a result (due to being interrupted).
         * Don't try writing it to the avro output to avoid being
         * misleading.
         */
        clean_result_map(&results);
        return 0;
    }

    /* All trackers have reported tallies for this interval and they've
     * been merged into a single result -- write it out!
     */
    if (conf->outformat == CORSARO_OUTPUT_AVRO) {
        if (report_write_avro_output(p, m, fin->timestamp, &results,
                subtrees_seen) < 0) {
            return -1;
        }
    }

    if (conf->outformat == CORSARO_OUTPUT_LIBTIMESERIES) {
        if (report_write_libtimeseries(p, m, fin->timestamp, &results,
                subtrees_seen) < 0) {
            return -1;
        }
    }

    for (i = 0; i < fin->threads_ended; i++) {
        free(tomerge[i]);
    }
    return 0;
}

/** Rotates the output file for the report plugin.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param local        The merge thread state for this plugin
 *  @return 0 if the file rotation was successful, -1 if an error occurs.
 */
int corsaro_report_rotate_output(corsaro_plugin_t *p, void *local) {

    corsaro_report_merge_state_t *m;
    corsaro_report_config_t *conf;

    conf = (corsaro_report_config_t *)(p->config);
    m = (corsaro_report_merge_state_t *)local;
    if (m == NULL) {
        return -1;
    }

    if (conf->outformat == CORSARO_OUTPUT_AVRO) {
        /* Nothing complicated here, just close the current Avro writer. We'll
         * create a new one (along with a new output file) the next time we have
         * a complete set of results for an interval that needs to be written.
         */
        if (m->writer == NULL || corsaro_close_avro_writer(m->writer) < 0) {
            return -1;
        }
    }

    return 0;
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
