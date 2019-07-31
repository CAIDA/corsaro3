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

#ifndef CORSARO_REPORT_INTERNAL_H_
#define CORSARO_REPORT_INTERNAL_H_

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <libipmeta.h>
#include <zmq.h>

#include <Judy.h>
#include "libcorsaro_plugin.h"

/* XXX could make this configurable? */
/** The number of IP tag updates to include in a single enqueued message
 *  to an IP tracker thread. */
#define REPORT_BATCH_SIZE (10000)

/** Macro function for converting a metric class and value into a 64 bit
 *  number that we can use as a numeric hash key.
  */
#define GEN_METRICID(class, val) \
      ((((uint64_t) class) << 32) + ((uint64_t)val))


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

/** Structure for keeping track of missing messages between a processing
 *  thread and an IP tracker thread.
 */
typedef struct corsaro_report_iptracker_source {
    uint32_t expected;      /**< Expected sequence number of the next message */
    uint32_t lost;          /**< Total messages lost since last interval */
} corsaro_report_iptracker_source_t;

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


/** Structure to store state for an IP tracker thread */
typedef struct corsaro_report_iptracker {

    /** The queue for reading incoming messages from the processing threads */
    void *incoming;

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

    /** High water mark for internal messaging queues */
    uint16_t internalhwm;

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
typedef struct corsaro_report_single_ip {

    /** The IP address itself */
    uint32_t ipaddr;

    /** Flag indicating whether the IP was observed as a source IP */
    uint8_t issrc;

    /** The number of metric tags that are following this header */
    uint16_t numtags;

} PACKED corsaro_report_single_ip_header_t;

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

    uint32_t tagcount;
} PACKED corsaro_report_ipmsg_header_t;



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

void *start_iptracker(void *tdata);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
