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

#define CORSARO_WDCAP_STRIP_VLANS_OFF 0
#define CORSARO_WDCAP_STRIP_VLANS_ON 1
#define CORSARO_DEFAULT_WDCAP_STRIP_VLANS CORSARO_WDCAP_STRIP_VLANS_OFF

#define CORSARO_DEFAULT_WDCAP_WRITE_STATS 0

#define CORSARO_WDCAP_INTERNAL_QUEUE_BACK "inproc://wdcapinternalback"
#define CORSARO_WDCAP_INTERNAL_QUEUE_FRONT "inproc://wdcapinternalfront"

#include "libcorsaro_trace.h"
#include "libcorsaro_log.h"
#include "libcorsaro.h"

#define CORSARO_WDCAP_DEFAULT_PIDFILE "/var/run/corsaro/corsarowdcap.pid"

/** Types of messages that can be received by the merging thread */
enum {
    /** Processing thread has seen all packets for a given time interval */
    CORSARO_WDCAP_MSG_INTERVAL_DONE,

    /** Program is ending, please halt thread as soon as possible. */
    CORSARO_WDCAP_MSG_STOP,
};

/** Types used to describe the next available packet in an interim trace
 *  file that is being merged.
 */
enum {
    /** A packet read is required to get the next available packet */
    CORSARO_WDCAP_INTERIM_NOPACKET = 0,

    /** A packet has already been read and is available */
    CORSARO_WDCAP_INTERIM_PACKET = 1,

    /** No more packets remain in the input trace */
    CORSARO_WDCAP_INTERIM_EOF = 2
};


/** Message that is sent to the corsarowdcap merging thread */
typedef struct corsaro_wdcap_message {
    /* The merging thread that this message must be sent to */
    uint8_t target_thread;

    /** The ID of the thread that sent this message */
    uint8_t threadid;

    /** The type of message (see CORSARO_WDCAP_MSG_*) enum for types */
    uint8_t type;

    /** The timestamp of the interval that has just completed (used by
     *  CORSARO_WDCAP_MSG_INTERVAL_DONE messages only)
     */
    uint32_t timestamp;

    /** The file descriptor that was being used to write the completed
     *  interim file (used by CORSARO_WDCAP_MSG_INTERVAL_DONE messages)
     */
    int src_fd;

    /** Stats counters from libtrace */
    libtrace_stat_t lt_stats;
} corsaro_wdcap_message_t;

typedef struct corsaro_wdcap_interval corsaro_wdcap_interval_t;

/** Used by the merging thread to keep track of which processing threads
 *  have reported that an interval is complete. Only once all threads have
 *  signaled that they are finished with an interval, can we begin to merge
 *  the interim files created by those threads.
 */
struct corsaro_wdcap_interval {
    /** The timestamp of the start of the completed interval. */
    uint32_t timestamp;
    /** The number of threads that have reported completion for this interval */
    uint8_t threads_done;
    /** The IDs of done threads (in the same order as the stats structures) */
    uint8_t *thread_ids;
    /** Array of stats stuctures (one per done thread) */
    libtrace_stat_t *thread_stats;
    /** Next pointer to maintain a linked list of outstanding intervals */
    corsaro_wdcap_interval_t *next;
};

typedef struct corsaro_wdcap_local corsaro_wdcap_local_t;
typedef struct corsaro_wdcap_merger corsaro_wdcap_merger_t;

/** Global state for a corsarowdcap instance */
typedef struct corsaro_wdcap_global {

    /** Corsaro logger instance for writing log messages */
    corsaro_logger_t *logger;

    /** Name of the file to write log messages to (if required) */
    char *logfilename;

    /** Libtrace URI describing the source of packets to save to disk */
    char *inputuri;

    /** Libtrace input object for capturing packets */
    libtrace_t *trace;

    /** Indicates whether logging is to stderr, syslog or to a file */
    uint8_t logmode;

	/** A constant ERF framing size for incoming packets -- used to speed
     *  up packet processing for nDAG inputs in cases where the user is
     *  able to guarantee a consistent packet "type" will be captured.
     */
    int consterfframing;

    /** The number of libtrace processing threads to use for reading
     *  packets from the input source.
     */
    uint8_t threads;

    /** The number of merging threads to use */
    uint8_t merge_threads;

    /** The length of the file rotation interval in seconds */
    uint32_t interval;

    /** A string describing this particular corsarowdcap instance, which
     *  can be included in output file names to distinguish between files
     *  from other instances that were running at the same time.
     */
    char *monitorid;

    /** The output file name format, including special formatting characters
     *  will be substituted with appropriate values (see README for more
     *  detail on the file name formatting.
     */
    char *template;

    /** The trace format to use when writing output files (e.g. erf, pcapfile).
     *  Must be a libtrace-compatible format name.
     */
    char *fileformat;

    /** Indicates whether VLAN tags should be stripped from received packets */
    uint8_t stripvlans;

    /** Indicates whether a stats file should be written */
    uint8_t writestats;

    /** ZeroMQ context for managing message queues */
    void *zmq_ctxt;

    /** ZeroMQ queue used for send messages from the main thread to the merge
     *  thread.
     */
    void *zmq_pushsock;

    /** Array to store processing thread local data */
    corsaro_wdcap_local_t *threaddata;

    corsaro_wdcap_merger_t *mergedata;

    uint8_t threads_ended;

    char *pidfile;

    uint8_t compress_level;
    trace_option_compresstype_t compress_method;

    pthread_mutex_t globmutex;

    pthread_t proxy_tid;
} corsaro_wdcap_global_t;

/** Describes an interim trace file that is being read by the merging thread */
typedef struct corsaro_wdcap_interim_reader {
    /** The URI used to identify the trace file */
    char *uri;
    /** The libtrace input handle for this file */
    libtrace_t *source;
    /** The next available packet in the file */
    libtrace_packet_t *nextp;
    /** The timestamp of the next available packet */
    uint64_t nextp_ts;
    /** Indicates whether we need to read another packet or not */
    int status;
} corsaro_wdcap_interim_reader_t;

/** Local thread state for the merging thread */
struct corsaro_wdcap_merger {
    /** pthread ID for this thread */
    pthread_t tid;

    /** Identifier for this merging thread */
    uint8_t thread_num;

    /** A libtrace output handle for the merged output file */
    libtrace_out_t *writer;

    /** References to each of the interim files that are being merged. */
    corsaro_wdcap_interim_reader_t *readers;

    /** Linked list of unfinished intervals that this thread is aware of. */
    corsaro_wdcap_interval_t *waiting;

    /** ZeroMQ queue for receiving messages from other threads. */
    void *zmq_subsock;

    /** Reference to global state for this corsarowdcap instance */
    corsaro_wdcap_global_t *glob;
};

/** Local thread state for the packet processing threads */
struct corsaro_wdcap_local {

    /** Asynchronous I/O output for writing an interim trace file */
    corsaro_fast_trace_writer_t *writer;

    /** pthread identifier for this thread */
    pthread_t tid;

    /** The filename for the current interim trace file */
    char *interimfilename;

    /** The details of the current interval that we are working on */
    corsaro_interval_t current_interval;

    /** Number of intervals completed by this thread */
    uint32_t interval_count;

    /** The timestamp when the current interval is due to end */
    uint32_t next_report;

    /** The timestamp of the last packet processed by this thread */
    uint32_t last_ts;

    /** ZeroMQ socket for pushing messages to the merging thread */
    void *zmq_pushsock;

    /** The last "missed" packet count for this thread */
    uint64_t lastmisscount;
    /** The last "accepted" packet count for this thread */
    uint64_t lastaccepted;

    /** Reference to the global state for this corsarowdcap instance */
    corsaro_wdcap_global_t *glob;

    uint8_t ending;
};

/** Initialises global state for a corsarowdcap instance, based on the
 *  contents of a YAML configuration file.
 *
 *  @param filename     The name of the configuration file to read.
 *  @param logmode      The logging method to employ when running,
 *                      one of GLOBAL_LOGMODE_STDERR, GLOBAL_LOGMODE_FILE or
 *                      GLOBAL_LOGMODE_SYSLOG.
 *  @return A newly allocated and initialised global state for corsarowdcap.
 */
corsaro_wdcap_global_t *corsaro_wdcap_init_global(char *filename,
        int logmode);

/** Frees the global state for a corsarowdcap instance.
 *
 *  @param glob     The global state to be freed.
 */
void corsaro_wdcap_free_global(corsaro_wdcap_global_t *glob);

/** Main loop for the corsarowdcap merging thread.
 *
 *  @param data     The global state for this corsarowdcap instance.
 *
 *  @return NULL once the thread is halted.
 */
void *start_merging_thread(void *data);

/** Uses the output filename template to create a suitable output file
 *  name for either an interim output file or the final merged output file.
 *  Also replaces all special formatting options in the template with
 *  the appropriate value.
 *
 *  Can be used both to generate a file name for writing, as well as by
 *  the merging thread to figure out the names of the interim files that
 *  it should read.
 *
 *  Supports a variety of format modifiers, including everything
 *  recognised by strftime() (for naming files based on the interval
 *  timestamp) plus a few custom ones specific to corsarowdcap (which
 *  are described in the README).
 *
 *  @param glob         The global state for this corsarowdcap instance.
 *  @param timestamp    The timestamp at the start of the current interval.
 *  @param threadid     The cardinal ID for the thread that is the writer of
 *                      this output file. Set to -1 if the writer is the
 *                      merging thread.
 *  @param needformat   If 1, prepend the trace file format followed by a
 *                      colon to the output filename to create a valid
 *                      libtrace URI.
 *  @param exttype      If 1, append the '.done' extension to the filename.
 *                      This is used to create special empty files which
 *                      indicate to archival scripts that an output file is
 *                      complete and ready to be archived.
 *                      If 2, append the '.stats' extension to the filename.
 *                      This is used to create the stats files.
 *  @return A pointer to a string allocated via strdup() that contains the
 *  output file name derived from the given parameters. This name must be
 *  later freed by the caller to avoid leaking the memory holding the string.
 */
char *corsaro_wdcap_derive_output_name(corsaro_wdcap_global_t *glob,
        uint32_t timestamp, int threadid, int needformat, int exttype);

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
