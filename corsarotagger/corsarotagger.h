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

#ifndef CORSAROTRACE_H_
#define CORSAROTRACE_H_

#include <stdlib.h>
#include <libtrace.h>
#include <libtrace_parallel.h>

#include "libcorsaro.h"
#include "libcorsaro_log.h"
#include "libcorsaro_filtering.h"
#include "libcorsaro_tagging.h"
#include "libcorsaro_memhandler.h"

#define TAGGER_PUB_QUEUE "inproc://taggerproxypub"
#define PACKET_PUB_QUEUE "inproc://taggerinternalpub"
#define TAGGER_SUB_QUEUE "inproc://taggerinternalsub"
#define TAGGER_CONTROL_SOCKET "inproc://taggercontrolsock"

#define TAGGER_BUFFER_SIZE (1 * 1024 * 1024)


typedef struct corsaro_tagger_local corsaro_tagger_local_t;
typedef struct corsaro_packet_local corsaro_packet_local_t;

/** Global flag that indicates if the tagger has received a halting
 *  signal, i.e. SIGTERM or SIGINT */
extern volatile int corsaro_halted;

/** Structure for storing global state for a corsarotagger instance */
typedef struct corsaro_tagger_glob {

    /** The logger instance to use when logging error messages */
    corsaro_logger_t *logger;

    /* The name of the file to use for logging (if logging to a file */
    char *logfilename;

    /** An array of URI strings to read packets from */
    char **inputuris;

    /** A constant ERF framing size for incoming packets -- used to speed
     *  up packet processing for nDAG inputs in cases where the user is
     *  able to guarantee a consistent packet "type" will be captured.
     */
    int consterfframing;

    /** A string describing a BPF filter to apply to all received packets */
    char *filterstring;

    /** The name of the zeromq socket to publish tagged packets to */
    char *pubqueuename;

    int sample_rate;

    /** The index of the input URI that we are currently reading from */
    int currenturi;

    /** The total number of valid entries in the inputuris array */
    int totaluris;

    /** The number of entries that can be stored in the inputuris array */
    int alloceduris;

    /** A libtrace input handle for the current input source */
    libtrace_t *trace;

    /** A libtrace filter handle for the active BPF filter */
    libtrace_filter_t *filter;

    /** A boolean flag describing whether promiscuous mode should be enabled
     *  on the input sources */
    uint8_t promisc;

    /** The logging method to be used by corsarotagger */
    uint8_t logmode;

    /** The number of packet processing threads to use */
    uint8_t pkt_threads;

    /** The number of tagging threads to use */
    uint8_t tag_threads;

    /** The configuration options for the libipmeta prefix to ASN module */
    pfx2asn_opts_t pfxtagopts;
    /** The configuration options for the libipmeta Maxmind geolocation
     *  module */
    maxmind_opts_t maxtagopts;
    /** The configuration options for the libipmeta Netacq-edge geolocation
     *  module */
    netacq_opts_t netacqtagopts;

    corsaro_ipmeta_state_t *ipmeta_state;
    uint32_t ipmeta_version;

    /** A libtrace hasher function that can be used to distribute received
     *  packets to processing threads.
     */
    fn_hasher hasher;

    /** Custom data for the libtrace hasher function */
    void *hasher_data;

    /** Boolean flag that is set to true if the input sources require the
     *  use of a libtrace hasher.
     */
    uint8_t hasher_required;

    /** The zeromq context used to create zeromq sockets */
    void *zmq_ctxt;

    /** URI to use when creating the zeromq control socket */
    char *control_uri;

    /** A zeromq socket for managing new subscribers */
    void *zmq_control;

    /** Number of unique labels to use when streaming tagged packets */
    uint8_t output_hashbins;

    /** ID of the IP meta reloading thread */
    pthread_t ipmeta_reloader;

    /** URI to use when creating the IP meta reloading socket */
    char *ipmeta_queue_uri;

    /** A zeromq socket for communicating with the IP meta reloading thread */
    void *zmq_ipmeta;

    /** An array of thread-local state data, one entry for each processing
     *  thread.
     */
    corsaro_tagger_local_t *threaddata;
    corsaro_packet_local_t *packetdata;

} corsaro_tagger_global_t;

typedef struct corsaro_tagger_buffer {
    uint8_t *space;

    uint32_t size;

    uint32_t used;
} corsaro_tagger_buffer_t;

typedef struct corsaro_tagger_packet {
    uint8_t taggedby;
    size_t pqueue_pos;
    corsaro_tagged_packet_header_t hdr;     /* Always have this LAST! */
} PACKED corsaro_tagger_packet_t;

enum {
    CORSARO_TAGGER_MSG_TOTAG,
    CORSARO_TAGGER_MSG_IPMETA
};

typedef struct corsaro_tagger_internal_msg {
    uint8_t type;
    union {
        corsaro_tagger_buffer_t *buf;
        corsaro_ipmeta_state_t *replace;
    } content;
} PACKED corsaro_tagger_internal_msg_t;

typedef struct tagger_proxy_data {
    char *insockname;
    char *outsockname;
    int recvtype;
    int pushtype;

    corsaro_tagger_global_t *glob;
} corsaro_tagger_proxy_data_t;

/** Structure for storing thread-local state for a single processing thread */
struct corsaro_tagger_local {

    pthread_t ptid;

    int threadid;

    corsaro_tagger_global_t *glob;

    /** A corsaro tagger instance */
    corsaro_packet_tagger_t *tagger;

    void *controlsock;

    /** A zeromq socket to publish tagged packets onto */
    void *pubsock;

    /** A zeromq socket to pull untagged packets from */
    void *pullsock;

    /** A boolean flag indicating whether this thread has halted */
    uint8_t stopped;

    /** Number of errors that have occurred during the lifetime of this
     *  thread.
     */
    uint64_t errorcount;
};


struct corsaro_packet_local {

    /** A boolean flag indicating whether this thread has halted */
    uint8_t stopped;

    /** Cumulative number of packets missed by this thread */
    uint64_t lastmisscount;
    /** Cumulative number of packets that have been accepted by this thread */
    uint64_t lastaccepted;

    /** A zeromq socket to publish tagged packets onto */
    void *pubsock;
    corsaro_tagger_buffer_t *buf;
    uint16_t tickcounter;
};

/** Initialises the global state for a corsarotagger instance, based on
 *  the YAML configuration found in the given config file.
 *
 *  @param filename         The path to the configuration file.
 *  @param logmode          The logging method to use (can be one of
 *                          GLOBAL_LOGMODE_STDERR, GLOBAL_LOGMODE_FILE,
 *                          GLOBAL_LOGMODE_SYSLOG or GLOBAL_LOGMODE_NONE.
 *  @return A pointer to an initialised global state structure, or NULL if
 *          a fatal error occurred.
 */
corsaro_tagger_global_t *corsaro_tagger_init_global(char *filename,
        int logmode);

/** Destroys the global state for a corsarotagger instance.
 *
 *  @param glob             The global state to destroy.
 */
void corsaro_tagger_free_global(corsaro_tagger_global_t *glob);

/** Initialises thread-local state for a packet processing thread.
 *
 *  @param tls          The thread local state for this thread
 *  @param threadid     The id number of the thread
 *  @param glob         The global state for the corsaro tagger
 */
void init_packet_thread_data(corsaro_packet_local_t *tls,
        int threadid, corsaro_tagger_global_t *glob);

/** Destroys the thread local state for a packet processing thread.
 *
 *  @param glob         The global state for this corsarotagger instance
 *  @param tls          The thread-local state to be destroyed
 *  @param threadid     The identifier for the thread that owned this state
 */
void destroy_local_packet_state(corsaro_tagger_global_t *glob,
        corsaro_packet_local_t *tls, int threadid);

/** Create a tagged packet message and publishes it to the tagger proxy
 *  queue.
 *
 *  @param glob         The global state for this corsarotagger instance.
 *  @param tls          The thread-local state for this processing thread.
 *  @param packet       The packet to be published.
 */
int corsaro_publish_tags(corsaro_tagger_global_t *glob,
        corsaro_packet_local_t *tls, libtrace_packet_t *packet);

/** Initialises the local data for a tagging thread.
 *
 *  @param tls          The thread-local data to be initialised
 *  @param threadid     A numeric identifier for the thread that this data
 *                      is going to be attached to
 *  @param glob         The global data for this corsarotagger instance.
 *
 */
void init_tagger_thread_data(corsaro_tagger_local_t *tls,
        int threadid, corsaro_tagger_global_t *glob);

/** Destroys the thread local state for a tagging thread.
 *
 *  @param glob         The global state for this corsarotagger instance
 *  @param tls          The thread-local state to be destroyed
 *  @param threadid     The identifier for the thread that owned this state
 */
void destroy_local_tagger_state(corsaro_tagger_global_t *glob,
        corsaro_tagger_local_t *tls, int threadid);

/** Starts a tagger worker thread.
 *
 *  @param data     The thread-local state variable for this tagger thread,
 *                  must be already initialised.
 *  @return NULL when the thread exits
 */
void *start_tagger_thread(void *data);

/** Main loop for the proxy thread that publishes tagged packets produced
 *  by the tagging threads.
 *
 *  @param data         The tagger proxy state for this proxy thread.
 *  @return NULL when the proxy thread has halted.
 */
void *start_zmq_output_thread(void *data);

/** Starts the thread which manages the proxy that bridges our zeromq
 *  publishing sockets to the clients that are subscribing to them.
 *
 *  The reason for the proxy is to support our multiple-publisher,
 *  multiple-subscriber architecture without either side having to
 *  know how many sockets exist on the other side of the proxy.
 *
 *  @param data         The tagger proxy state for this proxy thread.
 *  @return NULL when the proxy thread has halted.
 */
void *start_zmq_proxy_thread(void *data);

/** Allocates and initialises a new corsaro tagger buffer structure.
 */
static inline corsaro_tagger_buffer_t *create_tls_buffer() {

    corsaro_tagger_buffer_t *buf;

    buf = calloc(1, sizeof(corsaro_tagger_buffer_t));
    buf->space = malloc(TAGGER_BUFFER_SIZE * sizeof(uint8_t));
    buf->used = 0;
    buf->size = TAGGER_BUFFER_SIZE;

    return buf;
}

/** Deallocates a corsaro tagger buffer structure.
 *
 *  @param buf      The buffer to be deallocated
 */
static inline void free_tls_buffer(corsaro_tagger_buffer_t *buf) {
    free(buf->space);
    free(buf);
}

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
