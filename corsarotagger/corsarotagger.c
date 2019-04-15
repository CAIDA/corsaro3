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
#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <libtrace.h>
#include <libtrace_parallel.h>
#include <zmq.h>

#include "libcorsaro_log.h"
#include "libcorsaro_tagging.h"
#include "corsarotagger.h"
#include "libcorsaro_filtering.h"
#include "libcorsaro_memhandler.h"
#include "pqueue.h"

/* Some notes of the structure of the corsarotagger...
 *
 * The tagger's role is relatively simple: read packets from a packet
 * source (probably an ndag multicaster socket) and attach to each packet
 * a set of "tags" that are useful for filtering or analytic purposes.
 *
 * This seems simple, but is actually a lot more complex in practice.
 *
 * There are quite a few different classes of threads that run concurrently
 * to make this all work optimally:
 *   - packet processing threads
 *   - tagger worker threads
 *   - the internal proxy thread
 *   - the external proxy thread
 *   - the IPmeta reloading thread
 *   - the main thread
 *
 * Packet processing threads are typical parallel-libtrace style threads.
 * These receive packets from the input source, attach a blank set of tags
 * to each packet, buffer them together (to save on writes), then push
 * them on towards the tagger worker threads. The reason that we do not
 * do the tagging in these threads is because we want to minimise the amount
 * of time spent holding on to a packet -- the sooner our "per_packet"
 * function finishes, the less likely we are to drop packets during high load.
 *
 * Tagger worker threads do the actual tagging of each packet. This includes
 * both the "basic" tagging (i.e. port numbers, protocols) as well as
 * computing the flowtuple hash. Packets are also assigned to a hash bin
 * (represented by a single character) that allows clients to subscribe to
 * different portions of our output using different threads to parallelise
 * their own workload easily. The hash bin is based on the flowtuple hash to
 * ensure all packets for the same flow end up in the same hash bin.
 *
 * Advanced tagging can also occur via the libipmeta library, provided
 * suitable source data files are available. These can be used for
 * geo-location and prefix-to-ASN mapping of the packet's source IP address.
 *
 * The internal proxy thread is used to move packets between the packet
 * processing and tagger worker threads. This is required to make the
 * multiple-publisher, multiple-consumer model that we are using work
 * smoothly. Since the tagging process itself is relatively state-less on
 * a per-packet basis, it doesn't matter which worker thread each packet is
 * assigned to.
 *
 * The external proxy thread is used to publish the tagged packets produced
 * by the worker threads onto a single queue for consumption by any number
 * of interested subscribers.
 *
 * The IPmeta reloading thread has a single purpose: wait for a message
 * from the main thread telling it that a SIGHUP has been observed and once
 * received, reload the libipmeta source files and push the new IPmeta data
 * to each of the tagging threads.
 *
 * The main thread listens for signals (like the aforementioned SIGHUP) and
 * acts upon them (i.e. trigger a reload or begin a clean halt of the tagger).
 * It also waits for query messages from clients to which it will reply with
 * any useful configuration that the client may want to know (such as the
 * number of hash bins being used by the tagger threads).
 */


/** Older versions of libzmq use a different name for this option */
#ifndef ZMQ_IMMEDIATE
#define ZMQ_IMMEDIATE ZMQ_DELAY_ATTACH_ON_CONNECT
#endif

/** Name of the zeromq socket that tagged packets will be written to.
 *  This is an internal socket, read by a proxy thread which will act
 *  as a broker between the tagger and its clients. */
#define TAGGER_PUB_QUEUE "inproc://taggerproxypub"
#define PACKET_PUB_QUEUE "inproc://taggerinternalpub"
#define TAGGER_SUB_QUEUE "inproc://taggerinternalsub"
#define TAGGER_CONTROL_SOCKET "inproc://taggercontrolsock"

#define TAGGER_BUFFER_SIZE (1 * 1024 * 1024)

#define ASSIGN_HASH_BIN(hash_val, hash_bins, result) { \
    int hmod; \
    hmod = hash_val % hash_bins; \
    if (hmod < 26) {result = 'A' + hmod;} \
    else {result = 'a' + (hmod - 26); } \
}


typedef struct tagger_proxy_data {
    char *insockname;
    char *outsockname;
    int recvtype;
    int pushtype;

    corsaro_tagger_global_t *glob;
} corsaro_tagger_proxy_data_t;

libtrace_callback_set_t *processing = NULL;

/** Global flag that indicates if the tagger has received a halting
 *  signal, i.e. SIGTERM or SIGINT */
volatile int corsaro_halted = 0;

/** Global flag that indicates whether the tagger should stop reading
 *  packets from the input source */
volatile int trace_halted = 0;

/** Global flag that indicates whether the tagger should attempt to reload
 *  the IP meta data files as soon as it can */
volatile int ipmeta_reload = 0;


/** Signal handler for SIGINT and SIGTERM */
static void cleanup_signal(int sig) {
    (void)sig;
    corsaro_halted = 1;
    trace_halted = 1;
}

/** Signal handler for SIGHUP */
static void reload_signal(int sig) {
    (void)sig;
    ipmeta_reload = 1;
}

#define ENQUEUE_BUFFER(tls) \
    if (tls->buf) { \
        corsaro_tagger_internal_msg_t msg; \
        msg.type = CORSARO_TAGGER_MSG_TOTAG; \
        msg.content.buf = tls->buf; \
        zmq_send(tls->pubsock, &msg, sizeof(msg), 0); \
    }

/** Get Position function for a tagged packet priority queue */
static size_t pkt_get_pos(void *a) {
    corsaro_tagger_packet_t *pkt = (corsaro_tagger_packet_t *)a;
    return pkt->pqueue_pos;
}

/** Set Position function for a tagged packet priority queue */
static void pkt_set_pos(void *a, size_t pos) {
    corsaro_tagger_packet_t *pkt = (corsaro_tagger_packet_t *)a;
    pkt->pqueue_pos = pos;
}


/** Comparison function for two tagged packets.
 *
 *  @param next     A tagged packet being added to a priority queue
 *  @param curr     A tagged packet already in the priority queue
 *  @return 1 if curr has a high priority than next, 0 if next should
 *          be exported ahead of curr.
 */
static int pkt_cmp_pri(void *next, void *curr) {
    corsaro_tagger_packet_t *nextpkt = (corsaro_tagger_packet_t *)next;
    corsaro_tagger_packet_t *currpkt = (corsaro_tagger_packet_t *)curr;

    if (nextpkt->hdr.ts_sec > currpkt->hdr.ts_sec) {
        return 1;
    }

    if (nextpkt->hdr.ts_sec < currpkt->hdr.ts_sec) {
        return 0;
    }

    if (nextpkt->hdr.ts_usec < currpkt->hdr.ts_usec) {
        return 0;
    }

    return 1;
}


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


/** Initialises thread-local state for a packet processing thread.
 *
 *  @param tls          The thread local state for this thread
 *  @param threadid     The id number of the thread
 *  @param glob         The global state for the corsaro tagger
 */
static inline void init_packet_thread_data(corsaro_packet_local_t *tls,
        int threadid, corsaro_tagger_global_t *glob) {

    int hwm = 0;
    int one = 1;
    tls->stopped = 0;
    tls->lastmisscount = 0;
    tls->lastaccepted = 0;
    tls->tickcounter = 0;

    tls->buf = create_tls_buffer();

    /* create zmq socket for publishing */
    tls->pubsock = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
    if (zmq_setsockopt(tls->pubsock, ZMQ_SNDHWM, &hwm, sizeof(hwm)) != 0) {
        corsaro_log(glob->logger,
                "error while setting HWM for zeromq publisher socket in tagger thread %d:%s",
                threadid, strerror(errno));
        tls->stopped = 1;
    }

    /* Don't queue messages for incomplete connections */
    if (zmq_setsockopt(tls->pubsock, ZMQ_IMMEDIATE, &one, sizeof(one)) != 0) {
        corsaro_log(glob->logger,
                "error while setting immediate for zeromq publisher socket in tagger thread %d:%s",
                threadid, strerror(errno));
        tls->stopped = 1;
    }

    if (zmq_connect(tls->pubsock, PACKET_PUB_QUEUE) != 0) {
        corsaro_log(glob->logger,
                "error while connecting zeromq publisher socket in tagger thread %d:%s",
                threadid, strerror(errno));
        tls->stopped = 1;
    }
}

/** Initialises the local data for a tagging thread.
 *
 *  @param tls          The thread-local data to be initialised
 *  @param threadid     A numeric identifier for the thread that this data
 *                      is going to be attached to
 *  @param glob         The global data for this corsarotagger instance.
 *
 */
static inline void init_tagger_thread_data(corsaro_tagger_local_t *tls,
        int threadid, corsaro_tagger_global_t *glob) {
    int hwm = 0;
    int one = 1;
    char sockname[1024];

    tls->ptid = 0;
    tls->glob = glob;
    tls->stopped = 0;
    tls->tagger = corsaro_create_packet_tagger(glob->logger,
            glob->ipmeta_state);
    tls->errorcount = 0;
    tls->threadid = threadid;

    if (tls->tagger == NULL) {
        corsaro_log(glob->logger,
                "out of memory while creating packet tagger.");
        tls->stopped = 1;
        return;
    }

    /* create zmq socket for publishing */
    tls->pubsock = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
    if (zmq_setsockopt(tls->pubsock, ZMQ_SNDHWM, &hwm, sizeof(hwm)) != 0) {
        corsaro_log(glob->logger,
                "error while setting HWM for zeromq publisher socket in tagger thread %d:%s",
                threadid, strerror(errno));
        tls->stopped = 1;
    }

    /* Don't queue messages for incomplete connections */
    if (zmq_setsockopt(tls->pubsock, ZMQ_IMMEDIATE, &one, sizeof(one)) != 0) {
        corsaro_log(glob->logger,
                "error while setting immediate for zeromq publisher socket in tagger thread %d:%s",
                threadid, strerror(errno));
        tls->stopped = 1;
    }

    snprintf(sockname, 1024, "%s-%d", TAGGER_PUB_QUEUE, threadid);
    if (zmq_bind(tls->pubsock, sockname) != 0) {
        corsaro_log(glob->logger,
                "error while connecting zeromq publisher socket in tagger thread %d:%s",
                threadid, strerror(errno));
        tls->stopped = 1;
    }

    tls->pullsock = zmq_socket(glob->zmq_ctxt, ZMQ_PULL);
    if (zmq_connect(tls->pullsock, TAGGER_SUB_QUEUE) != 0) {
        corsaro_log(glob->logger,
                "error while binding zeromq publisher socket in tagger thread %d:%s",
                threadid, strerror(errno));
        tls->stopped = 1;
    }

    tls->controlsock = zmq_socket(glob->zmq_ctxt, ZMQ_PAIR);
    snprintf(sockname, 1024, "%s-%d", TAGGER_CONTROL_SOCKET, threadid);
    if (zmq_connect(tls->controlsock, sockname) != 0) {
        corsaro_log(glob->logger,
                "error while connecting zeromq control socket in tagger thread %d:%s",
                threadid, strerror(errno));
        tls->stopped = 1;
    }

}

/** Initialisation callback for a libtrace processing thread
 *
 *  @param trace        The libtrace input that this thread belongs to (unused)
 *  @param t            The libtrace processing thread
 *  @param global       The global state for this corsarotagger instance
 *
 *  @return The initialised thread-local state for this thread.
 */
static void *init_trace_processing(libtrace_t *trace, libtrace_thread_t *t,
        void *global) {
    corsaro_tagger_global_t *glob = (corsaro_tagger_global_t *)global;
    corsaro_packet_local_t *tls;

    /* The thread-local data has already been initialised, we just need
     * to pick our particular entry out of the array of TLS stored in
     * the global state.
     */
    tls = &(glob->packetdata[trace_get_perpkt_thread_id(t)]);

    return tls;
}


/** Destructor callback for a libtrace processing thread
 *
 *  @param trace        The libtrace input that this thread belongs to (unused)
 *  @param t            The libtrace processing thread
 *  @param global       The global state for this corsarotagger instance
 *  @param local        The thread-local state for this thread.
 */
static void halt_trace_processing(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *local) {

    corsaro_tagger_global_t *glob = (corsaro_tagger_global_t *)global;
    corsaro_packet_local_t *tls = (corsaro_packet_local_t *)local;

    if (tls->buf->used > 0) {
        ENQUEUE_BUFFER(tls);
    }
    zmq_send(tls->pubsock, NULL, 0, 0);
}

/** Destroys the thread local state for a tagging thread.
 *
 *  @param glob         The global state for this corsarotagger instance
 *  @param tls          The thread-local state to be destroyed
 *  @param threadid     The identifier for the thread that owned this state
 */
static void destroy_local_tagger_state(corsaro_tagger_global_t *glob,
        corsaro_tagger_local_t *tls, int threadid) {
    int linger = 1000;

    if (tls->tagger) {
        corsaro_destroy_packet_tagger(tls->tagger);
    }

    if (tls->controlsock) {
        zmq_setsockopt(tls->controlsock, ZMQ_LINGER, &linger, sizeof(linger));
        zmq_close(tls->controlsock);
    }

    if (tls->pubsock) {
        zmq_setsockopt(tls->pubsock, ZMQ_LINGER, &linger, sizeof(linger));
        zmq_close(tls->pubsock);
    }

    if (tls->pullsock) {
        zmq_setsockopt(tls->pullsock, ZMQ_LINGER, &linger, sizeof(linger));
        zmq_close(tls->pullsock);
    }

}

/** Destroys the thread local state for a packet processing thread.
 *
 *  @param glob         The global state for this corsarotagger instance
 *  @param tls          The thread-local state to be destroyed
 *  @param threadid     The identifier for the thread that owned this state
 */
static void destroy_local_packet_state(corsaro_tagger_global_t *glob,
        corsaro_packet_local_t *tls, int threadid) {
    int linger = 1000;

    if (tls->pubsock) {
        zmq_setsockopt(tls->pubsock, ZMQ_LINGER, &linger, sizeof(linger));
    }
    zmq_close(tls->pubsock);

    if (tls->buf) {
        free_tls_buffer(tls->buf);
    }

}

/** Create a tagged packet message and publishes it to the tagger proxy
 *  queue.
 *
 *  @param glob         The global state for this corsarotagger instance.
 *  @param tls          The thread-local state for this processing thread.
 *  @param packet       The packet to be published.
 */
static int corsaro_publish_tags(corsaro_tagger_global_t *glob,
        corsaro_packet_local_t *tls, libtrace_packet_t *packet) {

    struct timeval tv;
    void *pktcontents;
    uint32_t rem;
    libtrace_linktype_t linktype;
    corsaro_tagger_packet_t *tpkt;
    size_t bufsize;

    pktcontents = trace_get_layer2(packet, &linktype, &rem);
    if (rem == 0 || pktcontents == NULL) {
        return 0;
    }

    if (linktype != TRACE_TYPE_ETH) {
        return 0;
    }
    tv = trace_get_timeval(packet);

    bufsize = sizeof(corsaro_tagger_packet_t) + rem;

    assert(tls->buf->used <= tls->buf->size);
    if (tls->buf->size - tls->buf->used < bufsize) {
        ENQUEUE_BUFFER(tls);
        tls->buf = create_tls_buffer();
        if (tls->buf == NULL) {
            corsaro_log(glob->logger, "OOM while tagging packets");
            return -1;
        }
    }

    tpkt = (corsaro_tagger_packet_t *)
            (tls->buf->space + tls->buf->used);

    tpkt->taggedby = 255;
    tpkt->pqueue_pos = 0;
    tpkt->hdr.filterbits = 0;
    tpkt->hdr.ts_sec = tv.tv_sec;
    tpkt->hdr.ts_usec = tv.tv_usec;
    tpkt->hdr.pktlen = rem;
    memset(&(tpkt->hdr.tags), 0, sizeof(corsaro_packet_tags_t));

    tls->buf->used += sizeof(corsaro_tagger_packet_t);
    /* Put the packet itself in the buffer (minus the capture and
     * meta-data headers -- we don't need them).
     */
    memcpy(tls->buf->space + tls->buf->used, pktcontents, rem);
    tls->buf->used += rem;

    return 0;
}

/** Per-packet processing callback for a libtrace processing thread.
 *
 *  This function simply tags, then forwards each received packet.
 *
 *  @param trace        The libtrace input that the packet has been read from.
 *  @param t            The libtrace processing thread.
 *  @param global       The global state for this corsarotagger instance.
 *  @param local        The thread-local state for this processing thread.
 *  @param packet       The packet is to be processed.
 *
 *  @return the packet so it can be released back to the capture device.
 */
static libtrace_packet_t *per_packet(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *local, libtrace_packet_t *packet) {

    corsaro_tagger_global_t *glob = (corsaro_tagger_global_t *)global;
    corsaro_packet_local_t *tls = (corsaro_packet_local_t *)local;

    if (tls->stopped) {
        return packet;
    }

    if (tls->buf == NULL) {
        tls->buf = create_tls_buffer();
    }
    if (tls->buf == NULL) {
        corsaro_log(glob->logger, "OOM while tagging packets");
        tls->stopped = 1;
        return packet;
    }

    if (corsaro_publish_tags(glob, tls, packet) != 0) {
        corsaro_log(glob->logger, "error while attempting to publish a packet");
        tls->stopped = 1;
    }
    return packet;
}

/* Tick callback for a libtrace processing thread.
 *
 * The ticks are used simply to keep track of whether we are dropping
 * packets or not.
 *
 *  @param trace        The libtrace input that is reading packets.
 *  @param t            The libtrace processing thread.
 *  @param global       The global state for this corsarotagger instance.
 *  @param local        The thread-local state for this processing thread.
 *  @param tick         The timestamp of the current tick.
 */
static void process_tick(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *local, uint64_t tick) {

    corsaro_tagger_global_t *glob = (corsaro_tagger_global_t *)global;
    corsaro_packet_local_t *tls = (corsaro_packet_local_t *)local;
    libtrace_stat_t *stats;

    tls->tickcounter ++;
    if (tls->tickcounter == 120) {
        stats = trace_create_statistics();
        trace_get_thread_statistics(trace, t, stats);

        if (stats->missing > tls->lastmisscount) {
            corsaro_log(glob->logger,
                    "thread %d dropped %lu packets in last minute (accepted %lu)",
                    trace_get_perpkt_thread_id(t),
                    stats->missing - tls->lastmisscount,
                    stats->accepted - tls->lastaccepted);
            tls->lastmisscount = stats->missing;
        }
        tls->lastaccepted = stats->accepted;

        free(stats);
        tls->tickcounter = 0;
    }

    if (tls->buf->used > 0) {
	    ENQUEUE_BUFFER(tls);
        tls->buf = create_tls_buffer();
    }
}

/** Receives and processes a buffer of untagged packets for a tagger thread,
 *  tagging each packet contained within that buffer appropriately and
 *  publishing it to the external proxy thread.
 *
 *  @param tls      The thread-local state for this tagging thread.
 *  @return 1 if the buffer was received and processed successfully, -1
 *          if an error occurs, 0 if there is an EOF on receive.
 */
static int tagger_thread_process_buffer(corsaro_tagger_local_t *tls) {
    uint8_t recvbuf[TAGGER_BUFFER_SIZE];
    int r;
    uint32_t processed;
    corsaro_tagger_buffer_t *buf = NULL;
    corsaro_tagger_internal_msg_t *recvd = NULL;

    assert(tls->buf == NULL);
    memset(recvbuf, 0, TAGGER_BUFFER_SIZE);
    r = zmq_recv(tls->pullsock, recvbuf, TAGGER_BUFFER_SIZE, 0);
    if (r < 0) {
        corsaro_log(tls->glob->logger,
                "error while receiving from pull socket in tagger thread %d: %s",
                tls->threadid, strerror(errno));
        return -1;
    }

    if (r == 0) {
        return 0;
    }

    assert(r == sizeof(corsaro_tagger_internal_msg_t));
    recvd = (corsaro_tagger_internal_msg_t *)recvbuf;
    buf = recvd->content.buf;
    processed = 0;

    /* The buffer probably contains multiple untagged packets, so keep
     * looping until we've tagged them all */
    while (processed < buf->used) {
        corsaro_tagger_packet_t *packet;
        libtrace_ip_t *ip;
        void *l2, *next;
        uint32_t rem;
        uint16_t ethertype;

        packet = (corsaro_tagger_packet_t *)(buf->space + processed);

        if (buf->used - processed < sizeof(corsaro_tagger_packet_t)) {
            corsaro_log(tls->glob->logger,
                    "error: not enough buffer content for a complete header...");
            exit(2);
        }

        processed += sizeof(corsaro_tagger_packet_t);
        if (buf->used - processed < packet->hdr.pktlen) {
            corsaro_log(tls->glob->logger,
                    "error: missing packet contents in tagger thread...");
            exit(2);
        }

        /* Find the IP header in the packet contents.
         * The packet should start with an Ethernet header */
        l2 = buf->space + processed;
        rem = packet->hdr.pktlen;

        next = trace_get_payload_from_layer2(l2, TRACE_TYPE_ETH,
                &ethertype, &rem);
        while (next != NULL && rem > 0) {
            switch(ethertype) {
                case TRACE_ETHERTYPE_8021Q:
                    next = trace_get_payload_from_vlan(next, &ethertype, &rem);
                    continue;
                case TRACE_ETHERTYPE_MPLS:
                    next = trace_get_payload_from_mpls(next, &ethertype, &rem);
                    continue;
                case TRACE_ETHERTYPE_PPP_SES:
                    next = trace_get_payload_from_pppoe(next, &ethertype, &rem);
                    continue;
                default:
                    break;
            }
            break;
        }

        if (rem == 0) {
            next = NULL;
        }

        ip = (libtrace_ip_t *)next;

        /* Actually do the tagging */
        if (corsaro_tag_ippayload(tls->tagger, &(packet->hdr.tags),
                    ip, rem) < 0) {
            corsaro_log(tls->glob->logger,
                    "error while tagging IP payload in tagger thread.");
            tls->errorcount ++;
        }

        /* Using the results of the flowtuple hash tag, assign this packet
         * to one of our output hash bins, so clients will be able to
         * receive the tagged packets in parallel if they desire.
         */
        ASSIGN_HASH_BIN(packet->hdr.tags.ft_hash,
                tls->glob->output_hashbins, packet->hdr.hashbin);
        packet->hdr.filterbits = htons(packet->hdr.tags.highlevelfilterbits);
        packet->taggedby = tls->threadid;
        processed += packet->hdr.pktlen;

        /* Send the packet on to the external proxy for publishing. Don't
         * block -- if the proxy closes its pull socket (i.e. during
         * pre-exit cleanup), we can end up blocking forever.
         */
        while (!corsaro_halted) {
            r = zmq_send(tls->pubsock, packet, sizeof(corsaro_tagger_packet_t)
                    + packet->hdr.pktlen, ZMQ_DONTWAIT);
            if (r < 0) {
                if (errno == EAGAIN) {
                    usleep(10);
                    continue;
                }
                corsaro_log(tls->glob->logger,
                        "error publishing packet from tagger thread %d: %s",
                        tls->threadid, strerror(errno));
                return -1;
            }
            break;
        }

    }
    free_tls_buffer(buf);
    return 1;
}

/** Main loop for a tagger thread. */
static void *start_tagger_thread(void *data) {
    corsaro_tagger_local_t *tls = (corsaro_tagger_local_t *)data;
    zmq_pollitem_t items[2];

    /* We have two sockets that we care about -- the pull socket, which
     * we receive untagged packets from, and the control socket, which
     * we receive updated IPmeta state on.
     */

    while (!corsaro_halted) {
        corsaro_tagger_internal_msg_t *recvd = NULL;
        corsaro_tagger_buffer_t *buf = NULL;

        items[0].socket = tls->pullsock;
        items[0].events = ZMQ_POLLIN;
        items[1].socket = tls->controlsock;
        items[1].events = ZMQ_POLLIN;

        if (zmq_poll(items, 2, 100) < 0) {
            corsaro_log(tls->glob->logger,
                    "error while polling in tagger thread %d: %s",
                    tls->threadid, strerror(errno));
            break;
        }

        if (items[1].revents & ZMQ_POLLIN) {
            /* New IPmeta state, replace what we've got */
            char recvbuf[12];
            corsaro_ipmeta_state_t **replace;

            if (zmq_recv(tls->controlsock, recvbuf, 12, 0) < 0) {
                corsaro_log(tls->glob->logger,
                        "error while receiving new IPmeta state in tagger thread %d: %s",
                        tls->threadid, strerror(errno));
                break;
            }

            replace = (corsaro_ipmeta_state_t **)recvbuf;
            corsaro_replace_tagger_ipmeta(tls->tagger, *replace);
        }

        if (items[0].revents & ZMQ_POLLIN) {
            /* Got some untagged packets to process */
            if (tagger_thread_process_buffer(tls) <= 0) {
                break;
            }
        }
    }

    pthread_exit(NULL);
}

/** Main loop for the proxy thread that links our packet processing
 *  threads with our tagging worker threads.
 *
 *  @param proxy_recv       A zeromq socket for receiving from the packet
 *                          processing threads.
 *  @param proxy_fwd        A zeromq socket for sending to the tagger threads.
 */
static inline void run_simple_proxy(void *proxy_recv, void *proxy_fwd) {
    int tosend = 0;
    uint8_t recvbuf[TAGGER_BUFFER_SIZE];

    while (!corsaro_halted) {
        int r;

        if (tosend == 0) {
            /* Try read a tagged packet buffer from one of our packet threads */
            if ((r = zmq_recv(proxy_recv, recvbuf, TAGGER_BUFFER_SIZE, 0)) < 0)             {
                if (errno == EAGAIN) {
                    /* Nothing available for now, check if we need to halt
                     * then try again.
                     */
                    continue;
                }
                break;
            }

            tosend = r;
            if (corsaro_halted) {
                break;
            }
            assert(r == sizeof(corsaro_tagger_internal_msg_t));
        }

        /* Got something, publish it to our workers */
        r = zmq_send(proxy_fwd, recvbuf, tosend, ZMQ_DONTWAIT);

        if (r < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            break;
        }
        tosend = 0;
    }
}

/** Main loop for the proxy thread that publishes tagged packets produced
 *  by the tagging threads.
 *
 */
static void *start_zmq_output_thread(void *data) {
    corsaro_tagger_proxy_data_t *proxy = (corsaro_tagger_proxy_data_t *)data;
    corsaro_tagger_global_t *glob = proxy->glob;
    corsaro_tagger_packet_t *packet;

    pqueue_t *pq;
    int i, r, zero = 0;
    int onesec = 1000;

    void **proxy_recv = calloc(glob->tag_threads, sizeof(void *));
    void *proxy_fwd = zmq_socket(glob->zmq_ctxt, proxy->pushtype);

    uint8_t **recvbufs = calloc(glob->tag_threads, sizeof(uint8_t *));
    uint32_t *recvbufsizes = calloc(glob->tag_threads, sizeof(uint32_t));

    /** Our output needs to be in chronological order, so we'll use a
     *  priority queue to make sure we're publishing the oldest packet
     *  available.
     */
    pq = pqueue_init(glob->tag_threads, pkt_cmp_pri, pkt_get_pos, pkt_set_pos);

    if (zmq_setsockopt(proxy_fwd, ZMQ_LINGER, &zero, sizeof(zero)) < 0) {
        corsaro_log(glob->logger,
                "unable to configure tagger output forwarding socket %s: %s",
                proxy->outsockname, strerror(errno));
        goto proxyexit;
    }

    /* Allow the forwarding socket to buffer as many messages as it
     * wants -- NOTE: this means you will run out of memory if you
     * have a slow client!
     */
    if (zmq_setsockopt(proxy_fwd, ZMQ_SNDHWM, &zero, sizeof(zero)) != 0) {
        corsaro_log(glob->logger,
                "error while setting HWM for output forwarding socket %s: %s",
                proxy->outsockname, strerror(errno));
        goto proxyexit;
    }

    if (zmq_bind(proxy_fwd, proxy->outsockname) < 0) {
        corsaro_log(glob->logger,
                "unable to create tagger output forwarding socket %s: %s",
                proxy->outsockname, strerror(errno));
        goto proxyexit;
    }

    /* Set up our receiving sockets from each of the tagger threads and
     * read a packet from each to populate the priority queue.
     */
    for (i = 0; i < glob->tag_threads; i++) {
        char sockname[1024];

        snprintf(sockname, 1024, "%s-%d", proxy->insockname, i);

        recvbufs[i] = malloc(TAGGER_BUFFER_SIZE);

        proxy_recv[i] = zmq_socket(glob->zmq_ctxt, ZMQ_PULL);
        if (zmq_setsockopt(proxy_recv[i], ZMQ_LINGER, &zero, sizeof(zero)) < 0) {
            corsaro_log(glob->logger,
                    "unable to configure tagger output recv socket: %s",
                    strerror(errno));
            goto proxyexit;
        }

        /* Only block for a max of one second when reading published packets */
        if (zmq_setsockopt(proxy_recv[i], ZMQ_RCVTIMEO, &onesec, sizeof(onesec)) < 0) {
            corsaro_log(glob->logger,
                    "unable to configure tagger output recv socket %s: %s",
                    sockname,strerror(errno));
            goto proxyexit;
        }

        if (zmq_connect(proxy_recv[i], sockname) < 0) {
            corsaro_log(glob->logger,
                    "unable to create tagger output recv socket %s: %s",
                    sockname, strerror(errno));
            goto proxyexit;
        }

        /* Read the first packet produced by each tagger thread */
        while (1) {
            r = zmq_recv(proxy_recv[i], recvbufs[i], TAGGER_BUFFER_SIZE, 0);
            if (r < 0) {
                if (errno == EAGAIN) {
                    continue;
                }
                corsaro_log(glob->logger,
                        "error while reading first packet from tagger thread %d: %s",
                        i, strerror(errno));
                goto proxyexit;
            }

            if (r < sizeof(corsaro_tagger_packet_t)) {
                corsaro_log(glob->logger,
                        "first packet from tagger thread %d is too small?", i);
                goto proxyexit;
            }
            break;
        }
        packet = (corsaro_tagger_packet_t *)recvbufs[i];
        recvbufsizes[i] = r;
        pqueue_insert(pq, recvbufs[i]);
    }

    while (!corsaro_halted) {
        uint8_t *nextpkt;
        uint8_t workind = 0;

        /* Grab the oldest packet from the priority queue */
        nextpkt = (uint8_t *)(pqueue_pop(pq));
        if (nextpkt == NULL) {
            usleep(10);
            continue;
        }
        packet = (corsaro_tagger_packet_t *)nextpkt;
        workind = packet->taggedby;

        zmq_send(proxy_fwd, &(packet->hdr),
                sizeof(packet->hdr) + packet->hdr.pktlen, 0);

        /* Read the next packet from the worker that provided us with
         * the packet we just published.
         */
        while (!corsaro_halted) {
            r = zmq_recv(proxy_recv[workind], recvbufs[workind],
                    TAGGER_BUFFER_SIZE, ZMQ_DONTWAIT);

            if (r < 0) {
                if (errno == EAGAIN) {
                    continue;
                }
                corsaro_log(glob->logger,
                        "error while reading subsequent packet from tagger thread %d: %s",
                        workind, strerror(errno));
                goto proxyexit;
            }

            if (r < sizeof(corsaro_tagger_packet_t)) {
                corsaro_log(glob->logger,
                        "first packet from tagger thread %d is too small?",
                        workind);
                goto proxyexit;
            }
            break;
        }

        recvbufsizes[workind] = r;
        pqueue_insert(pq, recvbufs[workind]);
    }

proxyexit:
    pqueue_free(pq);
    for (i = 0; i < glob->tag_threads; i++) {
        if (proxy_recv[i]) {
            zmq_close(proxy_recv[i]);
        }
        free(recvbufs[i]);
    }
    free(proxy_recv);
    free(recvbufs);
    free(recvbufsizes);
    zmq_close(proxy_fwd);
    pthread_exit(NULL);
}

/** Starts the thread which manages the proxy that bridges our zeromq
 *  publishing sockets to the clients that are subscribing to them.
 *
 *  The reason for the proxy is to support our multiple-publisher,
 *  multiple-subscriber architecture without either side having to
 *  know how many sockets exist on the other side of the proxy.
 *
 *  @param data         The global state for this corsarotagger instance.
 *  @return NULL when the proxy thread has halted.
 */
static void *start_zmq_proxy_thread(void *data) {
    corsaro_tagger_proxy_data_t *proxy = (corsaro_tagger_proxy_data_t *)data;
    corsaro_tagger_global_t *glob = proxy->glob;

    void *proxy_recv = zmq_socket(glob->zmq_ctxt, proxy->recvtype);
    void *proxy_fwd = zmq_socket(glob->zmq_ctxt, proxy->pushtype);
    int zero = 0;
    int onesec = 1000;

    if (zmq_setsockopt(proxy_recv, ZMQ_LINGER, &zero, sizeof(zero)) < 0) {
        corsaro_log(glob->logger,
                "unable to configure tagger proxy recv socket: %s",
                strerror(errno));
        goto proxyexit;
    }

    /* Only block for a max of one second when reading published packets */
    if (zmq_setsockopt(proxy_recv, ZMQ_RCVTIMEO, &onesec, sizeof(onesec)) < 0) {
        corsaro_log(glob->logger,
                "unable to configure tagger proxy recv socket %s: %s",
                proxy->insockname,strerror(errno));
        goto proxyexit;
    }

    if (zmq_bind(proxy_recv, proxy->insockname) < 0) {
        corsaro_log(glob->logger,
                "unable to create tagger proxy recv socket %s: %s",
                proxy->insockname, strerror(errno));
        goto proxyexit;
    }

    if (proxy->recvtype == ZMQ_SUB) {
        /* Subscribe to ALL streams */
        if (zmq_setsockopt(proxy_recv, ZMQ_SUBSCRIBE, "", 0) < 0) {
            corsaro_log(glob->logger,
                    "unable to configure tagger proxy recv socket %s: %s",
                    proxy->insockname, strerror(errno));
            goto proxyexit;
        }
    }

    if (zmq_setsockopt(proxy_fwd, ZMQ_LINGER, &zero, sizeof(zero)) < 0) {
        corsaro_log(glob->logger,
                "unable to configure tagger proxy forwarding socket %s: %s",
                proxy->outsockname, strerror(errno));
        goto proxyexit;
    }

    /* Allow the forwarding socket to buffer as many messages as it
     * wants -- NOTE: this means you will run out of memory if you
     * have a slow client!
     */
    if (zmq_setsockopt(proxy_fwd, ZMQ_SNDHWM, &zero, sizeof(zero)) != 0) {
        corsaro_log(glob->logger,
                "error while setting HWM for proxy forwarding socket %s: %s",
                proxy->outsockname, strerror(errno));
        goto proxyexit;
    }

    if (zmq_bind(proxy_fwd, proxy->outsockname) < 0) {
        corsaro_log(glob->logger,
                "unable to create tagger proxy forwarding socket %s: %s",
                proxy->outsockname, strerror(errno));
        goto proxyexit;
    }

    run_simple_proxy(proxy_recv, proxy_fwd);

proxyexit:
    zmq_close(proxy_recv);
    zmq_close(proxy_fwd);
    pthread_exit(NULL);
}

/** Creates and starts a libtrace input.
 *
 *  @param glob     The global state for this corsarotagger instance.
 *
 *  @return -1 if an error occurs, 0 if successful.
 */
static int start_trace_input(corsaro_tagger_global_t *glob) {

    /* This is all pretty standard parallel libtrace configuration code */
    glob->trace = trace_create(glob->inputuris[glob->currenturi]);
    if (trace_is_err(glob->trace)) {
        libtrace_err_t err = trace_get_err(glob->trace);
        corsaro_log(glob->logger, "unable to create trace object: %s",
                err.problem);
        return -1;
    }

    /* nDAG does not require a hasher, so only set one if we're using
     * a different type of input.
     */
    if (glob->hasher_required) {
        trace_set_hasher(glob->trace, HASHER_BIDIRECTIONAL, glob->hasher,
                glob->hasher_data);
    }
    trace_set_perpkt_threads(glob->trace, glob->pkt_threads);

    /* trigger a tick every minute -- used for monitoring performance only */
    trace_set_tick_interval(glob->trace, 500);

    if (!processing) {
        processing = trace_create_callback_set();
        trace_set_starting_cb(processing, init_trace_processing);
        /* No stopping callback -- we free our thread-local data after
         * the processing threads have joined instead. */
        trace_set_packet_cb(processing, per_packet);
        trace_set_tick_interval_cb(processing, process_tick);
    }

    if (glob->filterstring) {
        glob->filter = trace_create_filter(glob->filterstring);

        if (trace_set_filter(glob->trace, glob->filter) == -1)
        {
            libtrace_err_t err = trace_get_err(glob->trace);
            corsaro_log(glob->logger,
                    "unable to push filter to trace object: %s", err.problem);
            return -1;
        }
    }

    if (glob->consterfframing >= 0 &&
            trace_config(glob->trace, TRACE_OPTION_CONSTANT_ERF_FRAMING,
            &(glob->consterfframing)) < 0) {
        libtrace_err_t err = trace_get_err(glob->trace);
        if (err.err_num != TRACE_ERR_OPTION_UNAVAIL) {
            corsaro_log(glob->logger, "error configuring trace object: %s",
                    err.problem);
            return -1;
        }
    }

    if (trace_pstart(glob->trace, glob, processing, NULL) == -1) {
        libtrace_err_t err = trace_get_err(glob->trace);
        corsaro_log(glob->logger, "unable to start reading from trace object: %s",
                err.problem);
        return -1;
    }

    corsaro_log(glob->logger, "successfully started input trace %s",
            glob->inputuris[glob->currenturi]);

    return 0;
}

/** Creates and populates an IPMeta data structure, based on the contents
 *  of the files listed in the configuration file.
 *
 *  @param glob             Global state for this corsarotagger instance
 *  @param ipmeta_state     A newly allocated IP meta state variable to be
 *                          populated by this function.
 */
static void load_ipmeta_data(corsaro_tagger_global_t *glob,
        corsaro_ipmeta_state_t *ipmeta_state) {

    ipmeta_provider_t *prov;

    ipmeta_state->ipmeta = ipmeta_init(IPMETA_DS_PATRICIA);
    if (glob->pfxtagopts.enabled) {
        /* Prefix to ASN mapping */
        prov = corsaro_init_ipmeta_provider(ipmeta_state->ipmeta,
                IPMETA_PROVIDER_PFX2AS, &(glob->pfxtagopts),
                glob->logger);
        if (prov == NULL) {
            corsaro_log(glob->logger, "error while enabling pfx2asn tagging.");
        } else {
            ipmeta_state->pfxipmeta = prov;
        }
    }

    if (glob->maxtagopts.enabled) {
        /* Maxmind geolocation */
        prov = corsaro_init_ipmeta_provider(ipmeta_state->ipmeta,
                IPMETA_PROVIDER_MAXMIND, &(glob->maxtagopts),
                glob->logger);
        if (prov == NULL) {
            corsaro_log(glob->logger,
                    "error while enabling Maxmind geo-location tagging.");
        } else {
            ipmeta_state->maxmindipmeta = prov;
        }
    }
    if (glob->netacqtagopts.enabled) {
        /* Netacq Edge geolocation */
        prov = corsaro_init_ipmeta_provider(ipmeta_state->ipmeta,
                IPMETA_PROVIDER_NETACQ_EDGE, &(glob->netacqtagopts),
                glob->logger);
        if (prov == NULL) {
            corsaro_log(glob->logger,
                    "error while enabling Netacq-Edge geo-location tagging.");
        } else {
            ipmeta_state->netacqipmeta = prov;
        }
    }

    ipmeta_state->ending = 0;
    ipmeta_state->refcount = 1;
    pthread_mutex_init(&(ipmeta_state->mutex), NULL);
}

/** Main loop for the thread that reloads IPMeta data when signaled.
 *
 */
static void *ipmeta_reload_thread(void *tdata) {
    corsaro_tagger_global_t *glob = (corsaro_tagger_global_t *)tdata;
    corsaro_ipmeta_state_t *replace;
    void **taggercontrolsocks;
    void *incoming;
    char msgin[8];
    char sockname[56];
    int i;

    /* These sockets allow us to tell the tagger threads to use the
     * newly reloaded IPMeta data.
     */
    taggercontrolsocks = calloc(glob->tag_threads, sizeof(void *));

    for (i = 0; i < glob->tag_threads; i++) {
        char sockname[56];

        taggercontrolsocks[i] = zmq_socket(glob->zmq_ctxt, ZMQ_PAIR);
        snprintf(sockname, 56, "%s-%d",
                TAGGER_CONTROL_SOCKET, i);

        if (zmq_bind(taggercontrolsocks[i], sockname) < 0) {
            corsaro_log(glob->logger,
                    "unable to bind tagger control socket %s: %s",
                    sockname, strerror(errno));
        }
    }

    /** This socket has two purposes:
     *  1) the main thread will use it to send us the signal to reload
     *  2) we send the new IPmeta data back to the main thread to signal
     *     that the reload is complete.
     */
    incoming = zmq_socket(glob->zmq_ctxt, ZMQ_PAIR);
    if (zmq_connect(incoming, glob->ipmeta_queue_uri) < 0) {
        corsaro_log(glob->logger,
                "error while connecting to IPmeta reload queue %s: %s",
                glob->ipmeta_queue_uri, strerror(errno));
        goto ipmeta_exit;
    }

    while (!corsaro_halted) {
        if (zmq_recv(incoming, msgin, sizeof(msgin), ZMQ_DONTWAIT) < 0) {
            if (errno == EAGAIN) {
                usleep(10000);
                continue;
            }
            corsaro_log(glob->logger,
                    "error during recv on IPmeta reload queue: %s",
                    strerror(errno));
            break;
        }

        /* Trigger a reload of the IPMeta data */
        corsaro_log(glob->logger,
                "starting reload of IPmeta data files...");
        replace = calloc(1, sizeof(corsaro_ipmeta_state_t));
        load_ipmeta_data(glob, replace);

        /* Send the replacement IPmeta data to all of the tagger threads */
        for (i = 0; i < glob->tag_threads; i++) {
            if (zmq_send(taggercontrolsocks[i], &replace,
                        sizeof(corsaro_ipmeta_state_t *), 0) < 0) {
                corsaro_log(glob->logger,
                        "error during send to tagger control queue: %s",
                        strerror(errno));
                goto ipmeta_exit;
            }
        }

        /* Send the replacement IPmeta data to the main thread, so we
         * can update our global reference to the IPmeta data  */
        if (zmq_send(incoming, &replace, sizeof(corsaro_ipmeta_state_t *), 0)
                < 0) {
            corsaro_log(glob->logger,
                    "error during send to IPmeta reload queue: %s",
                    strerror(errno));
            break;
        }
        corsaro_log(glob->logger,
                "IPmeta data file reload completed");
    }

ipmeta_exit:
    for (i = 0; i < glob->tag_threads; i++) {
        zmq_close(taggercontrolsocks[i]);
    }
    zmq_close(incoming);
    free(taggercontrolsocks);
    pthread_exit(NULL);

}

void usage(char *prog) {
    printf("Usage: %s [ -l logmode ] -c configfile \n\n", prog);
    printf("Accepted logmodes:\n");
    printf("\tterminal\n\tfile\n\tsyslog\n\tdisabled\n");
}

/** Checks for any messages that are sent to the main corsarotagger
 *  thread and acts upon them.
 *
 *  @param glob         The global state for the corsarotagger instance
 *  @return -1 if an error occurs, 0 otherwise.
 */
static inline int tagger_main_loop(corsaro_tagger_global_t *glob) {
    char controlin[100];
    uint8_t reply;
    zmq_pollitem_t items[2];
    int rc;

    if (ipmeta_reload) {
        /* We got a SIGHUP, trigger a reload of IPmeta data */
        if (zmq_send(glob->zmq_ipmeta, "", 0, 0) < 0) {
            corsaro_log(glob->logger, "error while sending reload IPMeta message: %s", strerror(errno));
        }

        ipmeta_reload = 0;
    }

    /* Two sockets are polled here. zmq_control is a socket that is used
     * to communicate information to new clients (i.e. the number of hash
     * bins that we are streaming tagged packets into). zmq_ipmeta is a
     * pair socket linking us with the IPmeta reloading thread and is used
     * to send us a pointer to the new IPmeta structure once a reload is
     * complete.
     */
    items[0].socket = glob->zmq_control;
    items[0].events = ZMQ_POLLIN;
    items[1].socket = glob->zmq_ipmeta;
    items[1].events = ZMQ_POLLIN;

    rc = zmq_poll(items, 2, 10);
    if (rc < 0) {
        if (errno == EINTR) {
            return 0;
        }
        corsaro_log(glob->logger, "error while polling zeromq sockets: %s",
                strerror(errno));
        return -1;
    }

    if (items[0].revents & ZMQ_POLLIN) {
        /* The message contents don't matter, just the fact that we got a
         * message.
         */
        if (zmq_recv(glob->zmq_control, controlin, sizeof(controlin), 0) < 0) {
            if (errno == EINTR) {
                return 0;
            }
            corsaro_log(glob->logger, "error while reading message from control socket: %s", strerror(errno));
            return -1;
        }
        /* Send our hash bin number back */
        reply = glob->output_hashbins;
        while (1) {
            if (zmq_send(glob->zmq_control, &reply, sizeof(reply), 0) < 0) {
                if (errno == EINTR) {
                    continue;
                }
                corsaro_log(glob->logger, "error while sending control message: %s", strerror(errno));
                /* carry on, don't die because of a bad client */
            }
            break;
        }
    }

    if (items[1].revents & ZMQ_POLLIN) {
        /* IP meta has been reloaded successfully */
        char recvbuf[12];
        corsaro_ipmeta_state_t *replace;

        if (zmq_recv(glob->zmq_ipmeta, recvbuf, 12, 0) < 0) {
            if (errno == EINTR) {
                return 0;
            }
            corsaro_log(glob->logger, "error while reading message from control socket: %s", strerror(errno));
            return -1;
        }
        replace = *((corsaro_ipmeta_state_t **)recvbuf);
        assert(replace);
        assert(replace->ipmeta);

        /* Replace our own global IP meta context */
        pthread_mutex_lock(&(glob->ipmeta_state->mutex));
        glob->ipmeta_state->refcount --;
        if (glob->ipmeta_state->refcount == 0) {
            glob->ipmeta_state->ending = 1;
            pthread_mutex_unlock(&(glob->ipmeta_state->mutex));
            corsaro_free_ipmeta_state(glob->ipmeta_state);
        } else {
            pthread_mutex_unlock(&(glob->ipmeta_state->mutex));
        }

        glob->ipmeta_state = replace;

    }

    return 0;
}

int main(int argc, char *argv[]) {
    char *configfile = NULL;
    char *logmodestr = NULL;
    corsaro_tagger_global_t *glob = NULL;
    int logmode = GLOBAL_LOGMODE_STDERR;
    int i;
    struct sigaction sigact;
    sigset_t sig_before, sig_block_all;
    libtrace_stat_t *stats;
    pthread_t proxythreads[2];

    corsaro_tagger_proxy_data_t internalproxy;
    corsaro_tagger_proxy_data_t externalproxy;

    while (1) {
        int optind;
        struct option long_options[] = {
            { "help", 0, 0, 'h' },
            { "config", 1, 0, 'c'},
            { "log", 1, 0, 'l'},
            { NULL, 0, 0, 0 }
        };

        int c = getopt_long(argc, argv, "l:c:h", long_options,
                &optind);
        if (c == -1) {
            break;
        }

        switch(c) {
            case 'l':
                logmodestr = optarg;
                break;
            case 'c':
                configfile = optarg;
                break;
            case 'h':
                usage(argv[0]);
                return 1;
            default:
                fprintf(stderr, "corsarotagger: unsupported option: %c\n", c);
                usage(argv[0]);
                return 1;
        }
    }

    if (configfile == NULL) {
        fprintf(stderr, "corsarotagger: no config file specified. Use -c to specify one.\n");
        usage(argv[0]);
        return 1;
    }

    if (logmodestr != NULL) {
        if (strcmp(logmodestr, "stderr") == 0 ||
                strcmp(logmodestr, "terminal") == 0) {
            logmode = GLOBAL_LOGMODE_STDERR;
        } else if (strcmp(logmodestr, "file") == 0) {
            logmode = GLOBAL_LOGMODE_FILE;
        } else if (strcmp(logmodestr, "syslog") == 0) {
            logmode = GLOBAL_LOGMODE_SYSLOG;
        } else if (strcmp(logmodestr, "disabled") == 0 ||
                strcmp(logmodestr, "off") == 0 ||
                strcmp(logmodestr, "none") == 0) {
            logmode = GLOBAL_LOGMODE_DISABLED;
        } else {
            fprintf(stderr, "corsarotagger: unexpected logmode: %s\n",
                    logmodestr);
            usage(argv[0]);
            return 1;
        }
    }
    sigact.sa_handler = reload_signal;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGHUP, &sigact, NULL);

    sigact.sa_handler = cleanup_signal;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    signal(SIGPIPE, SIG_IGN);

    glob = corsaro_tagger_init_global(configfile, logmode);
    if (glob == NULL) {
        return 1;
    }

    /* Set up the subscriber control socket */
    glob->zmq_control = zmq_socket(glob->zmq_ctxt, ZMQ_REP);
    if (zmq_bind(glob->zmq_control, glob->control_uri) < 0) {
        corsaro_log(glob->logger, "error while binding control socket: %s",
                strerror(errno));
        return 1;
    }

    /* Set up the IP meta reloading socket */
    glob->zmq_ipmeta = zmq_socket(glob->zmq_ctxt, ZMQ_PAIR);
    if (zmq_bind(glob->zmq_ipmeta, glob->ipmeta_queue_uri) < 0) {
        corsaro_log(glob->logger,
                "error while binding IP meta reload socket: %s",
                strerror(errno));
        return 1;
    }

    /* Start the zeromq proxy threads */
    internalproxy.glob = glob;
    internalproxy.insockname = PACKET_PUB_QUEUE;
    internalproxy.outsockname = TAGGER_SUB_QUEUE;
    internalproxy.recvtype = ZMQ_PULL;
    internalproxy.pushtype = ZMQ_PUSH;

    externalproxy.glob = glob;
    externalproxy.insockname = TAGGER_PUB_QUEUE;
    externalproxy.outsockname = glob->pubqueuename;
    externalproxy.recvtype = ZMQ_PULL;
    externalproxy.pushtype = ZMQ_PUB;

    pthread_create(&proxythreads[0], NULL, start_zmq_proxy_thread, &internalproxy);
    pthread_create(&proxythreads[1], NULL, start_zmq_output_thread, &externalproxy);

    /* Load the libipmeta provider data */
    glob->ipmeta_state = calloc(1, sizeof(corsaro_ipmeta_state_t));
    load_ipmeta_data(glob, glob->ipmeta_state);

    glob->threaddata = calloc(glob->tag_threads, sizeof(corsaro_tagger_local_t));
    glob->packetdata = calloc(glob->pkt_threads, sizeof(corsaro_packet_local_t));
    pthread_create(&(glob->ipmeta_reloader), NULL, ipmeta_reload_thread, glob);

    /* Initialise all of our thread local state for the tagging threads */
    for (i = 0; i < glob->tag_threads; i++) {
        init_tagger_thread_data(&(glob->threaddata[i]), i, glob);
        pthread_create(&(glob->threaddata[i].ptid), NULL, start_tagger_thread,
                &(glob->threaddata[i]));
    }

    /* Initialise all of our thread local state for the processing threads */
    for (i = 0; i < glob->pkt_threads; i++) {
        init_packet_thread_data(&(glob->packetdata[i]), i, glob);
    }

    while (glob->currenturi < glob->totaluris && !corsaro_halted) {

        sigemptyset(&sig_block_all);
        if (pthread_sigmask(SIG_SETMASK, &sig_block_all, &sig_before) < 0) {
            corsaro_log(glob->logger, "unable to disable signals before starting threads.");
            return 1;
        }
        trace_halted = 0;
        /* Create trace and start processing threads */
        if (start_trace_input(glob) < 0) {
            corsaro_log(glob->logger, "failed to start packet source %s.",
                    glob->inputuris[glob->currenturi]);
            glob->currenturi ++;
            trace_destroy(glob->trace);
            glob->trace = NULL;
            continue;
        }

        if (pthread_sigmask(SIG_SETMASK, &sig_before, NULL) < 0) {
            corsaro_log(glob->logger, "unable to re-enable signals after starting threads.");
            return 1;
        }

        /* Wait for the input to finish (or be halted via user signal) */
        while (!trace_halted) {
            if (tagger_main_loop(glob) < 0) {
                break;
            }

        }

        if (!trace_has_finished(glob->trace)) {
            glob->currenturi ++;
            trace_pstop(glob->trace);
        } else {
            glob->currenturi ++;
        }

        /* Join on input trace */
        trace_join(glob->trace);
        stats = trace_get_statistics(glob->trace, NULL);
        if (stats->dropped_valid) {
            corsaro_log(glob->logger, "dropped packet count: %lu",
                    stats->dropped);
        } else {
            corsaro_log(glob->logger, "dropped packet count: unknown");
        }

        if (stats->missing_valid) {
            corsaro_log(glob->logger, "missing packet count: %lu",
                    stats->missing);
        } else {
            corsaro_log(glob->logger, "missing packet count: unknown");
        }


        trace_destroy(glob->trace);
        glob->trace = NULL;
    }

    /* Destroy the thread local state for each processing thread */
    for (i = 0; i < glob->tag_threads; i++) {
        pthread_join(glob->threaddata[i].ptid, NULL);
        destroy_local_tagger_state(glob, &(glob->threaddata[i]), i);

    }
    for (i = 0; i < glob->pkt_threads; i++) {
        destroy_local_packet_state(glob, &(glob->packetdata[i]), i);
    }
    pthread_join(glob->ipmeta_reloader, NULL);

    corsaro_log(glob->logger, "all threads have joined, exiting.");
    corsaro_tagger_free_global(glob);
    pthread_join(proxythreads[0], NULL);
    pthread_join(proxythreads[1], NULL);

    if (processing) {
        trace_destroy_callback_set(processing);
    }
    return 0;
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

