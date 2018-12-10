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

#include "libcorsaro3_log.h"
#include "libcorsaro3_tagging.h"
#include "corsarotagger.h"
#include "libcorsaro3_filtering.h"
#include "libcorsaro3_memhandler.h"

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

#define TAGGER_BUFFER_SIZE (1 * 1024 * 1024)

typedef struct tagger_proxy_data {
    char *insockname;
    char *outsockname;
    int recvtype;
    int pushtype;

    corsaro_tagger_global_t *glob;
} corsaro_tagger_proxy_data_t;

libtrace_callback_set_t *processing = NULL;

volatile int corsaro_halted = 0;
volatile int trace_halted = 0;

static void cleanup_signal(int sig) {
    (void)sig;
    corsaro_halted = 1;
    trace_halted = 1;
}

static inline void init_packet_thread_data(corsaro_packet_local_t *tls,
        int threadid, corsaro_tagger_global_t *glob) {

    int hwm = 10000000;
    int one = 1;
    tls->stopped = 0;
    tls->lastmisscount = 0;
    tls->lastaccepted = 0;

    tls->bufferspace = calloc(TAGGER_BUFFER_SIZE, sizeof(uint8_t));
    tls->bufferused = 0;
    tls->buffersize = TAGGER_BUFFER_SIZE;

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

/** Initialises the local data for each processing thread.
 *
 *  @param tls          The thread-local data to be initialised
 *  @param threadid     A numeric identifier for the thread that this data
 *                      is going to be attached to
 *  @param glob         The global data for this corsarotagger instance.
 *
 */
static inline void init_tagger_thread_data(corsaro_tagger_local_t *tls,
        int threadid, corsaro_tagger_global_t *glob) {
    int hwm = 10000000;
    int one = 1;
    char pubname[1024];

    tls->ptid = 0;
    tls->glob = glob;
    tls->stopped = 0;
    tls->tagger = corsaro_create_packet_tagger(glob->logger, glob->ipmeta);
    tls->errorcount = 0;

    tls->bufferspace = calloc(TAGGER_BUFFER_SIZE, sizeof(uint8_t));
    tls->bufferused = 0;
    tls->buffersize = TAGGER_BUFFER_SIZE;

    if (tls->tagger == NULL) {
        corsaro_log(glob->logger,
                "out of memory while creating packet tagger.");
        tls->stopped = 1;
        return;
    }

    /* Enable the libipmeta providers */
    if (corsaro_enable_ipmeta_provider(tls->tagger, glob->pfxipmeta) < 0) {
        corsaro_log(glob->logger,
                "error while enabling prefix->asn tagging in thread %d",
                threadid);
        tls->stopped = 1;
    }

    if (corsaro_enable_ipmeta_provider(tls->tagger, glob->netacqipmeta) < 0) {
        corsaro_log(glob->logger,
                "error while enabling Netacq-Edge geo-location tagging in thread %d",
                threadid);
        tls->stopped = 1;
    }

    if (corsaro_enable_ipmeta_provider(tls->tagger, glob->maxmindipmeta) < 0) {
        corsaro_log(glob->logger,
                "error while enabling Maxmind geo-location tagging in thread %d",
                threadid);
        tls->stopped = 1;
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

    if (zmq_connect(tls->pubsock, TAGGER_PUB_QUEUE) != 0) {
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

static void halt_trace_processing(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *local) {

    corsaro_tagger_global_t *glob = (corsaro_tagger_global_t *)global;
    corsaro_packet_local_t *tls = (corsaro_packet_local_t *)local;

    if (tls->bufferused > 0) {
        zmq_send(tls->pubsock, tls->bufferspace, tls->bufferused, 0);
    }
    zmq_send(tls->pubsock, NULL, 0, 0);
}

/** Destroys the thread local state for a libtrace processing thread.
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

    if (tls->pubsock) {
        zmq_setsockopt(tls->pubsock, ZMQ_LINGER, &linger, sizeof(linger));
    }
    zmq_close(tls->pubsock);

    if (tls->pullsock) {
        zmq_setsockopt(tls->pullsock, ZMQ_LINGER, &linger, sizeof(linger));
    }
    zmq_close(tls->pullsock);

    free(tls->bufferspace);
}

static void destroy_local_packet_state(corsaro_tagger_global_t *glob,
        corsaro_packet_local_t *tls, int threadid) {
    int linger = 1000;

    if (tls->pubsock) {
        zmq_setsockopt(tls->pubsock, ZMQ_LINGER, &linger, sizeof(linger));
    }
    zmq_close(tls->pubsock);

    free(tls->bufferspace);
}

/** Create a tagged packet message and publishes it to the tagger proxy
 *  queue.
 *
 *  @param glob         The global state for this corsarotagger instance.
 *  @param tls          The thread-local state for this processing thread.
 *  @param tags         The tags assigned to the packet.
 *  @param packet       The packet to be published.
 */
static int corsaro_publish_tags(corsaro_tagger_global_t *glob,
        corsaro_packet_local_t *tls, libtrace_packet_t *packet) {

    struct timeval tv;
    void *pktcontents;
    uint32_t rem;
    libtrace_linktype_t linktype;
    corsaro_tagged_packet_header_t *hdr;
    size_t bufsize;

    pktcontents = trace_get_layer2(packet, &linktype, &rem);
    if (rem == 0 || pktcontents == NULL) {
        return 0;
    }

    if (linktype != TRACE_TYPE_ETH) {
        return 0;
    }
    tv = trace_get_timeval(packet);

    bufsize = sizeof(corsaro_tagged_packet_header_t) + rem;

    assert(tls->bufferused <= tls->buffersize);
    if (tls->buffersize - tls->bufferused < bufsize) {
        /* Put a copy of our buffer on the queue */
        if (zmq_send(tls->pubsock, tls->bufferspace, tls->bufferused, 0) < 0) {
            corsaro_log(glob->logger,
                    "error while publishing tagged packet: %s",
                    strerror(errno));
            return -1;
        }
        tls->bufferused = 0;
    }


    hdr = (corsaro_tagged_packet_header_t *)
            (tls->bufferspace + tls->bufferused);

    hdr->filterbits = 0;
    hdr->ts_sec = tv.tv_sec;
    hdr->ts_usec = tv.tv_usec;
    hdr->pktlen = rem;
    memset(&(hdr->tags), 0, sizeof(corsaro_packet_tags_t));

    tls->bufferused += sizeof(corsaro_tagged_packet_header_t);
    /* Put the packet itself in the buffer (minus the capture and
     * meta-data headers -- we don't need them).
     */
    memcpy(tls->bufferspace + tls->bufferused, pktcontents, rem);
    tls->bufferused += rem;

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

    if (tls->bufferused > 0) {
        zmq_send(tls->pubsock, tls->bufferspace, tls->bufferused, 0);
        tls->bufferused = 0;
    }
}

static void *start_tagger_thread(void *data) {
    corsaro_tagger_local_t *tls = (corsaro_tagger_local_t *)data;
    int r, processed;
    int onesec = 1000;

    if (zmq_setsockopt(tls->pullsock, ZMQ_RCVTIMEO, &onesec, sizeof(onesec)) < 0) {
        corsaro_log(tls->glob->logger,
                "unable to configure tagger thread pull socket: %s",
                strerror(errno));
        pthread_exit(NULL);
    }

    while (!corsaro_halted) {

        r = zmq_recv(tls->pullsock, tls->bufferspace, tls->buffersize, 0);
        if (r < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            break;
        }

        if (r == 0) {
            break;
        }

        tls->bufferused = r;
        processed = 0;

        while (processed < tls->bufferused) {
            corsaro_tagged_packet_header_t *hdr;
            libtrace_ip_t *ip;
            void *l2, *next;
            uint32_t rem;
            uint16_t ethertype;

            hdr = (corsaro_tagged_packet_header_t *)(tls->bufferspace + processed);

            if (tls->bufferused - processed < sizeof(corsaro_tagged_packet_header_t)) {
                corsaro_log(tls->glob->logger,
                        "error: not enough buffer content for a complete header...");
                exit(2);
            }

            processed += sizeof(corsaro_tagged_packet_header_t);
            if (tls->bufferused - processed < hdr->pktlen) {
                corsaro_log(tls->glob->logger,
                        "error: missing packet contents in tagger thread...");
                exit(2);
            }

            l2 = tls->bufferspace + processed;
            rem = hdr->pktlen;

            next = trace_get_payload_from_layer2(l2, TRACE_TYPE_ETH, &ethertype, &rem);
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
            if (corsaro_tag_ippayload(tls->tagger, &(hdr->tags), ip, rem) < 0) {
                corsaro_log(tls->glob->logger,
                        "error while tagging IP payload in tagger thread.");
                tls->errorcount ++;
            }
            hdr->filterbits = hdr->tags.highlevelfilterbits;
            processed += hdr->pktlen;
        }

        if (corsaro_halted) {
            break;
        }
        zmq_send(tls->pubsock, tls->bufferspace, tls->bufferused, 0);
    }

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

    if (zmq_bind(proxy_recv, proxy->insockname) < 0) {
        corsaro_log(glob->logger,
                "unable to create tagger proxy recv socket %s: %s",
                proxy->insockname, strerror(errno));
        goto proxyexit;
    }

    /* Only block for a max of one second when reading published packets */
    if (zmq_setsockopt(proxy_recv, ZMQ_RCVTIMEO, &onesec, sizeof(onesec)) < 0) {
        corsaro_log(glob->logger,
                "unable to configure tagger proxy recv socket %s: %s",
                proxy->insockname,strerror(errno));
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

    while (!corsaro_halted) {
        uint8_t recvspace[TAGGER_BUFFER_SIZE];
        int r;
        corsaro_tagged_packet_header_t *hdr;

        /* Try read a tagged packet from one of our publishers */
        if ((r = zmq_recv(proxy_recv, recvspace, TAGGER_BUFFER_SIZE, 0)) < 0) {
            if (errno == EAGAIN) {
                /* Nothing available for now, check if we need to halt
                 * then try again.
                 */
                continue;
            }
            break;
        }

        if (corsaro_halted) {
            break;
        }

        hdr = (corsaro_tagged_packet_header_t *)recvspace;
        /* Got something, publish it to our clients */
        if (r < TAGGER_BUFFER_SIZE) {
            zmq_send(proxy_fwd, recvspace, r, 0);
        } else {
            zmq_send(proxy_fwd, recvspace, TAGGER_BUFFER_SIZE, 0);
        }
    }

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
    trace_set_tick_interval(glob->trace, 60 * 1000);

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

void usage(char *prog) {
    printf("Usage: %s [ -l logmode ] -c configfile \n\n", prog);
    printf("Accepted logmodes:\n");
    printf("\tterminal\n\tfile\n\tsyslog\n\tdisabled\n");
}


int main(int argc, char *argv[]) {
    char *configfile = NULL;
    char *logmodestr = NULL;
    corsaro_tagger_global_t *glob = NULL;
    int logmode = GLOBAL_LOGMODE_STDERR;
    ipmeta_provider_t *prov;
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
    pthread_create(&proxythreads[1], NULL, start_zmq_proxy_thread, &externalproxy);

    /* Load the libipmeta provider data */
    glob->ipmeta = ipmeta_init(IPMETA_DS_PATRICIA);
    if (glob->pfxtagopts.enabled) {
        /* Prefix to ASN mapping */
        prov = corsaro_init_ipmeta_provider(glob->ipmeta,
                IPMETA_PROVIDER_PFX2AS, &(glob->pfxtagopts),
                glob->logger);
        if (prov == NULL) {
            corsaro_log(glob->logger, "error while enabling pfx2asn tagging.");
        } else {
            glob->pfxipmeta = prov;
        }
    }

    if (glob->maxtagopts.enabled) {
        /* Maxmind geolocation */
        prov = corsaro_init_ipmeta_provider(glob->ipmeta,
                IPMETA_PROVIDER_MAXMIND, &(glob->maxtagopts),
                glob->logger);
        if (prov == NULL) {
            corsaro_log(glob->logger,
                    "error while enabling Maxmind geo-location tagging.");
        } else {
            glob->maxmindipmeta = prov;
        }
    }
    if (glob->netacqtagopts.enabled) {
        /* Netacq Edge geolocation */
        prov = corsaro_init_ipmeta_provider(glob->ipmeta,
                IPMETA_PROVIDER_NETACQ_EDGE, &(glob->netacqtagopts),
                glob->logger);
        if (prov == NULL) {
            corsaro_log(glob->logger,
                    "error while enabling Netacq-Edge geo-location tagging.");
        } else {
            glob->netacqipmeta = prov;
        }
    }

    glob->threaddata = calloc(glob->tag_threads, sizeof(corsaro_tagger_local_t));
    glob->packetdata = calloc(glob->pkt_threads, sizeof(corsaro_packet_local_t));

    /* Initialise all of our thread local state for the processing threads */
    for (i = 0; i < glob->tag_threads; i++) {
        init_tagger_thread_data(&(glob->threaddata[i]), i, glob);
        pthread_create(&(glob->threaddata[i].ptid), NULL, start_tagger_thread,
                &(glob->threaddata[i]));
    }

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
            sleep(1);
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

