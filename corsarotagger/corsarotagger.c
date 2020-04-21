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
 * This seems simple, but is slightly more complex in practice.
 *
 * There are a few different classes of threads that run concurrently
 * to make this all work optimally:
 *   - packet processing threads        ( see packet_thread.c )
 *   - tagger worker threads            ( see tagger_thread.c )
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
 * computing the flowtuple hash.
 * Advanced tagging can also occur via the libipmeta library, provided
 * suitable source data files are available. These can be used for
 * geo-location and prefix-to-ASN mapping of the packet's source IP address.
 *
 * Each tagger thread emits the tagged packets to a multicast group, using the
 * nDAG protocol.
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
 * number of tagger threads that are emitting packets).
 */


/** Older versions of libzmq use a different name for this option */
#ifndef ZMQ_IMMEDIATE
#define ZMQ_IMMEDIATE ZMQ_DELAY_ATTACH_ON_CONNECT
#endif

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
    if (((tick >> 32) % 60) == 0 && (tick >> 32) > tls->laststat) {
        stats = trace_create_statistics();
        trace_get_thread_statistics(trace, t, stats);

        if (glob->statfilename) {
            FILE *f = NULL;
            char sfname[1024];

            snprintf(sfname, 1024, "%s-t%02d", glob->statfilename,
                    trace_get_perpkt_thread_id(t));
            f = fopen(sfname, "w");
            if (!f) {
                corsaro_log(glob->logger, "unable to open statistic file %s for writing: %s",
                        sfname, strerror(errno));
            } else {
                fprintf(f, "time=%lu accepted=%lu dropped=%lu\n",
                        (tick >> 32), stats->accepted - tls->lastaccepted,
                        stats->missing - tls->lastmisscount);
                fclose(f);
            }
        }

        if (stats->missing > tls->lastmisscount) {
            if (!glob->statfilename) {
                corsaro_log(glob->logger,
                        "thread %d dropped %lu packets in last minute (accepted %lu)",
                        trace_get_perpkt_thread_id(t),
                        stats->missing - tls->lastmisscount,
                        stats->accepted - tls->lastaccepted);
            }
            tls->lastmisscount = stats->missing;
        }
        tls->lastaccepted = stats->accepted;

        free(stats);
        tls->tickcounter = 0;
        tls->laststat = (tick >> 32);
    }

    if (tls->buf->used > 0) {
	    ENQUEUE_BUFFER(tls);
        tls->buf = create_tls_buffer();
    }
}

/** Creates and starts a libtrace input.
 *
 *  @param glob     The global state for this corsarotagger instance.
 *
 *  @return -1 if an error occurs, 0 if successful.
 */
static int start_trace_input(corsaro_tagger_global_t *glob) {

    FILE *f = NULL;

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

    /* Assign ourselves a "random" tagger ID number so that clients can
     * tell if the tagger is restarted (and therefore its sequence space
     * will be reset).
     * Try using /dev/urandom but fall back to current Unix time if that
     * fails for some reason.
     */
    f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        corsaro_log(glob->logger,
                "unable to open /dev/urandom to generate tagger ID: %s",
                strerror(errno));
        glob->instance_id = (uint32_t) time(NULL);
    }

    while (glob->instance_id == 0) {
        if (fread(&(glob->instance_id), sizeof(glob->instance_id), 1, f) < 1) {
            corsaro_log(glob->logger,
                    "unable to read /dev/urandom to generate tagger ID: %s",
                    strerror(errno));
            glob->instance_id = (uint32_t) time(NULL);
        }
    }

    if (f) {
        fclose(f);
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

static int start_ndag_beaconer(pthread_t *tid, ndag_beacon_params_t *bparams) {

    int ret;

#ifdef __linux__
    pthread_attr_t attrib;
    cpu_set_t cpus;
    //int i;
#endif

#ifdef __linux__

    /* This thread is low impact so can be bound to core 0 */
    CPU_ZERO(&cpus);
    CPU_SET(0, &cpus);
    pthread_attr_init(&attrib);
    pthread_attr_setaffinity_np(&attrib, sizeof(cpus), &cpus);
    ret = pthread_create(tid, &attrib, ndag_start_beacon,
            (void *)(bparams));
    pthread_attr_destroy(&attrib);

#else
    ret = pthread_create(tid, NULL, ndag_start_beacon,
            (void *)(bparams));
#endif


    if (ret != 0) {
        return -1;
    }

    return 1;
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
    taggercontrolsocks = calloc(glob->pkt_threads, sizeof(void *));

    for (i = 0; i < glob->pkt_threads; i++) {
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
        corsaro_load_ipmeta_data(glob->logger, &(glob->pfxtagopts),
            &(glob->maxtagopts), &(glob->netacqtagopts), replace);

        /* Send the replacement IPmeta data to all of the tagger threads */
        for (i = 0; i < glob->pkt_threads; i++) {
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
    for (i = 0; i < glob->pkt_threads; i++) {
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

static inline char *send_ipmeta_labels(Pvoid_t labelmap, char *buffer,
        char *rptr, int bufsize, void *sock, uint8_t labeltype) {

    corsaro_tagger_label_hdr_t *hdr;
    Word_t index;
    PWord_t pval;

    index = 0;
    JLF(pval, labelmap, index);
    while (pval) {
        char *label = (char *)(*pval);
        uint32_t subjid = (uint32_t) index;
        int labellen = strlen(label);

        int needed = labellen + sizeof(corsaro_tagger_label_hdr_t);

        if (bufsize - (rptr - buffer) < needed) {
            /* send what we've got */
            if (zmq_send(sock, buffer, rptr-buffer, ZMQ_SNDMORE) < 0) {
                /* TODO log an error? */

            }
            rptr = buffer;
        }

        hdr = (corsaro_tagger_label_hdr_t *)rptr;
        hdr->subject_type = labeltype;
        hdr->subject_id = ntohl(subjid);
        hdr->label_len = ntohs((uint16_t)labellen);

        rptr += sizeof(corsaro_tagger_label_hdr_t);
        memcpy(rptr, label, labellen);
        rptr += labellen;

        JLN(pval, labelmap, index);
    }

    return rptr;
}

static char *send_all_ipmeta_labels(corsaro_ipmeta_state_t *state,
        char *buffer, char *rptr, int bufsize, void *sock) {

    rptr = send_ipmeta_labels(state->country_labels, buffer, rptr, bufsize,
            sock, TAGGER_LABEL_COUNTRY);
    rptr = send_ipmeta_labels(state->region_labels, buffer, rptr, bufsize,
            sock, TAGGER_LABEL_REGION);
    rptr = send_ipmeta_labels(state->polygon_labels, buffer, rptr, bufsize,
            sock, TAGGER_LABEL_POLYGON);

    return rptr;
}

static char *send_new_ipmeta_labels(corsaro_ipmeta_state_t *state,
        char *buffer, char *rptr, int bufsize, void *sock) {

    rptr = send_ipmeta_labels(state->recently_added_country_labels, buffer,
            rptr, bufsize, sock, TAGGER_LABEL_COUNTRY);
    rptr = send_ipmeta_labels(state->recently_added_region_labels, buffer,
            rptr, bufsize, sock, TAGGER_LABEL_REGION);
    rptr = send_ipmeta_labels(state->recently_added_polygon_labels, buffer,
            rptr, bufsize, sock, TAGGER_LABEL_POLYGON);

    return rptr;

}

static int process_control_request(corsaro_tagger_global_t *glob) {

    corsaro_tagger_control_request_t req;
    corsaro_tagger_control_reply_t *reply;
    char reply_buffer[10000];
    char *rptr = reply_buffer;
    Word_t rc_word;
    struct timeval tv;

    gettimeofday(&tv, NULL);

    if (zmq_recv(glob->zmq_control, &req, sizeof(req), 0) < 0) {
        if (errno == EINTR) {
            return 0;
        }
        corsaro_log(glob->logger, "error while reading message from control socket: %s", strerror(errno));
        return -1;
    }

    if (tv.tv_sec - glob->ipmeta_state->last_reload >= 300) {

        if (glob->ipmeta_state->recently_added_country_labels) {
            corsaro_free_ipmeta_label_map(
                    glob->ipmeta_state->recently_added_country_labels, 0);
            glob->ipmeta_state->recently_added_country_labels = NULL;
        }

        if (glob->ipmeta_state->recently_added_region_labels) {
            corsaro_free_ipmeta_label_map(
                    glob->ipmeta_state->recently_added_region_labels, 0);
            glob->ipmeta_state->recently_added_region_labels = NULL;
        }

        if (glob->ipmeta_state->recently_added_polygon_labels) {
            corsaro_free_ipmeta_label_map(
                    glob->ipmeta_state->recently_added_polygon_labels, 0);
            glob->ipmeta_state->recently_added_polygon_labels = NULL;
        }
    }

    switch(req.request_type) {
        case TAGGER_REQUEST_HALT_FAUX:
            return 0;
        case TAGGER_REQUEST_HELLO:
            reply = (corsaro_tagger_control_reply_t *)reply_buffer;
            reply->hashbins = glob->pkt_threads;
            reply->ipmeta_version = htonl(glob->ipmeta_version);
            reply->label_count = 0;

            rptr = reply_buffer + sizeof(corsaro_tagger_control_reply_t);

            break;
        case TAGGER_REQUEST_IPMETA_UPDATE:
            reply = (corsaro_tagger_control_reply_t *)reply_buffer;
            reply->hashbins = glob->pkt_threads;
            reply->ipmeta_version = htonl(glob->ipmeta_version);
            reply->label_count = 0;

            rptr = reply_buffer + sizeof(corsaro_tagger_control_reply_t);
            if (req.data.last_version == 0) {
                JLC(rc_word, glob->ipmeta_state->country_labels, 0, -1);
                reply->label_count += (uint32_t)rc_word;
                JLC(rc_word, glob->ipmeta_state->region_labels, 0, -1);
                reply->label_count += (uint32_t)rc_word;
                reply->label_count = htonl(reply->label_count);

                rptr = send_all_ipmeta_labels(glob->ipmeta_state, reply_buffer,
                        rptr, 10000, glob->zmq_control);
            } else {
                JLC(rc_word, glob->ipmeta_state->recently_added_country_labels,
                        0, -1);
                reply->label_count += (uint32_t)rc_word;
                JLC(rc_word, glob->ipmeta_state->recently_added_region_labels,
                        0, -1);
                reply->label_count += (uint32_t)rc_word;
                reply->label_count = htonl(reply->label_count);
                rptr = send_new_ipmeta_labels(glob->ipmeta_state, reply_buffer,
                        rptr, 10000, glob->zmq_control);
            }

            break;
        default:
            corsaro_log(glob->logger, "unexpected control request type: %u",
                    req.request_type);
            return -1;
    }
    if (rptr == reply_buffer) {
        corsaro_log(glob->logger, "warning: no outstanding content in buffer at end of request processing loop?");
    }

    while (rptr - reply_buffer > 0) {
        if (zmq_send(glob->zmq_control, reply_buffer, rptr - reply_buffer,
                0) < 0) {
            if (errno == EINTR) {
                continue;
            }
            corsaro_log(glob->logger, "error while sending control message: %s", strerror(errno));
            /* carry on, don't die because of a bad client */
        }
        break;
    }
    return 1;
}

/** Checks for any messages that are sent to the main corsarotagger
 *  thread and acts upon them.
 *
 *  @param glob         The global state for the corsarotagger instance
 *  @return -1 if an error occurs, 0 otherwise.
 */
static inline int tagger_main_loop(corsaro_tagger_global_t *glob) {
    uint8_t reply;
    zmq_pollitem_t items[2];
    int rc;
    struct timeval tv;

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
        if ((rc = process_control_request(glob)) <= 0) {
            return rc;
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

        gettimeofday(&tv, NULL);
        glob->ipmeta_state = replace;
        glob->ipmeta_version = tv.tv_sec;
        glob->ipmeta_state->last_reload = tv.tv_sec;

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
    pthread_t beacon_tid;
    struct timeval tv;
    uint16_t firstport;
    ndag_beacon_params_t beaconparams;
    time_t t;

    srand((unsigned) time(&t));
    firstport = 10000 + (rand() % 50000);

    corsaro_halted = 0;
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

    /* Load the libipmeta provider data */
    glob->ipmeta_state = calloc(1, sizeof(corsaro_ipmeta_state_t));
    corsaro_load_ipmeta_data(glob->logger, &(glob->pfxtagopts),
            &(glob->maxtagopts), &(glob->netacqtagopts), glob->ipmeta_state);
    gettimeofday(&tv, NULL);
    glob->ipmeta_version = tv.tv_sec;
    glob->ipmeta_state->last_reload = tv.tv_sec;

    glob->threaddata = calloc(glob->pkt_threads, sizeof(corsaro_tagger_local_t));
    glob->packetdata = calloc(glob->pkt_threads, sizeof(corsaro_packet_local_t));
    pthread_create(&(glob->ipmeta_reloader), NULL, ipmeta_reload_thread, glob);

    /* Note: I'm being a bit unconventional here in that I'm creating and
     * initialising the thread-local state for my threads outside of the
     * threads themselves.
     *
     * The reason for this is that I have certain variables (namely the
     * zeromq sockets) that I only want to free *after* I am sure that the
     * threads spawned by this program have exited. This prevents deadlocks
     * on exit where a receiver has gone away but the sender is stuck in a
     * blocking send.
     */

    beaconparams.srcaddr = glob->ndag_sourceaddr;
    beaconparams.groupaddr = glob->ndag_mcastgroup;
    beaconparams.beaconport = glob->ndag_beaconport;
    beaconparams.frequency = 1000;
    beaconparams.monitorid = glob->ndag_monitorid;
    beaconparams.numstreams = glob->pkt_threads;
    beaconparams.streamports = (uint16_t *)calloc(glob->pkt_threads,
            sizeof(uint16_t));

	sigemptyset(&sig_block_all);
	if (pthread_sigmask(SIG_SETMASK, &sig_block_all, &sig_before) < 0) {
		corsaro_log(glob->logger, "unable to disable signals before starting threads.");
		return 1;
	}

    /* Initialise all of our thread local state for the tagging threads */
    for (i = 0; i < glob->pkt_threads; i++) {
        uint16_t mcast_port = firstport + (2 * i);
        beaconparams.streamports[i] = mcast_port;
        init_tagger_thread_data(&(glob->threaddata[i]), i, glob, mcast_port);
        pthread_create(&(glob->threaddata[i].ptid), NULL, start_tagger_thread,
                &(glob->threaddata[i]));
    }

    /* Start up the ndag beaconing thread */
    if (start_ndag_beaconer(&beacon_tid, &beaconparams) == -1) {
        corsaro_log(glob->logger, "Failed to start ndag beaconing thread");
        return 1;
    }

	if (pthread_sigmask(SIG_SETMASK, &sig_before, NULL) < 0) {
		corsaro_log(glob->logger, "unable to re-enable signals after starting threads.");
		return 1;
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

	ndag_interrupt_beacon();
	pthread_join(beacon_tid, NULL);

	free(beaconparams.streamports);

    /* Destroy the thread local state for each processing thread */
    for (i = 0; i < glob->pkt_threads; i++) {
        pthread_join(glob->threaddata[i].ptid, NULL);
        destroy_local_tagger_state(glob, &(glob->threaddata[i]), i);

    }
    for (i = 0; i < glob->pkt_threads; i++) {
        destroy_local_packet_state(glob, &(glob->packetdata[i]), i);
    }
    pthread_join(glob->ipmeta_reloader, NULL);

    corsaro_log(glob->logger, "all threads have joined, exiting.");
    corsaro_tagger_free_global(glob);

    if (processing) {
        trace_destroy_callback_set(processing);
    }
    return 0;
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

