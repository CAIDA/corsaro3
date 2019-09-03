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
 *   - packet processing threads        ( see packet_thread.c )
 *   - tagger worker threads            ( see tagger_thread.c )
 *   - the internal proxy thread        ( see proxy_threads.c )
 *   - the external proxy thread        ( see proxy_threads.c )
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

static void load_maxmind_country_labels(corsaro_tagger_global_t *glob,
        corsaro_ipmeta_state_t *ipmeta_state) {

    const char **countries;
    const char **continents;
    int count, ret, i;
    char build[16];
    uint32_t index;
    PWord_t pval;
    char *fqdn;

    count = ipmeta_provider_maxmind_get_iso2_list(&countries);
    ret = ipmeta_provider_maxmind_get_country_continent_list(&continents);

    if (count != ret) {
        corsaro_log(glob->logger, "libipmeta error: maxmind country array is notthe same length as the maxmind continent array?");
        return;
    }

    for (i = 0; i < count; i++) {
        index = (countries[i][0] & 0xff) + ((countries[i][1] & 0xff) << 8);
        snprintf(build, 16, "%s.%s", continents[i], countries[i]);

        JLI(pval, ipmeta_state->country_labels, index);
        if (*pval) {
            continue;
        }
        fqdn = strdup(build);
        *pval = (Word_t) fqdn;

        JLI(pval, ipmeta_state->recently_added_country_labels, index);
        *pval = (Word_t) fqdn;
    }
}

static void load_netacq_country_labels(corsaro_tagger_global_t *glob,
        corsaro_ipmeta_state_t *ipmeta_state) {

    int count, i;
    char build[16];
    uint32_t index;
    PWord_t pval;
    char *fqdn;
    ipmeta_provider_netacq_edge_country_t **countries = NULL;

    count = ipmeta_provider_netacq_edge_get_countries(
            ipmeta_state->netacqipmeta, &countries);

    for (i = 0; i < count; i++) {
        index = (countries[i]->iso2[0] & 0xff) +
                ((countries[i]->iso2[1] & 0xff) << 8);

        snprintf(build, 16, "%s.%s", countries[i]->continent,
                countries[i]->iso2);

        JLI(pval, ipmeta_state->country_labels, index);
        if (*pval) {
            continue;
        }
        fqdn = strdup(build);
        *pval = (Word_t) fqdn;

        JLI(pval, ipmeta_state->recently_added_country_labels, index);
        *pval = (Word_t) fqdn;
    }
}

static void load_netacq_region_labels(corsaro_tagger_global_t *glob,
        corsaro_ipmeta_state_t *ipmeta_state) {

    ipmeta_provider_netacq_edge_region_t **regions = NULL;
    char *fqdn;
    PWord_t pval;
    uint32_t index;
    char build[64];
    int i, count;

    count = ipmeta_provider_netacq_edge_get_regions(ipmeta_state->netacqipmeta,
            &regions);

    for (i = 0; i < count; i++) {
        index = regions[i]->code;

        /* TODO update libipmeta to add FQIDs to region entities */
        snprintf(build, 64, "TODO.%u", index);
        //snprintf(build, 64, "%s", regions[i]->fqid);
        JLI(pval, ipmeta_state->region_labels, index);
        if (*pval) {
            continue;
        }
        fqdn = strdup(build);
        *pval = (Word_t) fqdn;

        JLI(pval, ipmeta_state->recently_added_region_labels, index);
        *pval = (Word_t) fqdn;
    }
}

static void load_netacq_polygon_labels(corsaro_tagger_global_t *glob,
        corsaro_ipmeta_state_t *ipmeta_state) {

    ipmeta_polygon_table_t **tables = NULL;
    int i, count, j;
    PWord_t pval;
    uint32_t index;
    char build[96];
    char *label;

    count = ipmeta_provider_netacq_edge_get_polygon_tables(
            ipmeta_state->netacqipmeta, &tables);

    for (i = 0; i < count; i++) {

        for (j = 0; j < tables[i]->polygons_cnt; j++) {
            ipmeta_polygon_t *pol = tables[i]->polygons[j];

            if (tables[i]->id > 255) {
                corsaro_log(glob->logger,
                        "Warning: polygon table ID %u exceeds 8 bits, so Shane's sneaky renumbering scheme will no longer work!", tables[i]->id);
            }

            if (pol->id > 0xFFFFFF) {
                corsaro_log(glob->logger,
                        "Warning: polygon ID %u exceeds 24 bits, so Shane's sneaky renumbering scheme will no longer work!", pol->id);
            }

            index = (((uint32_t)i) << 24) + (pol->id & 0x00FFFFFF);
            JLI(pval, ipmeta_state->polygon_labels, (Word_t)index);
            if (*pval) {
                continue;
            }
            label = strdup(pol->fqid);
            *pval = (Word_t) label;

            JLI(pval, ipmeta_state->recently_added_polygon_labels,
                    (Word_t)index);
            *pval = (Word_t) label;
        }
    }
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

        load_maxmind_country_labels(glob, ipmeta_state);
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
        load_netacq_country_labels(glob, ipmeta_state);
        load_netacq_region_labels(glob, ipmeta_state);
        load_netacq_polygon_labels(glob, ipmeta_state);
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
        case TAGGER_REQUEST_HELLO:
            reply = (corsaro_tagger_control_reply_t *)reply_buffer;
            reply->hashbins = glob->output_hashbins;
            reply->ipmeta_version = htonl(glob->ipmeta_version);
            reply->label_count = 0;

            rptr = reply_buffer + sizeof(corsaro_tagger_control_reply_t);

            break;
        case TAGGER_REQUEST_IPMETA_UPDATE:
            reply = (corsaro_tagger_control_reply_t *)reply_buffer;
            reply->hashbins = glob->output_hashbins;
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
    pthread_t proxythreads[2];
    struct timeval tv;

    corsaro_tagger_proxy_data_t internalproxy;
    corsaro_tagger_proxy_data_t externalproxy;

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
    gettimeofday(&tv, NULL);
    glob->ipmeta_version = tv.tv_sec;
    glob->ipmeta_state->last_reload = tv.tv_sec;

    glob->threaddata = calloc(glob->tag_threads, sizeof(corsaro_tagger_local_t));
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

