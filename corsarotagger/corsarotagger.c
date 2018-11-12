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

#define PROXY_RECV_SOCKNAME "inproc://taggerproxy"
libtrace_callback_set_t *processing = NULL;

volatile int corsaro_halted = 0;
volatile int trace_halted = 0;

static void cleanup_signal(int sig) {
    (void)sig;
    corsaro_halted = 1;
    trace_halted = 1;
}

static inline void init_tagger_thread_data(corsaro_tagger_local_t *tls,
        int threadid, corsaro_tagger_global_t *glob) {
    int hwm = 10000000;
    int one = 1;

    tls->stopped = 0;
    tls->tagger = corsaro_create_packet_tagger(glob->logger, glob->ipmeta);
    tls->errorcount = 0;
    tls->lastmisscount = 0;
    tls->lastaccepted = 0;
    tls->freebufs = NULL;
    tls->fbclear = 0;

    pthread_mutex_init(&(tls->bufmutex), NULL);

    if (tls->tagger == NULL) {
        corsaro_log(glob->logger,
                "out of memory while creating packet tagger.");
        tls->stopped = 1;
        return;
    }

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
    tls->pubsock = zmq_socket(glob->zmq_ctxt, ZMQ_PUB);
    if (zmq_setsockopt(tls->pubsock, ZMQ_SNDHWM, &hwm, sizeof(hwm)) != 0) {
        corsaro_log(glob->logger,
                "error while setting HWM for zeromq publisher socket in thread %d:%s",
                threadid, strerror(errno));
        tls->stopped = 1;
    }

    /* Don't queue messages for incomplete connections */
    if (zmq_setsockopt(tls->pubsock, ZMQ_IMMEDIATE, &one, sizeof(one)) != 0) {
        corsaro_log(glob->logger,
                "error while setting immediate for zeromq publisher socket in thread %d:%s",
                threadid, strerror(errno));
        tls->stopped = 1;
    }

    if (zmq_connect(tls->pubsock, PROXY_RECV_SOCKNAME) != 0) {
        corsaro_log(glob->logger,
                "error while connecting zeromq publisher socket in thread %d:%s",
                threadid, strerror(errno));
        tls->stopped = 1;
    }

}

static void *init_trace_processing(libtrace_t *trace, libtrace_thread_t *t,
        void *global) {
    corsaro_tagger_global_t *glob = (corsaro_tagger_global_t *)global;
    corsaro_tagger_local_t *tls;

    tls = &(glob->threaddata[trace_get_perpkt_thread_id(t)]);

    return tls;
}

static void halt_trace_processing(corsaro_tagger_global_t *glob,
        corsaro_tagger_local_t *tls, int threadid) {
    int linger = 1000;

    /* -1 because we don't increment currenturi until all of the threads have
     * stopped for the trace, so current and total will never be equal at this
     * point.
     */
    if (tls->tagger) {
        corsaro_destroy_packet_tagger(tls->tagger);
    }

    if (tls->pubsock) {
        zmq_setsockopt(tls->pubsock, ZMQ_LINGER, &linger, sizeof(linger));
    }
    zmq_close(tls->pubsock);

    pthread_mutex_lock(&(tls->bufmutex));
    while (tls->freebufs) {
        corsaro_tagger_buffer_t *tmp;
        tmp = tls->freebufs;
        tls->freebufs = tls->freebufs->next;

        free(tmp->bufspace);
        free(tmp);
    }
    tls->fbclear = 1;
    pthread_mutex_unlock(&(tls->bufmutex));

    corsaro_log(glob->logger, "halted packet tagging thread %d, errors=%lu",
            threadid, tls->errorcount);
}

static void simple_free(void *data, void *hint) {
    free(data);
}

static void tbuf_free(void *data, void *hint) {
    corsaro_tagger_buffer_t *tbuf = (corsaro_tagger_buffer_t *)hint;

    if (tbuf->local->fbclear) {
        free(tbuf->bufspace);
        free(tbuf);
    } else {
        if (tbuf->local->freebufs) {
            tbuf->next = tbuf->local->freebufs;
        }
        tbuf->local->freebufs = tbuf;
    }
}

static int corsaro_publish_tags(corsaro_tagger_global_t *glob,
        corsaro_tagger_local_t *tls, corsaro_packet_tags_t *tags,
        libtrace_packet_t *packet) {

    struct timeval tv;
    void *pktcontents;
    uint32_t rem;
    libtrace_linktype_t linktype;
    corsaro_tagged_packet_header_t *hdr;
    int ret;
    size_t bufsize;
    corsaro_tagger_buffer_t *tbuf = NULL;

    pktcontents = trace_get_layer2(packet, &linktype, &rem);
    if (rem == 0 || pktcontents == NULL) {
        return 0;
    }

    if (linktype != TRACE_TYPE_ETH) {
        return 0;
    }
    tv = trace_get_timeval(packet);

    bufsize = sizeof(corsaro_tagged_packet_header_t) + rem;

    if (tls->freebufs) {
        tbuf = tls->freebufs;
        tls->freebufs = tls->freebufs->next;
        tbuf->next = NULL;
    } else {
        tbuf = (corsaro_tagger_buffer_t *)calloc(1,
                sizeof(corsaro_tagger_buffer_t));
        tbuf->next = NULL;
        tbuf->bufalloc = 0;
        tbuf->bufspace = NULL;
    }

    if (bufsize > tbuf->bufalloc) {
        int toalloc;
        if (bufsize < 512) {
            toalloc = 512;
        } else {
            toalloc = bufsize;
        }
        tbuf->bufspace = realloc(tbuf->bufspace, toalloc);
        tbuf->bufalloc = toalloc;
    }
    tbuf->local = tls;

    hdr = (corsaro_tagged_packet_header_t *)tbuf->bufspace;

    hdr->filterbits = htons(tags->highlevelfilterbits);
    hdr->ts_sec = tv.tv_sec;
    hdr->ts_usec = tv.tv_usec;
    hdr->pktlen = rem;
    memcpy(&(hdr->tags), tags, sizeof(corsaro_packet_tags_t));

    memcpy(tbuf->bufspace + sizeof(corsaro_tagged_packet_header_t),
            pktcontents, rem);

    ret = 0;

    if (zmq_send(tls->pubsock, tbuf->bufspace, bufsize, 0) < 0) {
        corsaro_log(glob->logger,
                "error while publishing tagged packet: %s", strerror(errno));
        tls->errorcount ++;
        ret = -1;
        tbuf_free(tbuf->bufspace, tbuf);
        goto endpublish;
    }

endpublish:
    tbuf_free(tbuf->bufspace, tbuf);
    return ret;

}

static libtrace_packet_t *per_packet(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *local, libtrace_packet_t *packet) {

    corsaro_tagger_global_t *glob = (corsaro_tagger_global_t *)global;
    corsaro_tagger_local_t *tls = (corsaro_tagger_local_t *)local;
    corsaro_packet_tags_t packettags;
    const libtrace_packet_t *firstpkt;

    if (tls->stopped) {
        return packet;
    }

    if (corsaro_tag_packet(tls->tagger, &packettags, packet) != 0) {
        corsaro_log(glob->logger, "error while attempting to tag a packet");
        tls->errorcount ++;
    } else if (corsaro_publish_tags(glob, tls, &packettags, packet) != 0) {
        corsaro_log(glob->logger, "error while attempting to publish a packet");
        tls->errorcount ++;
    }
    return packet;
}

static void process_tick(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *local, uint64_t tick) {

    corsaro_tagger_global_t *glob = (corsaro_tagger_global_t *)global;
    corsaro_tagger_local_t *tls = (corsaro_tagger_local_t *)local;
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
}


static void *start_zmq_proxy_thread(void *data) {
    corsaro_tagger_global_t *glob = (corsaro_tagger_global_t *)data;

    void *proxy_recv = zmq_socket(glob->zmq_ctxt, ZMQ_XSUB);
    void *proxy_fwd = zmq_socket(glob->zmq_ctxt, ZMQ_XPUB);
    int zero = 0;

    if (zmq_setsockopt(proxy_recv, ZMQ_LINGER, &zero, sizeof(zero)) < 0) {
        corsaro_log(glob->logger,
                "unable to configure tagger proxy recv socket: %s",
                strerror(errno));
        goto proxyexit;
    }

    if (zmq_bind(proxy_recv, PROXY_RECV_SOCKNAME) < 0) {
        corsaro_log(glob->logger,
                "unable to create tagger proxy recv socket: %s",
                strerror(errno));
        goto proxyexit;
    }

    if (zmq_setsockopt(proxy_fwd, ZMQ_LINGER, &zero, sizeof(zero)) < 0) {
        corsaro_log(glob->logger,
                "unable to configure tagger proxy forwarding socket: %s",
                strerror(errno));
        goto proxyexit;
    }

    if (zmq_setsockopt(proxy_fwd, ZMQ_SNDHWM, &zero, sizeof(zero)) != 0) {
        corsaro_log(glob->logger,
                "error while setting HWM for proxy forwarding socket: %s",
                strerror(errno));
        goto proxyexit;
    }

    if (zmq_bind(proxy_fwd, glob->pubqueuename) < 0) {
        corsaro_log(glob->logger,
                "unable to create tagger proxy forwarding socket: %s",
                strerror(errno));
        goto proxyexit;
    }

    zmq_proxy(proxy_recv, proxy_fwd, NULL);

proxyexit:
    zmq_close(proxy_recv);
    zmq_close(proxy_fwd);
    pthread_exit(NULL);
}

static int start_trace_input(corsaro_tagger_global_t *glob) {

    glob->trace = trace_create(glob->inputuris[glob->currenturi]);
    if (trace_is_err(glob->trace)) {
        libtrace_err_t err = trace_get_err(glob->trace);
        corsaro_log(glob->logger, "unable to create trace object: %s",
                err.problem);
        return -1;
    }

    if (glob->hasher_required) {
        trace_set_hasher(glob->trace, HASHER_BIDIRECTIONAL, glob->hasher,
                glob->hasher_data);
    }
    trace_set_perpkt_threads(glob->trace, glob->threads);
    trace_set_tick_interval(glob->trace, 60 * 1000);

    if (!processing) {
        processing = trace_create_callback_set();
        trace_set_starting_cb(processing, init_trace_processing);
        //trace_set_stopping_cb(processing, halt_trace_processing);
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
    pthread_t proxythread;

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

    pthread_create(&proxythread, NULL, start_zmq_proxy_thread, glob);

    glob->ipmeta = ipmeta_init(IPMETA_DS_PATRICIA);
    if (glob->pfxtagopts.enabled) {
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

    glob->threaddata = calloc(glob->threads, sizeof(corsaro_tagger_local_t));

    for (i = 0; i < glob->threads; i++) {
        init_tagger_thread_data(&(glob->threaddata[i]), i, glob);
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

    for (i = 0; i < glob->threads; i++) {
        halt_trace_processing(glob, &(glob->threaddata[i]), i);
    }
    corsaro_log(glob->logger, "all threads have joined, exiting.");
    corsaro_tagger_free_global(glob);
    pthread_join(proxythread, NULL);

    if (processing) {
        trace_destroy_callback_set(processing);
    }
    return 0;


}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

