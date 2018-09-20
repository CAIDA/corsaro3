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
#include "taggedpacket.pb-c.h"

libtrace_callback_set_t *processing = NULL;

volatile int corsaro_halted = 0;
volatile int trace_halted = 0;

static void cleanup_signal(int sig) {
    (void)sig;
    corsaro_halted = 1;
    trace_halted = 1;
}

static void *init_trace_processing(libtrace_t *trace, libtrace_thread_t *t,
        void *global) {
    corsaro_tagger_global_t *glob = (corsaro_tagger_global_t *)global;
    corsaro_tagger_local_t *tls;
    int hwm = 100000;

    if (glob->currenturi > 0) {
        return glob->savedlocalstate[trace_get_perpkt_thread_id(t)];
    }

    tls = (corsaro_tagger_local_t *)malloc(sizeof(corsaro_tagger_local_t));

    if (tls == NULL) {
        corsaro_log(glob->logger,
                "out of memory while starting packet processing thread.");
        return NULL;
    }

    tls->stopped = 0;
    tls->tagger = corsaro_create_packet_tagger(glob->logger, glob->ipmeta);
    tls->errorcount = 0;

    if (tls->tagger == NULL) {
        corsaro_log(glob->logger,
                "out of memory while creating packet tagger.");
        tls->stopped = 1;
        return tls;
    }

    if (corsaro_enable_ipmeta_provider(tls->tagger, glob->pfxipmeta) < 0) {
        corsaro_log(glob->logger,
                "error while enabling prefix->asn tagging in thread %d",
                trace_get_perpkt_thread_id(t));
        tls->stopped = 1;
    }

    if (corsaro_enable_ipmeta_provider(tls->tagger, glob->netacqipmeta) < 0) {
        corsaro_log(glob->logger,
                "error while enabling Netacq-Edge geo-location tagging in thread %d",
                trace_get_perpkt_thread_id(t));
        tls->stopped = 1;
    }

    if (corsaro_enable_ipmeta_provider(tls->tagger, glob->maxmindipmeta) < 0) {
        corsaro_log(glob->logger,
                "error while enabling Maxmind geo-location tagging in thread %d",
                trace_get_perpkt_thread_id(t));
        tls->stopped = 1;
    }

    tls->msg_source = malloc(sizeof(corsaro_memhandler_t));
    tls->ptag_source = malloc(sizeof(corsaro_memhandler_t));
    init_corsaro_memhandler(glob->logger, tls->msg_source,
            sizeof(TaggedPacket), 100);
    init_corsaro_memhandler(glob->logger, tls->ptag_source,
            sizeof(PacketTag), 1000);

    /* TODO create zmq socket for publishing */
    tls->pubsock = zmq_socket(glob->zmq_ctxt, ZMQ_PUB);
    if (zmq_setsockopt(tls->pubsock, ZMQ_SNDHWM, &hwm, sizeof(hwm)) != 0) {
        corsaro_log(glob->logger,
                "error while setting HWM for zeromq publisher socket in thread %d:%s",
                trace_get_perpkt_thread_id(t), strerror(errno));
        tls->stopped = 1;
    }

    if (zmq_connect(tls->pubsock, glob->pubqueuename) != 0) {
        corsaro_log(glob->logger,
                "error while connecting zeromq publisher socket in thread %d:%s",
                trace_get_perpkt_thread_id(t), strerror(errno));
        tls->stopped = 1;
    }

    return tls;
}

static void halt_trace_processing(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *local) {
    corsaro_tagger_global_t *glob = (corsaro_tagger_global_t *)global;
    corsaro_tagger_local_t *tls = (corsaro_tagger_local_t *)local;
    int linger = 1000;

    /* -1 because we don't increment currenturi until all of the threads have
     * stopped for the trace, so current and total will never be equal at this
     * point.
     */
    if (glob->currenturi < glob->totaluris - 1) {
        glob->savedlocalstate[trace_get_perpkt_thread_id(t)] = tls;
        return;
    }

    if (tls->tagger) {
        corsaro_destroy_packet_tagger(tls->tagger);
    }

    if (tls->pubsock) {
        zmq_setsockopt(tls->pubsock, ZMQ_LINGER, &linger, sizeof(linger));
    }
    zmq_close(tls->pubsock);

    destroy_corsaro_memhandler(tls->msg_source);
    destroy_corsaro_memhandler(tls->ptag_source);

    corsaro_log(glob->logger, "halted packet tagging thread %d, errors=%lu",
            trace_get_perpkt_thread_id(t), tls->errorcount);
    free(tls);
}

static int corsaro_publish_tags(corsaro_tagger_global_t *glob,
        corsaro_tagger_local_t *tls,
        corsaro_packet_tags_t *tags, libtrace_packet_t *packet) {

    TaggedPacket *tp = NULL;
    struct timeval tv;
    uint32_t rem, packedlen;
    void *pktcontents, *packbuf;
    libtrace_linktype_t linktype;
    PacketTag *ptags[16];
    int tagcount = 0, i, ret;
    corsaro_memsource_t *tpsrc;
    corsaro_memsource_t *ptagsrc[16];

    pktcontents = trace_get_layer2(packet, &linktype, &rem);
    if (rem == 0 || pktcontents == NULL) {
        return 0;
    }

    if (linktype != TRACE_TYPE_ETH) {
        return 0;
    }

    tv = trace_get_timeval(packet);

    tp = (TaggedPacket *)get_corsaro_memhandler_item(tls->msg_source,
            &tpsrc);

    tagged_packet__init(tp);
    /* possible metadata future extensions: wire length, link type, flow id hash
     */
    tp->ts_sec = tv.tv_sec;
    tp->ts_usec = tv.tv_usec;
    tp->pktlen = rem;
    tp->pktcontent.data = pktcontents;
    tp->pktcontent.len = rem;

    if (tags->providers_used & 1) {
        tagcount += 3;      // protocol, src port and dest port
    }

#if 0
    if (tags->providers_used & (1 << IPMETA_PROVIDER_PFX2AS)) {
        tagcount += 1;      // prefixasn
    }

    if (tags->providers_used & (1 << IPMETA_PROVIDER_MAXMIND)) {
        tagcount += 2;      // country and continent
    }

    if (tags->providers_used & (1 << IPMETA_PROVIDER_NETACQ_EDGE)) {
        tagcount += 4;      // polygon, region, country and continent
    }
#endif

    i = 0;

    if (tags->providers_used & 1) {
        ptags[i] = (PacketTag *)get_corsaro_memhandler_item(tls->ptag_source,
                &(ptagsrc[i]));
        packet_tag__init(ptags[i]);
        ptags[i]->tagid = CORSARO_TAGID_PROTOCOL;
        ptags[i]->tagval = tags->protocol;
        i++;

        ptags[i] = (PacketTag *)get_corsaro_memhandler_item(tls->ptag_source,
                &(ptagsrc[i]));
        packet_tag__init(ptags[i]);
        ptags[i]->tagid = CORSARO_TAGID_SOURCEPORT;
        ptags[i]->tagval = tags->src_port;
        i++;

        ptags[i] = (PacketTag *)get_corsaro_memhandler_item(tls->ptag_source,
                &(ptagsrc[i]));
        packet_tag__init(ptags[i]);
        ptags[i]->tagid = CORSARO_TAGID_DESTPORT;
        ptags[i]->tagval = tags->dest_port;
        i++;
    }

    tp->tags = ptags;

    packedlen = tagged_packet__get_packed_size(tp);
    packbuf = malloc(packedlen);
    tagged_packet__pack(tp, packbuf);

    ret = 0;
    if (zmq_send(tls->pubsock, &(tags->highlevelfilterbits),
            sizeof(tags->highlevelfilterbits), ZMQ_SNDMORE) < 0) {
        corsaro_log(glob->logger,
                "error while publishing tagged packet: %s", strerror(errno));
        tls->errorcount ++;
        ret = -1;
        goto endpublish;
    }

    if (zmq_send(tls->pubsock, packbuf, packedlen, 0) < 0) {
        corsaro_log(glob->logger,
                "error while publishing tagged packet: %s", strerror(errno));
        tls->errorcount ++;
        ret = -1;
        goto endpublish;
    }

endpublish:
    for (i = 0; i < tagcount; i++) {
        release_corsaro_memhandler_item(tls->ptag_source, ptagsrc[i]);
    }
    release_corsaro_memhandler_item(tls->msg_source, tpsrc);
    free(packbuf);


    return ret;
}

static libtrace_packet_t *per_packet(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *local, libtrace_packet_t *packet) {

    corsaro_tagger_global_t *glob = (corsaro_tagger_global_t *)global;
    corsaro_tagger_local_t *tls = (corsaro_tagger_local_t *)local;
    corsaro_packet_tags_t packettags;

    if (tls->stopped) {
        return packet;
    }

    if (corsaro_tag_packet(tls->tagger, &packettags, packet) != 0) {
        corsaro_log(glob->logger, "error while attempting to tag a packet");
        tls->errorcount ++;
    } else if (corsaro_publish_tags(glob, tls, &packettags, packet) != 0) {
        corsaro_log(glob->logger, "error while attempting to tag a packet");
        tls->errorcount ++;
    }
    return packet;
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

    if (glob->savedlocalstate == NULL) {
        glob->savedlocalstate = (corsaro_tagger_local_t **)malloc(
                sizeof(corsaro_tagger_local_t) * glob->threads);
    }

    if (!processing) {
        processing = trace_create_callback_set();
        trace_set_starting_cb(processing, init_trace_processing);
        trace_set_stopping_cb(processing, halt_trace_processing);
        trace_set_packet_cb(processing, per_packet);
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

    struct sigaction sigact;
    sigset_t sig_before, sig_block_all;
    libtrace_stat_t *stats;

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

    /* Join on merging thread */
    corsaro_log(glob->logger, "all threads have joined, exiting.");

    corsaro_tagger_free_global(glob);

    if (processing) {
        trace_destroy_callback_set(processing);
    }
    return 0;


}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

