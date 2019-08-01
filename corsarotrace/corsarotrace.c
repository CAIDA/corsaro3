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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

#include <libtrace.h>
#include <zmq.h>

#include "libcorsaro_log.h"
#include "libcorsaro_common.h"
#include "corsarotrace.h"
#include "libcorsaro_plugin.h"
#include "libcorsaro_filtering.h"

/* TODO: this is currently defined in both the tagger and here, so we
 * run the risk of them getting out of sync :/
 */
#define TAGGER_MAX_MSGSIZE (10 * 1024 * 1024)

typedef struct pcaphdr_t {
    uint32_t ts_sec;        /* Seconds portion of the timestamp */
    uint32_t ts_usec;       /* Microseconds portion of the timestamp */
    uint32_t caplen;        /* Capture length of the packet */
    uint32_t wirelen;       /* The wire length of the packet */
} pcaphdr_t;


volatile int corsaro_halted = 0;

static void cleanup_signal(int sig) {
    (void)sig;
    corsaro_halted = 1;
}


static void fast_construct_packet(libtrace_t *deadtrace,
        libtrace_packet_t *packet, corsaro_tagged_packet_header_t *taghdr,
        char *packetcontent, uint16_t *packetbufsize)
{

    /* Clone of trace_construct_packet() but designed to minimise
     * memory reallocations.
     */
    pcaphdr_t pcaphdr;

    pcaphdr.ts_sec = taghdr->ts_sec;
    pcaphdr.ts_usec = taghdr->ts_usec;
    pcaphdr.caplen = taghdr->pktlen;
    pcaphdr.wirelen = taghdr->pktlen;

    packet->trace = deadtrace;
    if (*packetbufsize < taghdr->pktlen + sizeof(pcaphdr)) {
        if (taghdr->pktlen + sizeof(pcaphdr) > 512) {
            packet->buffer = realloc(packet->buffer,
                    taghdr->pktlen + sizeof(pcaphdr));
            *packetbufsize = taghdr->pktlen + sizeof(pcaphdr);
        } else {
            packet->buffer = realloc(packet->buffer, 512);
            *packetbufsize = 512;
        }
    }

    packet->buf_control = TRACE_CTRL_PACKET;
    packet->header = packet->buffer;
    packet->payload = ((char *)(packet->buffer) + sizeof(pcaphdr));

    memcpy(packet->payload, packetcontent, taghdr->pktlen);
    memcpy(packet->header, &pcaphdr, sizeof(pcaphdr));
    packet->type = TRACE_RT_DATA_DLT + TRACE_DLT_EN10MB;

    packet->cached.l2_header = packet->payload;
    packet->cached.l3_header = NULL;
    packet->cached.l4_header = NULL;
    packet->cached.link_type = TRACE_TYPE_ETH;
    packet->cached.l3_ethertype = 0;
    packet->cached.transport_proto = 0;
    packet->cached.capture_length = taghdr->pktlen;
    packet->cached.wire_length = taghdr->pktlen;
    packet->cached.payload_length = -1;
    packet->cached.l2_remaining = taghdr->pktlen;
    packet->cached.l3_remaining = 0;
    packet->cached.l4_remaining = 0;
    packet->refcount = 0;
    packet->which_trace_start = 0;
}

static int push_interval_result(corsaro_trace_worker_t *tls,
        void **result) {

    corsaro_result_msg_t res;

    res.type = CORSARO_TRACE_MSG_MERGE;
    res.source = tls->workerid;
    res.interval_num = tls->current_interval.number;
    res.interval_time = tls->current_interval.time;
    res.plugindata = result;

    if (zmq_send(tls->zmq_pushsock, &res, sizeof(res), 0) < 0) {
        corsaro_log(tls->glob->logger,
                "error while pushing result from worker %d: %s",
                tls->workerid, strerror(errno));
        return -1;
    }

    return 0;
}

static int push_rotate_output(corsaro_trace_worker_t *tls, uint32_t ts) {

    corsaro_result_msg_t res;

    res.type = CORSARO_TRACE_MSG_ROTATE;
    res.source = tls->workerid;
    res.interval_num = tls->current_interval.number;
    res.interval_time = ts;
    res.plugindata = NULL;

    if (zmq_send(tls->zmq_pushsock, &res, sizeof(res), 0) < 0) {
        corsaro_log(tls->glob->logger,
                "error while pushing result from worker %d: %s",
                tls->workerid, strerror(errno));
        return -1;
    }

    return 0;
}

static int push_stop_merging(corsaro_trace_worker_t *tls) {

    corsaro_result_msg_t res;

    res.type = CORSARO_TRACE_MSG_STOP;
    res.source = tls->workerid;
    res.interval_num = tls->current_interval.number;
    res.interval_time = 0;
    res.plugindata = NULL;

    if (zmq_send(tls->zmq_pushsock, &res, sizeof(res), 0) < 0) {
        corsaro_log(tls->glob->logger,
                "error while pushing stop from worker %d: %s",
                tls->workerid, strerror(errno));
        return -1;
    }

    return 0;
}

static int worker_per_packet(corsaro_trace_worker_t *tls,
        corsaro_tagged_packet_header_t *taghdr, libtrace_t *deadtrace) {

    void **interval_data;
    uint32_t tagid;
    uint64_t thisseq;
    int seqindex;
    uint16_t pktalloc = 0;
    void **final_result;
    uint16_t fbits = 0;

    tagid = ntohl(taghdr->tagger_id);
    thisseq = bswap_be_to_host64(taghdr->seqno);

    if (taghdr->hashbin <= 'Z') {
        seqindex = taghdr->hashbin - 'A';
    } else {
        seqindex = taghdr->hashbin - 'a';
    }

    if (tagid != tls->taggerid) {
        /* tagger has restarted -- reset our sequence numbers */
        tls->taggerid = tagid;
        memset(tls->nextseq, 0, sizeof(uint64_t) * tls->glob->max_hashbins);
    }

    /* seqno of 0 is a reserved value -- we will never receive a seqno
     * of 0, so we can use it to mark the next expected sequence number
     * as "unknown".
     */
    if (tls->nextseq[seqindex] != 0 && thisseq != tls->nextseq[seqindex]) {
        tls->dropcounter += (thisseq - tls->nextseq[seqindex]);
        tls->dropinstances ++;
    }
    tls->nextseq[seqindex] = thisseq + 1;
    if (tls->nextseq[seqindex] == 0) {
        tls->nextseq[seqindex] = 1;
    }

    fast_construct_packet(deadtrace, tls->packet, taghdr,
            ((uint8_t *)taghdr) + sizeof(corsaro_tagged_packet_header_t),
            &pktalloc);

    if (tls->glob->boundstartts && taghdr->ts_sec <
            tls->glob->boundstartts) {
        return 0;
    }

    if (tls->glob->boundendts && taghdr->ts_sec >= tls->glob->boundendts) {
        /* push end interval message for glob->boundendts */
        final_result = corsaro_push_end_plugins(tls->plugins,
                tls->current_interval.number, tls->glob->boundendts, 0);

        if (push_interval_result(tls, final_result) < 0) {
            corsaro_log(tls->glob->logger,
                    "error while publishing results for final interval %u",
                    tls->current_interval.number);
        }

        /* push close file message for interval and boundendts */
        if (push_rotate_output(tls, tls->glob->boundendts) < 0) {
            corsaro_log(tls->glob->logger,
                    "error while pushing rotate message after final interval %u",
                    tls->current_interval.number);
        }
        return -1;
    }

    if (tls->current_interval.time == 0) {

        if (tls->first_pkt_ts == 0) {
            tls->first_pkt_ts = taghdr->ts_sec;
            pthread_mutex_lock(&(tls->glob->mutex));
            if (tls->first_pkt_ts < tls->glob->first_pkt_ts ||
                    tls->glob->first_pkt_ts == 0) {
                tls->glob->first_pkt_ts = tls->first_pkt_ts;
            }
            pthread_mutex_unlock(&(tls->glob->mutex));
        }

        /* First non-ignored packet */
        if (tls->glob->interval <= 0) {
            corsaro_log(tls->glob->logger,
                    "interval has somehow been assigned a bad value of %u\n",
                    tls->glob->interval);
            return -1;
        }

        pthread_mutex_lock(&(tls->glob->mutex));
        tls->current_interval.time = tls->glob->first_pkt_ts;
        pthread_mutex_unlock(&(tls->glob->mutex));
        tls->lastrotateinterval.time = tls->current_interval.time -
                (tls->current_interval.time %
                (tls->glob->interval * tls->glob->rotatefreq));

        corsaro_push_start_plugins(tls->plugins, tls->current_interval.number,
                tls->current_interval.time);

        tls->next_report = tls->current_interval.time -
                (tls->current_interval.time % tls->glob->interval) +
                 tls->glob->interval;
        tls->next_rotate = tls->lastrotateinterval.time +
                (tls->glob->interval * tls->glob->rotatefreq);
    }

    if (taghdr->ts_sec < tls->current_interval.time) {
        return 0;
    }
    /* check if we have passed the end of an interval */
    while (tls->next_report && taghdr->ts_sec >= tls->next_report) {
        uint8_t complete = 0;
        /* end interval */
        if (tls->next_report - tls->current_interval.time ==
                tls->glob->interval) {
            complete = 1;
        } else {
            complete = 0;
        }
        interval_data = corsaro_push_end_plugins(tls->plugins,
                tls->current_interval.number, tls->next_report, complete);

        if (push_interval_result(tls, interval_data) < 0) {
            corsaro_log(tls->glob->logger,
                    "error while publishing results for interval %u",
                    tls->current_interval.number);
            return -1;
        }

        if (tls->dropcounter > 0) {
            corsaro_log(tls->glob->logger,
                    "warning: worker thread %d has observed %u packets dropped by the tagger in the past interval (%u instances)",
                    tls->workerid,
                    tls->dropcounter, tls->dropinstances);
        }
        tls->dropcounter = 0;
        tls->dropinstances = 0;

        if (tls->glob->rotatefreq > 0 &&
                taghdr->ts_sec >= tls->next_rotate) {

            /* push rotate message */
            if (push_rotate_output(tls, tls->next_report) < 0) {
                corsaro_log(tls->glob->logger,
                        "error while pushing rotate message after interval %u",
                        tls->current_interval.number);
                return -1;
            }
            tls->next_rotate +=
                    (tls->glob->interval * tls->glob->rotatefreq);
        }

        tls->current_interval.number ++;
        tls->current_interval.time = tls->next_report;
        corsaro_push_start_plugins(tls->plugins, tls->current_interval.number,
            tls->current_interval.time);
        tls->next_report += tls->glob->interval;
        tls->pkts_outstanding = 0;

        if (tls->pkts_from_prev_interval > 0) {
            corsaro_log(tls->glob->logger, "worker thread %d has observed %u packets from previous interval during interval %u",
                    tls->workerid, tls->pkts_from_prev_interval,
                    tls->current_interval.number - 1);
            tls->pkts_from_prev_interval = 0;
        }
    }

    fbits = ntohs(taghdr->filterbits);
    if (tls->glob->removespoofed && (fbits & CORSARO_FILTERBIT_SPOOFED)) {
        goto filtered;
    }

    if (tls->glob->removeerratic && (fbits & CORSARO_FILTERBIT_ERRATIC)) {
        goto filtered;
    }

    if (tls->glob->removerouted && !(fbits & CORSARO_FILTERBIT_NONROUTABLE)) {
        goto filtered;
    }

    if (taghdr->ts_sec < tls->current_interval.time) {
        tls->pkts_from_prev_interval ++;
    }

    tls->pkts_outstanding ++;
    tls->last_ts = taghdr->ts_sec;
    corsaro_push_packet_plugins(tls->plugins, tls->packet, &(taghdr->tags));

    return 1;

filtered:
    return 1;
}
static int subscribe_streams(corsaro_trace_global_t *glob,
        void *zmqsock, int threadid) {

    char tosub[8];
    int i, j;

    memset(tosub, 0, sizeof(char) * 8);

    for (i = 0; i < glob->max_hashbins; i++) {
        if (i % glob->threads != threadid) {
            continue;
        }

        if (i < 26) {
            tosub[0] = 'A' + i;
        } else if (i < 52) {
            tosub[0] = 'a' + i;
        } else {
            assert(glob->max_hashbins < 52);
        }

        if (zmq_setsockopt(zmqsock, ZMQ_SUBSCRIBE, tosub, 1)
                < 0) {
            corsaro_log(glob->logger,
                    "unable to subscribe to all streams of tagged packets: %s",
                    strerror(errno));
            return -1;
        }
    }
    return 0;

}

static void *start_worker(void *tdata) {

    corsaro_trace_worker_t *tls = (corsaro_trace_worker_t *)tdata;
    uint8_t *rcvspace;
    void **final_result;
    libtrace_t *deadtrace = NULL;
    int hwm = tls->glob->inputhwm;

    deadtrace = trace_create_dead("pcapfile");
    tls->packet = trace_create_packet();
    rcvspace = malloc(TAGGER_MAX_MSGSIZE);

    tls->zmq_pullsock = zmq_socket(tls->glob->zmq_ctxt, ZMQ_SUB);

    if (subscribe_streams(tls->glob, tls->zmq_pullsock, tls->workerid) < 0) {
        goto endworker;
    }

    if (zmq_setsockopt(tls->zmq_pullsock, ZMQ_RCVHWM, &hwm, sizeof(hwm)) < 0) {
        corsaro_log(tls->glob->logger,
                "unable to configure sub socket for worker %d: %s",
                tls->workerid, strerror(errno));
        goto endworker;
    }


    if (zmq_connect(tls->zmq_pullsock, tls->glob->subqueuename) != 0) {
        corsaro_log(tls->glob->logger,
                "unable to connect sub socket for worker %d: %s", tls->workerid,
                strerror(errno));
        goto endworker;
    }

    tls->zmq_pushsock = zmq_socket(tls->glob->zmq_ctxt, ZMQ_PUSH);
    if (zmq_connect(tls->zmq_pushsock, "inproc://pluginresults") < 0) {
        corsaro_log(tls->glob->logger,
                "error while connecting worker %d to result socket: %s",
                tls->workerid, strerror(errno));
        goto endworker;
    }

    tls->plugins = corsaro_start_plugins(tls->glob->logger,
            tls->glob->active_plugins, tls->glob->plugincount,
            tls->workerid);

    if (tls->plugins == NULL) {
        corsaro_log(tls->glob->logger, "worker %d unable to start plugins.",
                tls->workerid);
        goto endworker;
    }

    while (!corsaro_halted) {
        corsaro_tagged_packet_header_t *hdr;
        int processed;
        int received;

        if ((received = zmq_recv(tls->zmq_pullsock, rcvspace,
                TAGGER_MAX_MSGSIZE, ZMQ_DONTWAIT)) < 0) {
            if (errno == EAGAIN) {
                usleep(10);
                continue;
            }

            corsaro_log(tls->glob->logger,
                    "error receiving message on worker %d sub socket: %s",
                    tls->workerid, strerror(errno));
            break;
        }
        processed = 0;

        while (processed < received) {

            hdr = (corsaro_tagged_packet_header_t *)(rcvspace + processed);

            if (worker_per_packet(tls, hdr, deadtrace) < 0) {
                break;
            }
            processed += hdr->pktlen + sizeof(corsaro_tagged_packet_header_t);
        }
    }

endworker:
    zmq_close(tls->zmq_pullsock);
    if (tls->pkts_outstanding > 0) {
        final_result = corsaro_push_end_plugins(tls->plugins,
                tls->current_interval.number, tls->last_ts, 0);
        if (push_interval_result(tls, final_result) < 0) {
            corsaro_log(tls->glob->logger,
                    "error while publishing results for final interval %u",
                    tls->current_interval.number);
        }

        if (push_rotate_output(tls, tls->next_report) < 0) {
            corsaro_log(tls->glob->logger,
                    "error while pushing rotate message after final interval %u",
                    tls->current_interval.number);
        }
    }

    push_stop_merging(tls);
    if (tls->plugins && corsaro_stop_plugins(tls->plugins) == -1) {
        corsaro_log(tls->glob->logger, "error while stopping plugins.");
    }

    free(rcvspace);
    trace_destroy_packet(tls->packet);
    trace_destroy_dead(deadtrace);
    zmq_close(tls->zmq_pushsock);
    pthread_exit(NULL);
}

static inline void *reconnect_taggersock(corsaro_trace_global_t *glob,
        void *current) {

    void *newsock = NULL;
    if (current) {
        zmq_close(current);
    }
    newsock = zmq_socket(glob->zmq_ctxt, ZMQ_REQ);
    if (zmq_connect(newsock, glob->control_uri) < 0) {
        corsaro_log(glob->logger, "unable to connect to corsarotagger control socket %s: %s",
                glob->control_uri, strerror(errno));
        zmq_close(newsock);
        return NULL;
    }
    return newsock;
}

static void process_mergeable_result(corsaro_trace_global_t *glob,
        corsaro_trace_merger_t *merge, corsaro_result_msg_t *msg) {

    corsaro_fin_interval_t *fin = merge->finished_intervals;
    corsaro_fin_interval_t *prev = NULL;

    if (glob->threads == 1) {
        corsaro_fin_interval_t quik;
        quik.interval_id = msg->interval_num;
        quik.timestamp = msg->interval_time;
        quik.threads_ended = 1;
        quik.next = NULL;
        quik.rotate_after = 0;
        quik.thread_plugin_data = (void ***)(calloc(glob->threads,
                    sizeof(void **)));
        quik.thread_plugin_data[0] = msg->plugindata;

        if (corsaro_merge_plugin_outputs(glob->logger, merge->pluginset,
                &quik, merge->zmq_taggersock) == CORSARO_MERGE_CONTROL_FAILURE)
        {
            merge->zmq_taggersock = reconnect_taggersock(glob,
                    merge->zmq_taggersock);
        }

        free(msg->plugindata);
        free(quik.thread_plugin_data);
        return;
    }

    while (fin != NULL) {
        if (fin->interval_id == msg->interval_num) {
            break;
        }
        prev = fin;
        fin = fin->next;
    }

    if (fin != NULL) {
        int i;

        fin->thread_plugin_data[fin->threads_ended] = msg->plugindata;
        fin->threads_ended ++;
        if (fin->threads_ended == glob->threads) {
            assert(fin == merge->finished_intervals);
            if (corsaro_merge_plugin_outputs(glob->logger, merge->pluginset,
                    fin, merge->zmq_taggersock) ==
                    CORSARO_MERGE_CONTROL_FAILURE) {
                merge->zmq_taggersock = reconnect_taggersock(glob,
                        merge->zmq_taggersock);
            }
            if (fin->rotate_after) {
                corsaro_rotate_plugin_output(glob->logger, merge->pluginset);
                merge->next_rotate_interval = msg->interval_num + 1;
            }
            merge->finished_intervals = fin->next;
            for (i = 0; i < glob->threads; i++) {
                free(fin->thread_plugin_data[i]);
            }
            free(fin->thread_plugin_data);
            free(fin);
        }
    } else {
        fin = (corsaro_fin_interval_t *)malloc(sizeof(corsaro_fin_interval_t));
        fin->interval_id = msg->interval_num;
        fin->timestamp = msg->interval_time;
        fin->threads_ended = 1;
        fin->next = NULL;
        fin->rotate_after = 0;
        fin->thread_plugin_data = (void ***)(calloc(glob->threads,
                sizeof(void **)));
        fin->thread_plugin_data[0] = msg->plugindata;

        if (prev) {
            prev->next = fin;
        } else {
            merge->finished_intervals = fin;
        }
    }

}

static void *start_merger(void *tdata) {
    corsaro_trace_merger_t *merge = (corsaro_trace_merger_t *)tdata;
    corsaro_trace_global_t *glob = merge->glob;
    corsaro_result_msg_t res;
    corsaro_fin_interval_t *fin;

    merge->zmq_pullsock = zmq_socket(glob->zmq_ctxt, ZMQ_PULL);
    merge->zmq_taggersock = reconnect_taggersock(glob, NULL);

    if (merge->zmq_taggersock == NULL) {
        goto endmerger;
    }

    if (zmq_bind(merge->zmq_pullsock, "inproc://pluginresults") != 0) {
        corsaro_log(glob->logger,
                "unable to bind pull socket for merger: %s",
                strerror(errno));
        goto endmerger;
    }

    merge->pluginset = corsaro_start_merging_plugins(glob->logger,
            glob->active_plugins, glob->plugincount, glob->threads);

    while (1) {
        if (zmq_recv(merge->zmq_pullsock, &res, sizeof(res), 0) < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }

            corsaro_log(glob->logger,
                    "error receiving message on merger pull socket: %s",
                    strerror(errno));
            break;
        }

        if (res.type == CORSARO_TRACE_MSG_STOP) {
            merge->stops_seen ++;
            if (merge->stops_seen == glob->threads) {
                break;
            }
        }
        else if (res.type == CORSARO_TRACE_MSG_ROTATE) {
            fin = merge->finished_intervals;

            if (fin == NULL && merge->next_rotate_interval <= res.interval_num) {
                corsaro_rotate_plugin_output(glob->logger, merge->pluginset);
                merge->next_rotate_interval = res.interval_num + 1;
                continue;
            }

            while (fin != NULL) {
                if (fin->interval_id == res.interval_num) {
                    fin->rotate_after = 1;
                    break;
                }
                fin = fin->next;
            }
        } else if (res.type == CORSARO_TRACE_MSG_MERGE) {
            process_mergeable_result(glob, merge, &res);
        }
    }
endmerger:
    while (merge->finished_intervals) {
        fin = merge->finished_intervals;

        if (corsaro_merge_plugin_outputs(glob->logger, merge->pluginset, fin,
                merge->zmq_taggersock) == CORSARO_MERGE_CONTROL_FAILURE) {
            if (merge->zmq_taggersock) {
                zmq_close(merge->zmq_taggersock);
            }
            merge->zmq_taggersock = NULL;
        }
        merge->finished_intervals = fin->next;
        free(fin);
    }

    if (merge->zmq_taggersock) {
       zmq_close(merge->zmq_taggersock);
    }
    corsaro_stop_plugins(merge->pluginset);
    pthread_exit(NULL);
}

void usage(char *prog) {
    printf("Usage: %s [ -l logmode ] -c configfile \n\n", prog);
    printf("Accepted logmodes:\n");
    printf("\tterminal\n\tfile\n\tsyslog\n\tdisabled\n");

}

static corsaro_trace_global_t *configure_corsaro(int argc, char *argv[]) {

    corsaro_trace_global_t *glob = NULL;
    char *configfile = NULL;
    char *logmodestr = NULL;
    struct sigaction sigact;
    int logmode = GLOBAL_LOGMODE_STDERR;

    /* Replaced old getopt-based nightmare with a proper YAML config file. */
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
                return NULL;
            default:
                fprintf(stderr, "corsarotrace: unsupported option: %c\n", c);
                usage(argv[0]);
                return NULL;
        }
    }

    if (configfile == NULL) {
        fprintf(stderr, "corsarotrace: no config file specified. Use -c to specify one.\n");
        usage(argv[0]);
        return NULL;
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
            fprintf(stderr, "corsarotrace: unexpected logmode: %s\n",
                    logmodestr);
            usage(argv[0]);
            return NULL;
        }
    }

    sigact.sa_handler = cleanup_signal;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    signal(SIGPIPE, SIG_IGN);

    glob = corsaro_trace_init_global(configfile, logmode);
    return glob;
}

int main(int argc, char *argv[]) {

    corsaro_trace_global_t *glob = NULL;
    int linger = 1000;
    sigset_t sig_before, sig_block_all;
    int i;
    corsaro_worker_msg_t halt;
    corsaro_trace_worker_t *workers;
    corsaro_trace_merger_t merger;
    libtrace_t *dummy;
    void *control_sock;
    corsaro_tagger_control_request_t ctrlreq;
    corsaro_tagger_control_reply_t ctrlreply;

    glob = configure_corsaro(argc, argv);
    if (glob == NULL) {
        return 1;
    }

    /* We need this to ensure libtrace initialises itself in a thread
     * safe way...
     */
    dummy = trace_create_dead("pcapfile");

    control_sock = zmq_socket(glob->zmq_ctxt, ZMQ_REQ);
    if (zmq_connect(control_sock, glob->control_uri) < 0) {
        corsaro_log(glob->logger, "unable to connect to corsarotagger control socket %s: %s", glob->control_uri, strerror(errno));
        goto endcorsarotrace;
    }

    ctrlreq.request_type = TAGGER_REQUEST_HELLO;
    ctrlreq.data.last_version = 0;

    if (zmq_send(control_sock, &ctrlreq, sizeof(ctrlreq), 0) < 0) {
        corsaro_log(glob->logger, "unable to send request to corsarotagger via control socket: %s", strerror(errno));
        goto endcorsarotrace;
    }

    if (zmq_recv(control_sock, &ctrlreply, sizeof(ctrlreply), 0) < 0) {
        corsaro_log(glob->logger, "unable to receive reply from corsarotagger via control socket: %s", strerror(errno));
        goto endcorsarotrace;
    }

    zmq_close(control_sock);
    corsaro_log(glob->logger, "corsarotagger is using %u hashbins",
            ctrlreply.hashbins);
    glob->max_hashbins = ctrlreply.hashbins;

    workers = calloc(glob->threads, sizeof(corsaro_trace_worker_t));

    for (i = 0; i < glob->threads; i++) {
        workers[i].glob = glob;
        workers[i].workerid = i;
        workers[i].taggerid = 0;
        /* XXX wasteful, but easier than having to use a hash map */
        workers[i].nextseq = calloc(glob->max_hashbins, sizeof(uint64_t));
        workers[i].dropcounter = 0;
        workers[i].dropinstances = 0;
    }

    merger.glob = glob;
    merger.stops_seen = 0;
    merger.next_rotate_interval = 0;
    merger.pluginset = NULL;
    merger.finished_intervals = NULL;

    sigemptyset(&sig_block_all);
    if (pthread_sigmask(SIG_SETMASK, &sig_block_all, &sig_before) < 0) {
        corsaro_log(glob->logger,
                "unable to disable signals before starting worker threads.");
        return 1;
    }

    for (i = 0; i < glob->threads; i++) {
        pthread_create(&(workers[i].threadid), NULL, start_worker,
                &(workers[i]));
    }

    pthread_create(&(merger.threadid), NULL, start_merger, &merger);

    if (pthread_sigmask(SIG_SETMASK, &sig_before, NULL) < 0) {
        corsaro_log(glob->logger,
                "unable to re-enable signals after starting worker threads.");
        return 1;
    }

    while (!corsaro_halted) {
        usleep(100);
    }

    for (i = 0; i < glob->threads; i++) {
        pthread_join(workers[i].threadid, NULL);
        free(workers[i].nextseq);
    }

    pthread_join(merger.threadid, NULL);
    if (merger.zmq_pullsock) {
        zmq_close(merger.zmq_pullsock);
    }
    free(workers);

    corsaro_log(glob->logger, "all threads have joined, exiting.");

endcorsarotrace:
    trace_destroy_dead(dummy);
    corsaro_trace_free_global(glob);

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
