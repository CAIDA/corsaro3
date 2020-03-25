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

typedef struct pcaphdr_t {
    uint32_t ts_sec;        /* Seconds portion of the timestamp */
    uint32_t ts_usec;       /* Microseconds portion of the timestamp */
    uint32_t caplen;        /* Capture length of the packet */
    uint32_t wirelen;       /* The wire length of the packet */
} pcaphdr_t;


volatile int corsaro_halted = 0;

libtrace_t *inputtrace = NULL;

static void cleanup_signal(int sig) {
    (void)sig;
    corsaro_halted = 1;
    trace_pstop(inputtrace);
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

static int push_interval_result(corsaro_logger_t *logger,
		corsaro_trace_worker_t *tls, void **result) {

    corsaro_result_msg_t res;

    res.type = CORSARO_TRACE_MSG_MERGE;
    res.source = tls->workerid;
    res.interval_num = tls->current_interval.number;
    res.interval_time = tls->current_interval.time;
    res.plugindata = result;

    if (zmq_send(tls->zmq_pushsock, &res, sizeof(res), 0) < 0) {
        corsaro_log(logger,
                "error while pushing result from worker %d: %s",
                tls->workerid, strerror(errno));
        return -1;
    }

    return 0;
}

static int push_rotate_output(corsaro_logger_t *logger,
		corsaro_trace_worker_t *tls, uint32_t ts) {

    corsaro_result_msg_t res;

    res.type = CORSARO_TRACE_MSG_ROTATE;
    res.source = tls->workerid;
    res.interval_num = tls->current_interval.number;
    res.interval_time = ts;
    res.plugindata = NULL;

    if (zmq_send(tls->zmq_pushsock, &res, sizeof(res), 0) < 0) {
        corsaro_log(logger,
                "error while pushing result from worker %d: %s",
                tls->workerid, strerror(errno));
        return -1;
    }

    return 0;
}

static int push_stop_merging(corsaro_logger_t *logger,
		corsaro_trace_worker_t *tls) {

    corsaro_result_msg_t res;

    res.type = CORSARO_TRACE_MSG_STOP;
    res.source = tls->workerid;
    res.interval_num = tls->current_interval.number;
    res.interval_time = 0;
    res.plugindata = NULL;

    if (zmq_send(tls->zmq_pushsock, &res, sizeof(res), 0) < 0) {
        corsaro_log(logger,
                "error while pushing stop from worker %d: %s",
                tls->workerid, strerror(errno));
        return -1;
    }

    return 0;
}

static libtrace_packet_t * per_packet(libtrace_t *trace,
		libtrace_thread_t *t, void *global, void *local,
		libtrace_packet_t *packet) {

	corsaro_trace_worker_t *tls = (corsaro_trace_worker_t *)local;
	corsaro_trace_global_t *glob = (corsaro_trace_global_t *)global;
    corsaro_packet_tags_t *tags;
    corsaro_tagged_packet_header_t *taghdr;
	void **interval_data;
    void **final_result;
    uint16_t fbits = 0;

	libtrace_linktype_t linktype;
	uint32_t remaining;
	uint32_t ts;

	/* naughty to use ->header directly, but it's ok because I'm doing it */
	taghdr = (corsaro_tagged_packet_header_t *)(packet->header);
    corsaro_update_tagged_loss_tracker(tls->tracker, taghdr);

	if (tls->stopped) {
		return packet;
	}

	tags = trace_get_packet_meta(packet, &linktype, &remaining);
	if (tags == NULL || remaining < sizeof(corsaro_packet_tags_t)) {
		return packet;
	}

    if (linktype != TRACE_TYPE_CORSAROTAG) {
        tags = NULL;
    }

	ts = ntohl(taghdr->ts_sec);
    if (glob->boundstartts && ts < glob->boundstartts) {
        return packet;
    }

    if (glob->boundendts && ts >= glob->boundendts) {
        /* push end interval message for glob->boundendts */
        final_result = corsaro_push_end_plugins(tls->plugins,
                tls->current_interval.number, glob->boundendts, 0);

        if (push_interval_result(glob->logger, tls, final_result) < 0) {
            corsaro_log(glob->logger,
                    "error while publishing results for final interval %u",
                    tls->current_interval.number);
        }

        /* push close file message for interval and boundendts */
        if (push_rotate_output(glob->logger, tls, glob->boundendts) < 0) {
            corsaro_log(glob->logger,
                    "error while pushing rotate message after final interval %u",
                    tls->current_interval.number);
        }
		tls->stopped = 1;
        return packet;
    }

    if (tls->current_interval.time == 0) {

        if (tls->first_pkt_ts == 0) {
            tls->first_pkt_ts = ts;
            pthread_mutex_lock(&(glob->mutex));
            if (tls->first_pkt_ts < glob->first_pkt_ts ||
                    glob->first_pkt_ts == 0) {
                glob->first_pkt_ts = tls->first_pkt_ts;
            }
            pthread_mutex_unlock(&(glob->mutex));
        }

        /* First non-ignored packet */
        if (glob->interval <= 0) {
            corsaro_log(glob->logger,
                    "interval has somehow been assigned a bad value of %u\n",
                    glob->interval);
			tls->stopped = 1;
            return packet;
        }

        pthread_mutex_lock(&(glob->mutex));
        tls->current_interval.time = glob->first_pkt_ts;
        pthread_mutex_unlock(&(glob->mutex));
        tls->lastrotateinterval.time = tls->current_interval.time -
                (tls->current_interval.time %
                (glob->interval * glob->rotatefreq));

        corsaro_push_start_plugins(tls->plugins, tls->current_interval.number,
                tls->current_interval.time);

        tls->next_report = tls->current_interval.time -
                (tls->current_interval.time % glob->interval) +
                 glob->interval;
        tls->next_rotate = tls->lastrotateinterval.time +
                (glob->interval * glob->rotatefreq);
    }

    if (ts < tls->current_interval.time) {
        tls->pkts_from_prev_interval ++;
        return packet;
    }

    /* check if we have passed the end of an interval */
    while (tls->next_report && ts >= tls->next_report) {
        uint8_t complete = 0;
        /* end interval */
        if (tls->next_report - tls->current_interval.time == glob->interval) {
            complete = 1;
        } else {
            complete = 0;
        }
        interval_data = corsaro_push_end_plugins(tls->plugins,
                tls->current_interval.number, tls->next_report, complete);

        if (push_interval_result(glob->logger, tls, interval_data) < 0) {
            corsaro_log(glob->logger,
                    "error while publishing results for interval %u",
                    tls->current_interval.number);
			tls->stopped = 1;
            return packet;
        }

        if (tls->tracker->lostpackets > 0) {
            corsaro_log(glob->logger,
                    "warning: worker thread %d has observed %lu packets dropped by the tagger in the past interval (%u instances) -- %lu",
                    tls->workerid,
                    tls->tracker->lostpackets, tls->tracker->lossinstances,
                    tls->tracker->packetsreceived);
        }
        corsaro_reset_tagged_loss_tracker(tls->tracker);

        if (glob->rotatefreq > 0 && ts >= tls->next_rotate) {

            /* push rotate message */
            if (push_rotate_output(glob->logger, tls, tls->next_report) < 0) {
                corsaro_log(glob->logger,
                        "error while pushing rotate message after interval %u",
                        tls->current_interval.number);
				tls->stopped = 1;
                return packet;
            }
            tls->next_rotate += (glob->interval * glob->rotatefreq);
        }

        tls->current_interval.number ++;
        tls->current_interval.time = tls->next_report;
        corsaro_push_start_plugins(tls->plugins, tls->current_interval.number,
            tls->current_interval.time);
        tls->next_report += glob->interval;
        tls->pkts_outstanding = 0;

        if (tls->pkts_from_prev_interval > 0) {
            corsaro_log(glob->logger, "worker thread %d has observed %u packets from previous interval during interval %u",
                    tls->workerid, tls->pkts_from_prev_interval,
                    tls->current_interval.number - 1);
            tls->pkts_from_prev_interval = 0;
        }
    }

    fbits = ntohs(taghdr->filterbits);
    if (glob->removenotscan && !(fbits & CORSARO_FILTERBIT_LARGE_SCALE_SCAN)) {
        goto filtered;
    }

    if (glob->removespoofed && (fbits & CORSARO_FILTERBIT_SPOOFED)) {
        goto filtered;
    }

    if (glob->removeerratic && (fbits & CORSARO_FILTERBIT_ERRATIC)) {
        goto filtered;
    }

    if (glob->removerouted && !(fbits & CORSARO_FILTERBIT_NONROUTABLE)) {
        goto filtered;
    }

    tls->pkts_outstanding ++;
    tls->last_ts = ts;
    corsaro_push_packet_plugins(tls->plugins, packet, tags);

    return packet;

filtered:
    return packet;
}
static void *init_corsarotrace_worker(libtrace_t *trace, libtrace_thread_t *t,
		void *global) {

    corsaro_trace_worker_t *tls;
	corsaro_trace_global_t *glob = (corsaro_trace_global_t *)global;

	tls = calloc(1, sizeof(corsaro_trace_worker_t));
	tls->workerid = trace_get_perpkt_thread_id(t);
	tls->tracker = corsaro_create_tagged_loss_tracker(glob->threads);

    tls->zmq_pushsock = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
    if (zmq_connect(tls->zmq_pushsock, "inproc://pluginresults") < 0) {
        corsaro_log(glob->logger,
                "error while connecting worker %d to result socket: %s",
                tls->workerid, strerror(errno));
		tls->stopped = 1;
		return tls;
    }

    tls->plugins = corsaro_start_plugins(glob->logger,
            glob->active_plugins, glob->plugincount,
            tls->workerid);

    if (tls->plugins == NULL) {
        corsaro_log(glob->logger, "worker %d unable to start plugins.",
                tls->workerid);
		tls->stopped = 1;
    }

	return tls;
}

static void halt_corsarotrace_worker(libtrace_t *trace, libtrace_thread_t *t,
		void *global, void *local) {

	corsaro_trace_worker_t *tls = (corsaro_trace_worker_t *)local;
	corsaro_trace_global_t *glob = (corsaro_trace_global_t *)global;
    void **final_result;

    if (tls->pkts_outstanding > 0) {
        final_result = corsaro_push_end_plugins(tls->plugins,
                tls->current_interval.number, tls->last_ts, 0);
        if (push_interval_result(glob->logger, tls, final_result) < 0) {
            corsaro_log(glob->logger,
                    "error while publishing results for final interval %u",
                    tls->current_interval.number);
        }

        if (push_rotate_output(glob->logger, tls, tls->next_report) < 0) {
            corsaro_log(glob->logger,
                    "error while pushing rotate message after final interval %u",
                    tls->current_interval.number);
        }
    }

    push_stop_merging(glob->logger, tls);
    if (tls->plugins && corsaro_stop_plugins(tls->plugins) == -1) {
        corsaro_log(glob->logger, "error while stopping plugins.");
    }

    zmq_close(tls->zmq_pushsock);
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
    sigset_t sig_before, sig_block_all;
    int i;
    corsaro_trace_merger_t merger;
    void *control_sock = NULL;
    corsaro_tagger_control_request_t ctrlreq;
    corsaro_tagger_control_reply_t ctrlreply;
	libtrace_stat_t *stats;
	libtrace_callback_set_t *processing = NULL;
    corsaro_plugin_proc_options_t stdopts;

    glob = configure_corsaro(argc, argv);
    if (glob == NULL) {
        return 1;
    }

    control_sock = zmq_socket(glob->zmq_ctxt, ZMQ_REQ);
    if (zmq_connect(control_sock, glob->control_uri) < 0) {
        corsaro_log(glob->logger, "unable to connect to corsarotagger control socket %s: %s", glob->control_uri, strerror(errno));
        goto endcorsarotrace;
    }

    ctrlreq.request_type = TAGGER_REQUEST_HELLO;
    ctrlreq.data.last_version = 0;

    corsaro_log(glob->logger, "waiting for message from tagger control socket...");
    if (zmq_send(control_sock, &ctrlreq, sizeof(ctrlreq), 0) < 0) {
        corsaro_log(glob->logger, "unable to send request to corsarotagger via control socket: %s", strerror(errno));
        goto endcorsarotrace;
    }

    if (zmq_recv(control_sock, &ctrlreply, sizeof(ctrlreply), 0) < 0) {
        corsaro_log(glob->logger, "unable to receive reply from corsarotagger via control socket: %s", strerror(errno));
        goto endcorsarotrace;
    }

    zmq_close(control_sock);
    control_sock = NULL;
    corsaro_log(glob->logger, "corsarotagger is using %u tagger threads",
            ctrlreply.hashbins);
    glob->threads = ctrlreply.hashbins;

    stdopts.template = glob->template;
    stdopts.monitorid = glob->monitorid;
    stdopts.procthreads = glob->threads;
    stdopts.libtsascii = &(glob->libtsascii);
    stdopts.libtskafka = &(glob->libtskafka);
    stdopts.libtsdbats = &(glob->libtsdbats);

    if (corsaro_finish_plugin_config(glob->active_plugins, &stdopts,
                glob->zmq_ctxt) < 0) {
        corsaro_log(glob->logger,
                "error while finishing plugin configuration. Exiting.");
        goto endcorsarotrace;
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

    pthread_create(&(merger.threadid), NULL, start_merger, &merger);

    if (pthread_sigmask(SIG_SETMASK, &sig_before, NULL) < 0) {
        corsaro_log(glob->logger,
                "unable to re-enable signals after starting worker threads.");
        return 1;
    }

    inputtrace = trace_create(glob->source_uri);
    if (trace_is_err(inputtrace)) {
        libtrace_err_t err = trace_get_err(inputtrace);
        corsaro_log(glob->logger, "unable to create trace object: %s",
                err.problem);
        return -1;
    }

    trace_set_perpkt_threads(inputtrace, glob->threads);

    processing = trace_create_callback_set();
    trace_set_starting_cb(processing, init_corsarotrace_worker);
    trace_set_stopping_cb(processing, halt_corsarotrace_worker);
    trace_set_packet_cb(processing, per_packet);

    /*
     * TODO
    if (glob->filterstring) {

    }
     */

    if (trace_pstart(inputtrace, glob, processing, NULL) == -1) {
        libtrace_err_t err = trace_get_err(inputtrace);
        corsaro_log(glob->logger, "unable to start reading from trace object: %s",
                err.problem);
        return -1;
    }

    trace_join(inputtrace);
	stats = trace_get_statistics(inputtrace, NULL);
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

    pthread_join(merger.threadid, NULL);
    if (merger.zmq_pullsock) {
        zmq_close(merger.zmq_pullsock);
    }

    corsaro_log(glob->logger, "all threads have joined, exiting.");

endcorsarotrace:
    if (control_sock) {
        zmq_close(control_sock);
    }
	if (inputtrace) {
		trace_destroy(inputtrace);
	}
	if (processing) {
		trace_destroy_callback_set(processing);
	}

    corsaro_trace_free_global(glob);

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
