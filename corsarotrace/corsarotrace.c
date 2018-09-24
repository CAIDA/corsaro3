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

#include "libcorsaro3_log.h"
#include "corsarotrace.h"
#include "libcorsaro3_plugin.h"
#include "libcorsaro3_filtering.h"
#include "taggedpacket.pb-c.h"

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

#if 0
static void publish_file_closed_message(libtrace_t *trace,
        libtrace_thread_t *t, uint32_t last_interval, uint32_t rotatets) {

    corsaro_trace_msg_t *msg = NULL;
    libtrace_generic_t topub;

    msg = (corsaro_trace_msg_t *)malloc(sizeof(corsaro_trace_msg_t));

    memset(msg, 0, sizeof(corsaro_trace_msg_t));
    msg->type = CORSARO_TRACE_MSG_ROTATE;
    msg->interval_num = last_interval;
    msg->interval_time = rotatets - 1;
    msg->plugindata = NULL;

    topub.ptr = msg;

    trace_publish_result(trace, t, ((uint64_t)rotatets) << 32, topub,
            RESULT_USER);

}

static void publish_interval_ended(libtrace_t *trace,
        libtrace_thread_t *t, uint32_t interval_num, uint32_t interval_ts,
        uint32_t endts, int plugincount, void **plugin_data) {

    corsaro_trace_msg_t *msg = NULL;
    libtrace_generic_t topub;

    msg = (corsaro_trace_msg_t *)malloc(sizeof(corsaro_trace_msg_t));

    memset(msg, 0, sizeof(corsaro_trace_msg_t));
    msg->type = CORSARO_TRACE_MSG_MERGE;
    msg->interval_num = interval_num;
    msg->interval_time = interval_ts;
    msg->plugindata = plugin_data;

    topub.ptr = msg;

    trace_publish_result(trace, t, ((uint64_t)endts) << 32, topub,
            RESULT_USER);

}

static void publish_stop_message(libtrace_t *trace, libtrace_thread_t *t,
        uint64_t ts) {

    corsaro_trace_msg_t *msg = NULL;
    libtrace_generic_t topub;

    msg = (corsaro_trace_msg_t *)malloc(sizeof(corsaro_trace_msg_t));
    memset(msg, 0, sizeof(corsaro_trace_msg_t));

    msg->type = CORSARO_TRACE_MSG_STOP;
    msg->interval_num = 0;
    msg->interval_time = 0;
    msg->plugindata = NULL;

    topub.ptr = msg;

    trace_publish_result(trace, t, ts, topub, RESULT_USER);
}

static inline int corsarotrace_interval_end(corsaro_logger_t *logger,
        libtrace_t *trace,
        libtrace_thread_t *t, corsaro_trace_local_t *tls, uint32_t ts) {
    void **interval_data;
    libtrace_stat_t *stats;
    interval_data = corsaro_push_end_plugins(tls->plugins,
            tls->current_interval.number, ts);

    if (interval_data == NULL) {
        corsaro_log(logger,
                "error while pushing 'end interval' to plugins.");
        return -1;
    } else {
        publish_interval_ended(trace, t, tls->current_interval.number,
                tls->current_interval.time, ts,
                tls->plugins->plugincount, interval_data);
    }
    stats = trace_create_statistics();
    trace_get_thread_statistics(trace, t, stats);

    corsaro_log(logger,
            "thread %d stats: %lu seen, %lu dropped, %lu missing",
            trace_get_perpkt_thread_id(t), stats->accepted,
            stats->dropped, stats->missing);
    free(stats);

    tls->pkts_outstanding = 0;
    return 0;
}


static void *init_trace_processing(libtrace_t *trace, libtrace_thread_t *t,
        void *global) {

    corsaro_trace_global_t *glob = (corsaro_trace_global_t *)global;
    corsaro_trace_local_t *tls;


    if (glob->currenturi == 0) {
        tls = (corsaro_trace_local_t *)malloc(
                sizeof(corsaro_trace_local_t));

        tls->plugins = corsaro_start_plugins(glob->logger,
                glob->active_plugins, glob->plugincount,
                trace_get_perpkt_thread_id(t));

        tls->next_report = 0;
        tls->current_interval.number = 0;
        tls->current_interval.time = 0;
        tls->pkts_outstanding = 0;
        tls->pkts_since_tick = 0;
        tls->last_ts = 0;
        tls->stopped = 0;
        tls->customfilters = corsaro_create_filters(glob->logger,
                glob->treefiltername);

        if (glob->taggingon) {
            tls->tagger = corsaro_create_packet_tagger(glob->logger,
                    glob->ipmeta);
            if (tls->tagger == NULL) {
                corsaro_log(glob->logger,
                        "out of memory while creating packet tagger.");
            }
       
            if (corsaro_enable_ipmeta_provider(tls->tagger,
                        glob->pfxipmeta) < 0) {
                corsaro_log(glob->logger,
                        "error while enabling prefix->asn tagging.");
            }

            if (corsaro_enable_ipmeta_provider(tls->tagger,
                        glob->maxmindipmeta) < 0) {
                corsaro_log(glob->logger,
                        "error while enabling Maxmind geo-location tags.");
            }

            if (corsaro_enable_ipmeta_provider(tls->tagger,
                        glob->netacqipmeta) < 0) {
                corsaro_log(glob->logger,
                        "error while enabling Netacq-Edge geo-location tags.");
            }
        } else {
            tls->tagger = NULL;
        }

        if (tls->plugins == NULL) {
            corsaro_log(glob->logger, "error while starting plugins.");
        }

    } else {
        tls = glob->savedlocalstate[trace_get_perpkt_thread_id(t)];
    }

    return tls;
}

static void halt_trace_processing(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *local) {
    corsaro_trace_global_t *glob = (corsaro_trace_global_t *)global;
    corsaro_trace_local_t *tls = (corsaro_trace_local_t *)local;

    /* -1 because we don't increment currenturi until all of the threads have
     * stopped for the trace, so current and total will never be equal at this
     * point.
     */
    if (glob->currenturi == glob->totaluris - 1) {
        if (tls->pkts_outstanding) {
            if (corsarotrace_interval_end(glob->logger, trace, t, tls,
                        tls->last_ts) == -1) {
                /* do something?? */
            }
        }

        if (corsaro_stop_plugins(tls->plugins) == -1) {
            corsaro_log(glob->logger, "error while stopping plugins.");
        }

        if (!tls->stopped) {
            publish_file_closed_message(trace, t, tls->current_interval.number,
                            tls->next_report);
        }
        corsaro_destroy_filters(tls->customfilters);
        corsaro_destroy_packet_tagger(tls->tagger);
        corsaro_log(glob->logger, "shut down trace processing thread %d",
                trace_get_perpkt_thread_id(t));
        free(tls);
    } else {
        glob->savedlocalstate[trace_get_perpkt_thread_id(t)] = tls;
    }
}

static libtrace_packet_t *per_packet(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *local, libtrace_packet_t *packet) {

    corsaro_trace_global_t *glob = (corsaro_trace_global_t *)global;
    corsaro_trace_local_t *tls = (corsaro_trace_local_t *)local;
    struct timeval tv, firsttv;
    const libtrace_packet_t *firstpkt;
    corsaro_packet_tags_t packettags;
    int ret;

    if (tls->stopped) {
        return packet;
    }

    tv = trace_get_timeval(packet);

    if (glob->boundstartts && tv.tv_sec < glob->boundstartts) {
        return packet;
    }

    if (glob->boundendts && tv.tv_sec >= glob->boundendts) {
        if (corsarotrace_interval_end(glob->logger, trace, t, tls,
                    glob->boundendts) == -1) {
            /* do something?? */
        }
        publish_file_closed_message(trace, t, tls->current_interval.number,
                glob->boundendts);
        publish_stop_message(trace, t, ((uint64_t)glob->boundendts) << 32);
        tls->stopped = 1;
        tls->pkts_outstanding = 0;
        return packet;
    }


    while (tls->current_interval.time == 0) {
        /* First non-ignored packet */
        if (glob->interval <= 0) {
            corsaro_log(glob->logger,
                    "interval has somehow been assigned a bad value of %u\n",
                    glob->interval);
            exit(1);
        }

        if ((ret = trace_get_first_packet(trace, NULL, &firstpkt, NULL)) == -1) {
            corsaro_log(glob->logger,
                    "unable to get first packet timestamp?");
            return packet;
        }

        if (ret == 0) {
            usleep(10);
            continue;
        }

        firsttv = trace_get_timeval(firstpkt);

        tls->current_interval.time = firsttv.tv_sec -
                (firsttv.tv_sec % glob->interval);
        tls->lastrotateinterval.time = tls->current_interval.time -
                (tls->current_interval.time %
                (glob->interval * glob->rotatefreq));
        corsaro_push_start_plugins(tls->plugins, tls->current_interval.number,
                tls->current_interval.time);

        tls->next_report = tls->current_interval.time + glob->interval;
        tls->next_rotate = tls->lastrotateinterval.time +
                (glob->interval * glob->rotatefreq);
    }

    if (tv.tv_sec < tls->current_interval.time) {
        return packet;
    }

    /* check if we have passed the end of an interval */
    while (tls->next_report && tv.tv_sec >= tls->next_report) {
        if (corsarotrace_interval_end(glob->logger, trace, t, tls,
                    tls->next_report) == -1) {
            /* do something?? */
        }
        if (glob->rotatefreq > 0 && tv.tv_sec >= tls->next_rotate) {
            publish_file_closed_message(trace, t, tls->current_interval.number,
                    tls->next_report);
            tls->next_rotate += (glob->interval * glob->rotatefreq);
        }
        tls->current_interval.number ++;
        tls->current_interval.time = tls->next_report;
        corsaro_push_start_plugins(tls->plugins, tls->current_interval.number,
            tls->current_interval.time);
        tls->next_report += glob->interval;
        tls->pkts_outstanding = 0;
    }

    if (glob->removespoofed &&
            corsaro_apply_spoofing_filter(glob->logger, packet)) {
        return packet;
    }

    if (glob->removeerratic && corsaro_apply_erratic_filter(glob->logger,
                packet)) {
        return packet;
    }

    if (glob->removerouted && corsaro_apply_routable_filter(glob->logger,
                packet)) {
        return packet;
    }

    tls->pkts_outstanding ++;
    tls->pkts_since_tick ++;
    tls->last_ts = tv.tv_sec;
    if (tls->tagger) {
        if (corsaro_tag_packet(tls->tagger, &packettags, packet) != 0) {
            corsaro_log(glob->logger,
                    "error while attempting to tag a packet.");
        }
        corsaro_push_packet_plugins(tls->plugins, packet, &packettags);
    } else {
        corsaro_push_packet_plugins(tls->plugins, packet, NULL);
    }

    return packet;
}

static void process_tick(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *local, uint64_t tick) {

    corsaro_trace_global_t *glob = (corsaro_trace_global_t *)global;
    corsaro_trace_local_t *tls = (corsaro_trace_local_t *)local;

    /* If we go an entire interval of real time without seeing a packet,
     * then the thread is probably not getting any packets. Let's force
     * an interval end here to try and keep things moving, otherwise
     * our merging thread is never going to do any work.
     *
     * NOTE: this is generally a bad state to be in -- if the ticks
     * are necessary, you really should be looking into another
     * hashing method that will distribute your packets more evenly
     * or reduce the number of threads that you're using to prevent
     * any from being idle.
     */

    if (tls->pkts_since_tick == 0) {
        if (corsarotrace_interval_end(glob->logger, trace, t, tls,
                    glob->boundendts) == -1) {
            /* do something?? */
        }
        if (glob->rotatefreq > 0 &&
                ((tls->current_interval.number + 1) % glob->rotatefreq) == 0) {
            publish_file_closed_message(trace, t, tls->current_interval.number,
                    tls->next_report);
        }
        tls->current_interval.number ++;
        tls->current_interval.time = tls->next_report;
        corsaro_push_start_plugins(tls->plugins, tls->current_interval.number,
            tls->current_interval.time);
        tls->next_report += glob->interval;
        tls->pkts_outstanding = 0;
        corsaro_log(glob->logger,
                "forced an interval to end within idle processing thread.");
    }

    tls->pkts_since_tick = 0;
}

static void *init_waiter(libtrace_t *trace, libtrace_thread_t *t,
        void *global) {

    corsaro_trace_global_t *glob = (corsaro_trace_global_t *)global;
    corsaro_trace_waiter_t *wait = (corsaro_trace_waiter_t *)malloc(
            sizeof(corsaro_trace_waiter_t));

    wait->stops_seen = 0;
    wait->finished_intervals = NULL;
    wait->next_rotate_interval = 0;
    wait->pluginset = corsaro_start_merging_plugins(glob->logger,
            glob->active_plugins, glob->plugincount, glob->threads);

    return wait;
}

static void halt_waiter(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *tls) {

    corsaro_trace_global_t *glob = (corsaro_trace_global_t *)global;
    corsaro_trace_waiter_t *wait = (corsaro_trace_waiter_t *)tls;

    corsaro_fin_interval_t *fin;

    while (wait->finished_intervals) {
        fin = wait->finished_intervals;

        corsaro_merge_plugin_outputs(glob->logger, wait->pluginset, fin);
        wait->finished_intervals = fin->next;
        free(fin);
    }

    corsaro_stop_plugins(wait->pluginset);

    free(wait);
    trace_halted = 1;
}

static void handle_trace_msg(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *tls, libtrace_result_t *result) {

    corsaro_trace_global_t *glob = (corsaro_trace_global_t *)global;
    corsaro_trace_waiter_t *wait = (corsaro_trace_waiter_t *)tls;
    corsaro_trace_msg_t *msg;

    if (result->type != RESULT_USER) {
        return;
    }

    msg = (corsaro_trace_msg_t *)result->value.ptr;

    if (msg->type == CORSARO_TRACE_MSG_STOP) {
        wait->stops_seen ++;
        if (wait->stops_seen == glob->threads) {
            trace_pstop(trace);
        }
    }

    if (msg->type == CORSARO_TRACE_MSG_ROTATE) {
        corsaro_fin_interval_t *fin = wait->finished_intervals;

        if (fin == NULL && wait->next_rotate_interval <= msg->interval_num) {
            corsaro_rotate_plugin_output(glob->logger, wait->pluginset);
            wait->next_rotate_interval = msg->interval_num + 1;
            free(msg);
            return;
        }

        while (fin != NULL) {
            if (fin->interval_id == msg->interval_num) {
                fin->rotate_after = 1;
                break;
            }
            fin = fin->next;
        }
        assert(fin != NULL);
    }

    if (msg->type == CORSARO_TRACE_MSG_MERGE) {
        corsaro_fin_interval_t *fin = wait->finished_intervals;
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

            corsaro_merge_plugin_outputs(glob->logger, wait->pluginset,
                    &quik);
            free(msg->plugindata);
            free(quik.thread_plugin_data);
            free(msg);
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
                assert(fin == wait->finished_intervals);
                corsaro_merge_plugin_outputs(glob->logger,
                        wait->pluginset, fin);
                if (fin->rotate_after) {
                    corsaro_rotate_plugin_output(glob->logger,
                            wait->pluginset);
                    wait->next_rotate_interval = msg->interval_num + 1;
                }
                wait->finished_intervals = fin->next;
                for (i = 0; i < glob->threads; i++) {
                    free(fin->thread_plugin_data[i]);
                }
                free(fin->thread_plugin_data);
                free(fin);
            }
        } else {
            fin = (corsaro_fin_interval_t *)malloc(
                    sizeof(corsaro_fin_interval_t));
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
                wait->finished_intervals = fin;
            }
        }
    }
    free(msg);

}

int start_trace_input(corsaro_trace_global_t *glob) {

    libtrace_generic_t nothing;
    nothing.ptr = NULL;

    glob->trace = trace_create(glob->inputuris[glob->currenturi]);
    if (trace_is_err(glob->trace)) {
        libtrace_err_t err = trace_get_err(glob->trace);
        corsaro_log(glob->logger, "unable to create trace object: %s",
                err.problem);
        return -1;
    }

    trace_set_reporter_thold(glob->trace, 1);
    if (glob->interval > 0) {
        trace_set_tick_interval(glob->trace, glob->interval * 1000);
    }

    trace_set_combiner(glob->trace, &combiner_unordered, nothing);
    if (glob->hasher_required) {
        trace_set_hasher(glob->trace, HASHER_BIDIRECTIONAL, glob->hasher,
                glob->hasher_data);
    }
    trace_set_perpkt_threads(glob->trace, glob->threads);

    if (glob->savedlocalstate == NULL) {
        glob->savedlocalstate = (corsaro_trace_local_t **)malloc(
                sizeof(corsaro_trace_local_t) * glob->threads);
    }

    if (!processing) {
        processing = trace_create_callback_set();
        trace_set_starting_cb(processing, init_trace_processing);
        trace_set_stopping_cb(processing, halt_trace_processing);
        trace_set_packet_cb(processing, per_packet);
        trace_set_tick_interval_cb(processing, process_tick);
    }

    if (!reporter) {
        reporter = trace_create_callback_set();
        trace_set_starting_cb(reporter, init_waiter);
        trace_set_stopping_cb(reporter, halt_waiter);
        trace_set_result_cb(reporter, handle_trace_msg);
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

    if (trace_pstart(glob->trace, glob, processing, reporter) == -1) {
        libtrace_err_t err = trace_get_err(glob->trace);
        corsaro_log(glob->logger, "unable to start reading from trace object: %s",
                err.problem);
        return -1;
    }

    corsaro_log(glob->logger, "successfully started input trace %s",
            glob->inputuris[glob->currenturi]);

    return 0;
}

#endif

static int worker_per_packet(corsaro_trace_worker_t *tls,
        libtrace_packet_t *packet, corsaro_packet_tags_t *ptags,
        TaggedPacket *tp) {


    if (tls->current_interval.time == 0) {

        /* Need a first ts to set our initial interval alignments, so skip
         * any packets that we receive before then.
         */
        if (!tp->has_first_ts) {
            return 0;
        }
        /* First non-ignored packet */
        if (tls->glob->interval <= 0) {
            corsaro_log(tls->glob->logger,
                    "interval has somehow been assigned a bad value of %u\n",
                    tls->glob->interval);
            return -1;
        }

        tls->current_interval.time = tp->first_ts - (tp->first_ts %
                tls->glob->interval);
        tls->lastrotateinterval.time = tls->current_interval.time -
                (tls->current_interval.time %
                (tls->glob->interval * tls->glob->rotatefreq));

        corsaro_push_start_plugins(tls->plugins, tls->current_interval.number,
                tls->current_interval.time);

        tls->next_report = tls->current_interval.time + tls->glob->interval;
        tls->next_rotate = tls->lastrotateinterval.time +
                (tls->glob->interval * tls->glob->rotatefreq);
    }

    if (tp->ts_sec < tls->current_interval.time) {
        return 0;
    }

    /* check if we have passed the end of an interval */
    while (tls->next_report && tp->ts_sec >= tls->next_report) {

        /* end interval TODO */

        if (tls->glob->rotatefreq > 0 && tp->ts_sec >= tls->next_rotate) {

            /* push rotate message TODO */
            tls->next_rotate += (tls->glob->interval * tls->glob->rotatefreq);
        }
        tls->current_interval.number ++;
        tls->current_interval.time = tls->next_report;
        corsaro_push_start_plugins(tls->plugins, tls->current_interval.number,
            tls->current_interval.time);
        tls->next_report += tls->glob->interval;
        tls->pkts_outstanding = 0;
    }

    tls->pkts_outstanding ++;
    tls->last_ts = tp->ts_sec;
    corsaro_push_packet_plugins(tls->plugins, packet, ptags);

}

static inline void reconstruct_packet_tags(TaggedPacket *tp,
        corsaro_packet_tags_t *ptags, corsaro_logger_t *logger) {

    int i;

    ptags->highlevelfilterbits = 0;
    ptags->ft_hash = tp->flowhash;
    ptags->providers_used = 0;

    for (i = 0; i < tp->n_tags; i++) {
        switch(tp->tags[i]->tagid) {
            case CORSARO_TAGID_NETACQ_REGION:
                ptags->netacq_region = tp->tags[i]->tagval;
                ptags->providers_used |= (1 << IPMETA_PROVIDER_NETACQ_EDGE);
                break;
            case CORSARO_TAGID_NETACQ_POLYGON:
                ptags->netacq_polygon = tp->tags[i]->tagval;
                ptags->providers_used |= (1 << IPMETA_PROVIDER_NETACQ_EDGE);
                break;
            case CORSARO_TAGID_NETACQ_COUNTRY:
                ptags->netacq_country = tp->tags[i]->tagval;
                ptags->providers_used |= (1 << IPMETA_PROVIDER_NETACQ_EDGE);
                break;
            case CORSARO_TAGID_NETACQ_CONTINENT:
                ptags->netacq_continent = tp->tags[i]->tagval;
                ptags->providers_used |= (1 << IPMETA_PROVIDER_NETACQ_EDGE);
                break;
            case CORSARO_TAGID_MAXMIND_COUNTRY:
                ptags->maxmind_country = tp->tags[i]->tagval;
                ptags->providers_used |= (1 << IPMETA_PROVIDER_MAXMIND);
                break;
            case CORSARO_TAGID_MAXMIND_CONTINENT:
                ptags->maxmind_continent = tp->tags[i]->tagval;
                ptags->providers_used |= (1 << IPMETA_PROVIDER_MAXMIND);
                break;
            case CORSARO_TAGID_PREFIXASN:
                ptags->prefixasn = tp->tags[i]->tagval;
                ptags->providers_used |= (1 << IPMETA_PROVIDER_PFX2AS);
                break;
            case CORSARO_TAGID_SOURCEPORT:
                ptags->src_port = tp->tags[i]->tagval;
                ptags->providers_used |= (1);
                break;
            case CORSARO_TAGID_DESTPORT:
                ptags->dest_port = tp->tags[i]->tagval;
                ptags->providers_used |= (1);
                break;
            case CORSARO_TAGID_PROTOCOL:
                ptags->protocol = tp->tags[i]->tagval;
                ptags->providers_used |= (1);
                break;
            default:
                corsaro_log(logger,
                        "unexpected tag ID %u -- ignoring", tp->tags[i]->tagid);
                break;
        }
    }
}

static inline void fast_construct_packet(libtrace_t *deadtrace,
        libtrace_packet_t *packet, TaggedPacket *tp, uint16_t *packetbufsize)
{

    /* Clone of trace_construct_packet() but designed to minimise
     * memory reallocations.
     */
    pcaphdr_t pcaphdr;

    pcaphdr.ts_sec = tp->ts_sec;
    pcaphdr.ts_usec = tp->ts_usec;
    pcaphdr.caplen = tp->pktlen;
    pcaphdr.wirelen = tp->pktlen;

    packet->trace = deadtrace;
    if (*packetbufsize < tp->pktlen + sizeof(pcaphdr)) {
        packet->buffer = realloc(packet->buffer, tp->pktlen + sizeof(pcaphdr));
        *packetbufsize = tp->pktlen + sizeof(pcaphdr);
    }

    packet->buf_control = TRACE_CTRL_PACKET;
    packet->header = packet->buffer;
    packet->payload = ((char *)(packet->buffer) + sizeof(pcaphdr));

    memcpy(packet->payload, tp->pktcontent.data, tp->pktlen);
    memcpy(packet->header, &pcaphdr, sizeof(pcaphdr));
    packet->type = TRACE_RT_DATA_DLT + TRACE_DLT_EN10MB;

    packet->l2_header = packet->payload;
    packet->l3_header = NULL;
    packet->l4_header = NULL;
    packet->link_type = TRACE_TYPE_ETH;
    packet->l3_ethertype = 0;
    packet->transport_proto = 0;
    packet->capture_length = tp->pktlen;
    packet->wire_length = tp->pktlen;
    packet->payload_length = -1;
    packet->l2_remaining = tp->pktlen;
    packet->l3_remaining = 0;
    packet->l4_remaining = 0;
    packet->refcount = 0;

}

static void *start_worker(void *tdata) {

    corsaro_trace_worker_t *tls = (corsaro_trace_worker_t *)tdata;
    corsaro_worker_msg_t incoming;
    char sockname[30];
    libtrace_t *deadtrace = NULL;
    libtrace_packet_t *packet = NULL;
    uint64_t packetsseen = 0;
    uint16_t pktalloc = 0;
    corsaro_packet_tags_t ptags;

    deadtrace = trace_create_dead("pcapfile");
    packet = trace_create_packet();

    assert(deadtrace && packet);

    snprintf(sockname, 30, "inproc://worker%d", tls->workerid);
    tls->zmq_pullsock = zmq_socket(tls->glob->zmq_ctxt, ZMQ_PULL);
    if (zmq_connect(tls->zmq_pullsock, sockname) < 0) {
        corsaro_log(tls->glob->logger,
                "error while connecting to worker %d pull socket: %s",
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

    while (1) {
        if (zmq_recv(tls->zmq_pullsock, &incoming, sizeof(incoming), 0) < 0) {
            corsaro_log(tls->glob->logger,
                    "error receiving message on worker %d pull socket: %s",
                    tls->workerid, strerror(errno));
            break;
        }

        if (incoming.type == CORSARO_TRACE_MSG_STOP) {
            break;
        }

        if (incoming.type != CORSARO_TRACE_MSG_PACKET) {
            corsaro_log(tls->glob->logger,
                    "received invalid message type %d on worker %d pull socket",
                    incoming.type, tls->workerid);
            break;
        }
        packetsseen ++;
        fast_construct_packet(deadtrace, packet, incoming.tp, &pktalloc);
        reconstruct_packet_tags(incoming.tp, &ptags, tls->glob->logger);

        if (tls->glob->boundstartts && incoming.tp->ts_sec <
                    tls->glob->boundstartts) {
            tagged_packet__free_unpacked(incoming.tp, NULL);
            continue;
        }

        if (tls->glob->boundendts && incoming.tp->ts_sec >=
                tls->glob->boundendts) {
            /* push end interval message for glob->boundendts TODO */

            /* push close file message for interval and boundendts TODO */
            tagged_packet__free_unpacked(incoming.tp, NULL);
            break;
        }

        if (worker_per_packet(tls, packet, &ptags, incoming.tp) < 0) {
            corsaro_log(tls->glob->logger,
                    "error while processing received packet in worker %d",
                    tls->workerid);
            tagged_packet__free_unpacked(incoming.tp, NULL);
            break;
        }
/*
        printf("%u  %u.%u  %u %u %lu\n", filttags, tp->ts_sec, tp->ts_usec,
                tp->pktlen, tp->flowhash, tp->n_tags);
        for (i = 0; i < tp->n_tags; i++) {
            printf("    %u = %u\n", tp->tags[i]->tagid, tp->tags[i]->tagval);
        }
*/
        tagged_packet__free_unpacked(incoming.tp, NULL);
    }

endworker:
    if (tls->plugins && corsaro_stop_plugins(tls->plugins) == -1) {
        corsaro_log(tls->glob->logger, "error while stopping plugins.");
    }

    trace_destroy_packet(packet);
    trace_destroy_dead(deadtrace);
    zmq_close(tls->zmq_pullsock);
    printf("worker thread %d saw %lu packets\n", tls->workerid, packetsseen);
    pthread_exit(NULL);
}

static int receive_tagged_packet(corsaro_trace_global_t *glob) {

    /* TODO receive message, decode it, forward to an appropriate worker */
    zmq_msg_t zmsg;
    zmq_msg_init(&zmsg);
    uint16_t filttags = 1000;
    int rcvsize, i;
    char *rcvspace;
    TaggedPacket *tp;
    corsaro_worker_msg_t jobmsg;

    if (zmq_msg_recv(&zmsg, glob->zmq_subsock, 0) < 0) {
        corsaro_log(glob->logger,
                "error while receiving message from sub socket: %s",
                strerror(errno));
        return -1;
    }

    if (zmq_msg_size(&zmsg) != sizeof(filttags)) {
        corsaro_log(glob->logger,
                "unexpected item received on sub socket, was expecting filter tags");
        return -1;
    }

    filttags = ntohs(*(uint16_t *)zmq_msg_data(&zmsg));
    zmq_msg_close(&zmsg);

    zmq_msg_init(&zmsg);
    if (zmq_msg_recv(&zmsg, glob->zmq_subsock, 0) < 0) {
        corsaro_log(glob->logger,
                "error while receiving message from sub socket: %s",
                strerror(errno));
        return -1;
    }

    rcvsize = zmq_msg_size(&zmsg);
    rcvspace = (char *)zmq_msg_data(&zmsg);

    tp = tagged_packet__unpack(NULL, rcvsize, rcvspace);
    if (tp == NULL) {
        corsaro_log(glob->logger,
                "error while unpacking message received from sub socket");
        return -1;
    }

    jobmsg.type = CORSARO_TRACE_MSG_PACKET;
    jobmsg.tp = tp;

    if (zmq_send(glob->zmq_workersocks[tp->flowhash % glob->threads],
            &jobmsg, sizeof(jobmsg), 0) < 0) {
        corsaro_log(glob->logger,
                "error while pushing tagged packet to worker thread %d: %s",
                tp->flowhash % glob->threads, strerror(errno));
        return -1;
    }

    zmq_msg_close(&zmsg);

    return 0;
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

static inline int subscribe_streams(corsaro_trace_global_t *glob) {

    uint8_t tosub[8];
    int i;
    uint16_t subbytes;

    memset(tosub, 1, sizeof(uint8_t) * 8);

    /* If nothing is removed, then subscribe to everything */
    if (glob->removespoofed == 0 && glob->removeerratic == 0 &&
            glob->removerouted == 0) {

        if (zmq_setsockopt(glob->zmq_subsock, ZMQ_SUBSCRIBE, "", 0) < 0) {
            corsaro_log(glob->logger,
                    "unable to subscribe to all streams of tagged packets: %s",
                    strerror(errno));
            return -1;
        }
        return 0;
    }

    for (i = 0; i < 8; i++) {
        if ((i & CORSARO_FILTERBIT_ERRATIC) && glob->removeerratic) {
            tosub[i] = 0;
        }
        if ((i & CORSARO_FILTERBIT_SPOOFED) && glob->removespoofed) {
            tosub[i] = 0;
        }
        if ((i & CORSARO_FILTERBIT_NONROUTABLE) == 0 && glob->removerouted) {
            tosub[i] = 0;
        }

        if (tosub[i]) {
            subbytes = htons((uint16_t)i);
            if (zmq_setsockopt(glob->zmq_subsock, ZMQ_SUBSCRIBE, &subbytes,
                    sizeof(subbytes)) < 0) {
                corsaro_log(glob->logger,
                        "unable to subscribe to stream of tagged packets: %s",
                        strerror(errno));
                return -1;
            }
        }
    }
    return 0;

}

int main(int argc, char *argv[]) {

    corsaro_trace_global_t *glob = NULL;
    int hwm = 100000;
    int linger = 1000;
    sigset_t sig_before, sig_block_all;
    int i;
    corsaro_worker_msg_t halt;
    corsaro_trace_worker_t *workers;
    zmq_pollitem_t pollitems[1];

    glob = configure_corsaro(argc, argv);
    if (glob == NULL) {
        return 1;
    }

    glob->zmq_workersocks = calloc(glob->threads, sizeof(void *));
    workers = calloc(glob->threads, sizeof(corsaro_trace_worker_t));

    for (i = 0; i < glob->threads; i++) {
        char sockname[30];
        glob->zmq_workersocks[i] = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
        snprintf(sockname, 30, "inproc://worker%d", i);
        if (zmq_bind(glob->zmq_workersocks[i], sockname) != 0) {
            corsaro_log(glob->logger,
                    "unable to bind push socket for worker %d: %s", i,
                    strerror(errno));
            return 1;
        }

        if (zmq_setsockopt(glob->zmq_workersocks[i], ZMQ_SNDHWM, &hwm,
                sizeof(hwm)) < 0) {
            corsaro_log(glob->logger,
                    "unable to set HWM for push socket for worker %d: %s", i,
                    strerror(errno));
            return 1;
        }

        workers[i].glob = glob;
        workers[i].workerid = i;
    }

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

    if (pthread_sigmask(SIG_SETMASK, &sig_before, NULL) < 0) {
        corsaro_log(glob->logger,
                "unable to re-enable signals after starting worker threads.");
        return 1;
    }

    glob->zmq_subsock = zmq_socket(glob->zmq_ctxt, ZMQ_SUB);
    if (zmq_bind(glob->zmq_subsock, glob->subqueuename) < 0) {
        corsaro_log(glob->logger,
                "unable to bind to socket for receiving tagged packets: %s",
                strerror(errno));
        return 1;
    }

    /* subscribe to the desired packet streams, based on our filter options */
    if (subscribe_streams(glob) < 0) {
        return 1;
    }

    pollitems[0].socket = glob->zmq_subsock;
    pollitems[0].fd = 0;
    pollitems[0].events = ZMQ_POLLIN;
    pollitems[0].revents = 0;

    while (!corsaro_halted) {
        /* poll our sub socket */
        if (zmq_poll(pollitems, 1, 1000) < 0) {
            corsaro_log(glob->logger,
                    "error while polling socket for incoming tagged packets");
            break;
        }

        if (pollitems[0].revents == ZMQ_POLLIN) {
            if (receive_tagged_packet(glob) < 0) {
                break;
            }
        }

    }

    halt.type = CORSARO_TRACE_MSG_STOP;
    halt.tp = NULL;

    for (i = 0; i < glob->threads; i++) {

        if (zmq_send(glob->zmq_workersocks[i], &halt, sizeof(halt), 0) < 0) {
            corsaro_log(glob->logger, "error sending halt message to worker %d",
                    i);
            return 1;
        }

        pthread_join(workers[i].threadid, NULL);
        zmq_setsockopt(glob->zmq_workersocks[i], ZMQ_LINGER, &linger,
                sizeof(linger));
        zmq_close(glob->zmq_workersocks[i]);
    }

    zmq_close(glob->zmq_subsock);
    free(glob->zmq_workersocks);
    free(workers);

    corsaro_log(glob->logger, "all threads have joined, exiting.");
    corsaro_trace_free_global(glob);

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
