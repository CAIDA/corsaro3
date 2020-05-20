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

#ifndef CORSAROTRACE_H_
#define CORSAROTRACE_H_

#include <libtrace.h>
#include <libtrace_parallel.h>
#include <libtrace/message_queue.h>

#include "libcorsaro.h"
#include "libcorsaro_log.h"
#include "libcorsaro_plugin.h"
#include "libcorsaro_filtering.h"
#include "libcorsaro_tagging.h"
#include "libcorsaro_libtimeseries.h"

#define INTERNAL_ZMQ_CONTROL_URI "inproc://corsarotrace_ipmeta"

enum {
    CORSARO_TRACE_MSG_MERGE = 0,
    CORSARO_TRACE_MSG_STOP = 1,
    CORSARO_TRACE_MSG_ROTATE = 2,
    CORSARO_TRACE_MSG_PACKET = 3,
};

enum {
    CORSARO_TRACE_SOURCE_FANNER,
    CORSARO_TRACE_SOURCE_TAGGER
};

typedef struct corsaro_worker_msg {
    uint8_t type;
    corsaro_tagged_packet_header_t header;
    uint8_t *packetcontent;
} corsaro_worker_msg_t;

typedef struct corsaro_result_msg {
    uint8_t type;
    uint8_t source;
    uint32_t interval_num;
    uint32_t interval_time;
    void **plugindata;
} corsaro_result_msg_t;

typedef struct corsaro_trace_worker corsaro_trace_worker_t;
typedef struct corsaro_trace_merger corsaro_trace_merger_t;

typedef struct corsaro_trace_glob {
    corsaro_plugin_t *active_plugins;
    corsaro_logger_t *logger;
    char *template;
    char *logfilename;
    char *statfilename;
    char *source_uri;
    char *filterstring;
    char *monitorid;
    char *control_uri;

    libts_ascii_backend_t libtsascii;
    libts_kafka_backend_t libtskafka;
    libts_dbats_backend_t libtsdbats;

    pthread_mutex_t mutex;
    uint32_t first_pkt_ts;
    uint32_t boundstartts;
    uint32_t boundendts;
    uint32_t interval;
    uint32_t rotatefreq;

    uint8_t subsource;
    uint8_t logmode;
    uint8_t threads;
    uint8_t plugincount;

    uint8_t removespoofed;
    uint8_t removeerratic;
    uint8_t removerouted;
    uint8_t removenotscan;

    void *zmq_ctxt;

    corsaro_ipmeta_state_t *ipmeta_state;
    pfx2asn_opts_t pfxtagopts;
    maxmind_opts_t maxtagopts;
    netacq_opts_t netacqtagopts;

} corsaro_trace_global_t;

struct corsaro_trace_worker {
    int workerid;

    corsaro_interval_t current_interval;
    corsaro_interval_t lastrotateinterval;
    corsaro_plugin_set_t *plugins;
    uint64_t pkts_outstanding;
    uint64_t pkts_from_prev_interval;

    uint32_t first_pkt_ts;
    uint32_t next_report;
    uint32_t next_rotate;
    uint32_t last_ts;
    uint8_t stopped;

    corsaro_tagged_loss_tracker_t *tracker;
    corsaro_packet_tagger_t *tagger;
    void *zmq_pushsock;
};

struct corsaro_trace_merger {
    corsaro_trace_global_t *glob;
    pthread_t threadid;

    int stops_seen;
    uint32_t next_rotate_interval;
    corsaro_plugin_set_t *pluginset;
    corsaro_fin_interval_t *finished_intervals;

    void *zmq_pullsock;
    void *zmq_taggersock;
};

corsaro_trace_global_t *corsaro_trace_init_global(char *filename, int logmode);
void corsaro_trace_free_global(corsaro_trace_global_t *glob);
void *start_faux_control_thread(void *data);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
