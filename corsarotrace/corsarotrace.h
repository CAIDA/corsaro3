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

enum {
    CORSARO_TRACE_MSG_MERGE = 0,
    CORSARO_TRACE_MSG_STOP = 1,
    CORSARO_TRACE_MSG_ROTATE = 2,
    CORSARO_TRACE_MSG_PACKET = 3,
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
    char *subqueuename;
    char *filterstring;
    char *monitorid;

    libts_ascii_backend_t libtsascii;
    libts_kafka_backend_t libtskafka;
    libts_dbats_backend_t libtsdbats;

    uint32_t first_pkt_ts;
    uint32_t boundstartts;
    uint32_t boundendts;
    uint32_t interval;
    uint32_t rotatefreq;

    uint8_t logmode;
    uint8_t threads;
    uint8_t plugincount;

    uint8_t removespoofed;
    uint8_t removeerratic;
    uint8_t removerouted;

    void *zmq_ctxt;
    void *zmq_subsock;
    void **zmq_workersocks;

} corsaro_trace_global_t;

struct corsaro_trace_worker {
    corsaro_trace_global_t *glob;
    pthread_t threadid;
    int workerid;

    corsaro_interval_t current_interval;
    corsaro_interval_t lastrotateinterval;
    corsaro_plugin_set_t *plugins;
    uint64_t pkts_outstanding;

    uint32_t next_report;
    uint32_t next_rotate;
    uint32_t last_ts;
    uint8_t stopped;

    void *zmq_pullsock;
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
};

corsaro_trace_global_t *corsaro_trace_init_global(char *filename, int logmode);
void corsaro_trace_free_global(corsaro_trace_global_t *glob);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
