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

#ifndef LIBCORSARO_PLUGIN_H_
#define LIBCORSARO_PLUGIN_H_

#include <yaml.h>
#include <libtrace.h>

#include "libcorsaro_tagging.h"
#include "libcorsaro.h"
#include "libcorsaro_log.h"
#include "libcorsaro_libtimeseries.h"

/** Convenience macros that define all the function prototypes for the corsaro
 * plugin API
 */
#define CORSARO_PLUGIN_GENERATE_PROTOTYPES(plugin)          \
    corsaro_plugin_t *plugin##_alloc(void);                 \
    int plugin##_parse_config(corsaro_plugin_t *p, yaml_document_t *doc, \
            yaml_node_t *options);                          \
    int plugin##_finalise_config(corsaro_plugin_t *p,       \
            corsaro_plugin_proc_options_t *stdopts,         \
            void *zmq_ctxt);                                \
    void plugin##_destroy_self(corsaro_plugin_t *p);        \
    void *plugin##_init_processing(corsaro_plugin_t *p, int threadid);    \
    int plugin##_halt_processing(corsaro_plugin_t *p, void *local); \
    int plugin##_start_interval(corsaro_plugin_t *p, void *local, \
            corsaro_interval_t *int_start);                 \
    void *plugin##_end_interval(corsaro_plugin_t *p, void *local, \
            corsaro_interval_t *int_end, uint8_t complete);      \
    int plugin##_process_packet(corsaro_plugin_t *p, void *local, \
            libtrace_packet_t *packet, corsaro_packet_tags_t *tags); \
    char *plugin##_derive_output_name(corsaro_plugin_t *p, void *local, \
            uint32_t timestamp, int threadid);              \
    void *plugin##_init_merging(corsaro_plugin_t *p, int sources); \
    int plugin##_halt_merging(corsaro_plugin_t *p, void *local); \
    int plugin##_merge_interval_results(corsaro_plugin_t *p, void *local, \
            void **tomerge, corsaro_fin_interval_t *fin, void *tagsock);  \
    int plugin##_rotate_output(corsaro_plugin_t *p, void *local);


typedef enum corsaro_plugin_id {
    CORSARO_PLUGIN_ID_FLOWTUPLE = 20,
    CORSARO_PLUGIN_ID_DOS = 30,
    CORSARO_PLUGIN_ID_REPORT = 100,
    CORSARO_PLUGIN_ID_WDCAP = 200,
    CORSARO_PLUGIN_ID_NULL = 205,
    CORSARO_PLUGIN_ID_FILTERINGSTATS = 210,
    CORSARO_PLUGIN_ID_MAX = CORSARO_PLUGIN_ID_FILTERINGSTATS
} corsaro_plugin_id_t;

enum {
    CORSARO_TRACE_API = 0,
    CORSARO_MERGING_API = 1
};

enum {
    CORSARO_MERGE_SUCCESS = 1,
    CORSARO_MERGE_NO_ACTION = 0,
    CORSARO_MERGE_CONTROL_FAILURE = -1,
    CORSARO_MERGE_WRITE_FAILED = -2,
    CORSARO_MERGE_BAD_ARGUMENTS = -3,
};

typedef struct corsaro_plugin corsaro_plugin_t;
typedef struct corsaro_plugin_result corsaro_plugin_result_t;

typedef struct corsaro_plugin_proc_options {
    char *template;
    libts_ascii_backend_t *libtsascii;
    libts_kafka_backend_t *libtskafka;
    libts_dbats_backend_t *libtsdbats;
    char *monitorid;
    uint8_t procthreads;
} corsaro_plugin_proc_options_t;

/** Corsaro state for a packet
 *
 * This is passed, along with the packet, to each plugin.
 * Plugins can add data to it, or check for data from earlier plugins.
 */
typedef struct corsaro_packet_state {
    /** Features of the packet that have been identified by earlier plugins */
    uint8_t flags;

    /* TODO add other stuff in here as needed, e.g. tags */

} corsaro_packet_state_t;

/** The possible packet state flags */
enum {
    /** The packet is classified as backscatter */
    CORSARO_PACKET_STATE_FLAG_BACKSCATTER = 0x01,

    /** The packet should be ignored by filter-aware plugins */
    CORSARO_PACKET_STATE_FLAG_IGNORE = 0x02,

    /** Indicates the P0F plugin has run */
    CORSARO_PACKET_STATE_FLAG_P0F = 0x08,
};


struct corsaro_plugin {

    /* Static identifying information for the plugin */
    const char *name;
    const corsaro_plugin_id_t id;
    const uint32_t magic;           /* XXX Don't really use this anymore */

    /* Callbacks for general functionality */
    int (*parse_config)(corsaro_plugin_t *p, yaml_document_t *doc,
            yaml_node_t *options);
    int (*finalise_config)(corsaro_plugin_t *p,
            corsaro_plugin_proc_options_t *stdopts, void *zmq_ctxt);
    void (*destroy_self)(corsaro_plugin_t *p);

    /* Callbacks for trace processing */
    void *(*init_processing)(corsaro_plugin_t *p, int threadid);
    int (*halt_processing)(corsaro_plugin_t *p, void *local);
    int (*start_interval)(corsaro_plugin_t *p, void *local,
            corsaro_interval_t *int_start);
    void *(*end_interval)(corsaro_plugin_t *p, void *local,
            corsaro_interval_t *int_end, uint8_t complete);
    int (*process_packet)(corsaro_plugin_t *p, void *local,
            libtrace_packet_t *packet, corsaro_packet_tags_t *tags);
    char *(*derive_output_name)(corsaro_plugin_t *p, void *local,
            uint32_t timestamp, int threadid);

    /* Callbacks for reading and merging results */
    void *(*init_merging)(corsaro_plugin_t *p, int sources);
    int (*halt_merging)(corsaro_plugin_t *p, void *local);
    int (*merge_interval_results)(corsaro_plugin_t *p, void *local,
            void **tomerge, corsaro_fin_interval_t *fin, void *tagsock);
    int (*rotate_output)(corsaro_plugin_t *p, void *local);


    /* High level global state variables */
    void *config;       // plugin-specific global config goes here
    uint8_t enabled;    // if 0, the plugin is disabled and will be skipped
                        // when processing packets
    uint8_t local_logger;   // if 1, ->logger points to a logger instance
                            // created specifically for this plugin. If 0,
                            // ->logger points to the global logger.
    corsaro_logger_t *logger;
    corsaro_plugin_t *next;

};

typedef struct corsaro_running_plugins {
    corsaro_plugin_t *active_plugins;
    int plugincount;
    void ** plugin_state;
    corsaro_logger_t *globlogger;
    uint8_t api;
} corsaro_plugin_set_t;

corsaro_plugin_t *corsaro_load_all_plugins(corsaro_logger_t *logger);
void corsaro_cleanse_plugin_list(corsaro_plugin_t *plist);
corsaro_plugin_t *corsaro_find_plugin(corsaro_plugin_t *plist, char *name);
corsaro_plugin_t *corsaro_enable_plugin(corsaro_logger_t *logger,
        corsaro_plugin_t *plist, corsaro_plugin_t *parent);
void corsaro_disable_plugin(corsaro_plugin_t *p);
int corsaro_configure_plugin(corsaro_plugin_t *p, yaml_document_t *doc,
        yaml_node_t *options);
int corsaro_finish_plugin_config(corsaro_plugin_t *p,
        corsaro_plugin_proc_options_t *stdopts, void *zmq_ctxt);

corsaro_plugin_set_t *corsaro_start_plugins(corsaro_logger_t *logger,
        corsaro_plugin_t *plist, int count, int threadid);
corsaro_plugin_set_t *corsaro_start_merging_plugins(corsaro_logger_t *logger,
        corsaro_plugin_t *plist, int count, int maxsources);
int corsaro_stop_plugins(corsaro_plugin_set_t *pluginset);
void **corsaro_push_end_plugins(corsaro_plugin_set_t *pluginset, uint32_t intid,
        uint32_t ts, uint8_t complete);
int corsaro_push_start_plugins(corsaro_plugin_set_t *pluginset, uint32_t intid,
        uint32_t ts);
int corsaro_push_packet_plugins(corsaro_plugin_set_t *pluginset,
        libtrace_packet_t *packet, corsaro_packet_tags_t *tags);
int corsaro_rotate_plugin_output(corsaro_logger_t *logger,
        corsaro_plugin_set_t *pset);
int corsaro_merge_plugin_outputs(corsaro_logger_t *logger,
        corsaro_plugin_set_t *pset, corsaro_fin_interval_t *fin,
        void *tagsock);

int corsaro_is_backscatter_packet(libtrace_packet_t *packet,
        corsaro_packet_tags_t *tags);

#define CORSARO_INIT_PLUGIN_PROC_OPTS(opts) \
  opts.template = NULL; \
  opts.libtsascii = NULL; \
  opts.libtsdbats = NULL; \
  opts.libtskafka = NULL; \
  opts.monitorid = NULL;

#define CORSARO_PLUGIN_GENERATE_BASE_PTRS(plugin)               \
  plugin##_parse_config,              \
  plugin##_finalise_config,              \
  plugin##_destroy_self

#define CORSARO_PLUGIN_GENERATE_TRACE_PTRS(plugin)              \
  plugin##_init_processing, plugin##_halt_processing,           \
  plugin##_start_interval, plugin##_end_interval,               \
  plugin##_process_packet, plugin##_derive_output_name

#define CORSARO_PLUGIN_GENERATE_MERGE_PTRS(plugin)          \
  plugin##_init_merging, plugin##_halt_merging,                 \
  plugin##_merge_interval_results,                          \
  plugin##_rotate_output

#define CORSARO_PLUGIN_GENERATE_TAIL                            \
  NULL, 0, 0, NULL, NULL

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
