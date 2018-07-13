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

#ifndef LIBCORSARO_PLUGIN_H_
#define LIBCORSARO_PLUGIN_H_

#include <yaml.h>
#include <libtrace.h>

#include "libcorsaro3_tagging.h"
#include "libcorsaro3.h"
#include "libcorsaro3_log.h"

/** Convenience macros that define all the function prototypes for the corsaro
 * plugin API
 */
#define CORSARO_PLUGIN_GENERATE_PROTOTYPES(plugin)          \
    corsaro_plugin_t *plugin##_alloc(void);                 \
    int plugin##_parse_config(corsaro_plugin_t *p, yaml_document_t *doc, \
            yaml_node_t *options);                          \
    int plugin##_finalise_config(corsaro_plugin_t *p,       \
            corsaro_plugin_proc_options_t *stdopts);        \
    void plugin##_destroy_self(corsaro_plugin_t *p);        \
    void *plugin##_init_processing(corsaro_plugin_t *p, int threadid);    \
    int plugin##_halt_processing(corsaro_plugin_t *p, void *local); \
    int plugin##_start_interval(corsaro_plugin_t *p, void *local, \
            corsaro_interval_t *int_start);                 \
    void *plugin##_end_interval(corsaro_plugin_t *p, void *local, \
            corsaro_interval_t *int_end);                   \
    int plugin##_process_packet(corsaro_plugin_t *p, void *local, \
            libtrace_packet_t *packet, corsaro_packet_tags_t *tags); \
    char *plugin##_derive_output_name(corsaro_plugin_t *p, void *local, \
            uint32_t timestamp, int threadid);              \
    void *plugin##_init_merging(corsaro_plugin_t *p, int sources);    \
    int plugin##_halt_merging(corsaro_plugin_t *p, void *local); \
    int plugin##_merge_interval_results(corsaro_plugin_t *p, void *local, \
            void **tomerge, corsaro_fin_interval_t *fin);                    \
    int plugin##_rotate_output(corsaro_plugin_t *p, void *local);


typedef enum corsaro_plugin_id {
    CORSARO_PLUGIN_ID_FLOWTUPLE = 20,
    CORSARO_PLUGIN_ID_DOS = 30,
    CORSARO_PLUGIN_ID_REPORT = 100,
    CORSARO_PLUGIN_ID_WDCAP = 200,
    CORSARO_PLUGIN_ID_FILTERINGSTATS = 210,
    CORSARO_PLUGIN_ID_MAX = CORSARO_PLUGIN_ID_FILTERINGSTATS
} corsaro_plugin_id_t;

enum {
    CORSARO_TRACE_API = 0,
    CORSARO_MERGING_API = 1
};

typedef struct corsaro_plugin corsaro_plugin_t;
typedef struct corsaro_plugin_result corsaro_plugin_result_t;

typedef struct corsaro_plugin_proc_options {
    char *template;
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
            corsaro_plugin_proc_options_t *stdopts);
    void (*destroy_self)(corsaro_plugin_t *p);

    /* Callbacks for trace processing */
    void *(*init_processing)(corsaro_plugin_t *p, int threadid);
    int (*halt_processing)(corsaro_plugin_t *p, void *local);
    int (*start_interval)(corsaro_plugin_t *p, void *local,
            corsaro_interval_t *int_start);
    void *(*end_interval)(corsaro_plugin_t *p, void *local,
            corsaro_interval_t *int_end);
    int (*process_packet)(corsaro_plugin_t *p, void *local,
            libtrace_packet_t *packet, corsaro_packet_tags_t *tags);
    char *(*derive_output_name)(corsaro_plugin_t *p, void *local,
            uint32_t timestamp, int threadid);

    /* Callbacks for reading and merging results */
    void *(*init_merging)(corsaro_plugin_t *p, int sources);
    int (*halt_merging)(corsaro_plugin_t *p, void *local);
    int (*merge_interval_results)(corsaro_plugin_t *p, void *local,
            void **tomerge, corsaro_fin_interval_t *fin);
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
        corsaro_plugin_proc_options_t *stdopts);

corsaro_plugin_set_t *corsaro_start_plugins(corsaro_logger_t *logger,
        corsaro_plugin_t *plist, int count, int threadid);
corsaro_plugin_set_t *corsaro_start_merging_plugins(corsaro_logger_t *logger,
        corsaro_plugin_t *plist, int count, int maxsources);
int corsaro_stop_plugins(corsaro_plugin_set_t *pluginset);
void **corsaro_push_end_plugins(corsaro_plugin_set_t *pluginset, uint32_t intid,
        uint32_t ts);
int corsaro_push_start_plugins(corsaro_plugin_set_t *pluginset, uint32_t intid,
        uint32_t ts);
int corsaro_push_packet_plugins(corsaro_plugin_set_t *pluginset,
        libtrace_packet_t *packet, corsaro_packet_tags_t *tags);

int corsaro_rotate_plugin_output(corsaro_logger_t *logger,
        corsaro_plugin_set_t *pset);
int corsaro_merge_plugin_outputs(corsaro_logger_t *logger,
        corsaro_plugin_set_t *pset, corsaro_fin_interval_t *fin);

int corsaro_is_backscatter_packet(libtrace_packet_t *packet);

#define CORSARO_INIT_PLUGIN_PROC_OPTS(opts) \
  opts.template = NULL; \
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
  plugin##_merge_interval_results, plugin##_rotate_output       

#define CORSARO_PLUGIN_GENERATE_TAIL                            \
  NULL, 0, 0, NULL, NULL

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
