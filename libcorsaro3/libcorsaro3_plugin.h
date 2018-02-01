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

#include "libcorsaro3.h"
#include "libcorsaro3_log.h"
#include "libcorsaro3_io.h"

typedef enum corsaro_plugin_id {
    CORSARO_PLUGIN_ID_FLOWTUPLE = 20,
    CORSARO_PLUGIN_ID_DOS = 30,
    CORSARO_PLUGIN_ID_REPORT = 100,
    CORSARO_PLUGIN_ID_MAX = CORSARO_PLUGIN_ID_REPORT
} corsaro_plugin_id_t;

enum {
    CORSARO_TRACE_API = 0,
    CORSARO_READER_API = 1
};

typedef struct corsaro_plugin corsaro_plugin_t;

typedef struct corsaro_plugin_proc_options {
    char *template;
    char *monitorid;
    corsaro_file_mode_t outmode;
    corsaro_file_compress_t compress;
    int compresslevel;
} corsaro_plugin_proc_options_t;

struct corsaro_plugin {

    /* Static identifying information for the plugin */
    const char *name;
    const corsaro_plugin_id_t id;
    const uint32_t magic;

    /* Callbacks for general functionality */
    int (*parse_config)(corsaro_plugin_t *p, yaml_document_t *doc,
            yaml_node_t *options);
    int (*finalise_config)(corsaro_plugin_t *p,
            corsaro_plugin_proc_options_t *stdopts);
    void (*destroy_self)(corsaro_plugin_t *p);

    /* Callbacks for trace processing */
    void *(*init_processing)(corsaro_plugin_t *p);
    int (*halt_processing)(corsaro_plugin_t *p, void *local);
    int (*start_interval)(corsaro_plugin_t *p, void *local,
            corsaro_interval_t *int_start);
    int (*end_interval)(corsaro_plugin_t *p, void *local,
            corsaro_interval_t *int_end);
    int (*process_packet)(corsaro_plugin_t *p, void *local,
            libtrace_packet_t *packet);
    int (*rotate_output)(corsaro_plugin_t *p, void *local,
            corsaro_interval_t *rot_start);

    /* Callbacks for reading results */
    /* TODO */

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
        corsaro_plugin_t *plist, int count, int api);
int corsaro_stop_plugins(corsaro_plugin_set_t *pluginset);
int corsaro_push_end_plugins(corsaro_plugin_set_t *pluginset, uint32_t intid,
        uint32_t ts);
int corsaro_push_start_plugins(corsaro_plugin_set_t *pluginset, uint32_t intid,
        uint32_t ts);
int corsaro_push_packet_plugins(corsaro_plugin_set_t *pluginset,
        libtrace_packet_t *packet);
int corsaro_push_rotate_file_plugins(corsaro_plugin_set_t *pset,
        uint32_t intervalid, uint32_t ts);


#define CORSARO_INIT_PLUGIN_PROC_OPTS(opts) \
  opts->template = NULL; \
  opts->monitorid = NULL; \
  opts->outmode = CORSARO_FILE_MODE_UNKNOWN; \
  opts->compress = CORSARO_FILE_COMPRESS_UNSET; \
  opts->compresslevel = -1; 

#define CORSARO_PLUGIN_GENERATE_BASE_PTRS(plugin)               \
  plugin##_parse_config, plugin##_finalise_config,              \
  plugin##_destroy_self

#define CORSARO_PLUGIN_GENERATE_TRACE_PTRS(plugin)              \
  plugin##_init_processing, plugin##_halt_processing,           \
  plugin##_start_interval, plugin##_end_interval,               \
  plugin##_process_packet, plugin##_rotate_output

#define CORSARO_PLUGIN_GENERATE_READ_PTRS(plugin)               \
  plugin##_read_result, plugin##_compare_results

#define CORSARO_PLUGIN_GENERATE_TAIL                            \
  NULL, 0, 0, NULL, NULL

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
