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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libtrace.h>
#include <assert.h>

#include "libcorsaro3_plugin.h"
#include "libcorsaro3_trace.h"
#include "corsaro_wdcap.h"
#include "utils.h"

#define CORSARO_WDCAP_MAGIC 0x57444341

typedef struct wdcapstate {
    libtrace_out_t *writer;
    int threadid;
    uint32_t interval_start_ts;
} wdcapstate_t;

typedef struct corsaro_wdcap_config {
    corsaro_plugin_proc_options_t basic;
    char *fileformat;
    uint8_t stripvlans;
} corsaro_wdcap_config_t;

#define PLUGIN_NAME "wdcap"

static corsaro_plugin_t corsaro_wdcap_plugin = {
    PLUGIN_NAME,
    CORSARO_PLUGIN_ID_WDCAP,
    CORSARO_WDCAP_MAGIC,
    CORSARO_INTERIM_TRACE,
    CORSARO_INTERIM_TRACE,
    CORSARO_MERGE_TYPE_DISTINCT,
    CORSARO_PLUGIN_GENERATE_BASE_PTRS(corsaro_wdcap),
    CORSARO_PLUGIN_GENERATE_TRACE_PTRS(corsaro_wdcap),
    CORSARO_PLUGIN_GENERATE_BASE_READ_PTRS(corsaro_wdcap),
    CORSARO_PLUGIN_GENERATE_READ_STD_DISTINCT(corsaro_wdcap),
    CORSARO_PLUGIN_GENERATE_TAIL
};

corsaro_plugin_t *corsaro_wdcap_alloc(void) {
    return &corsaro_wdcap_plugin;
}

const char *corsaro_wdcap_get_avro_schema(void) {
    return NULL;
}

int corsaro_wdcap_parse_config(corsaro_plugin_t *p, yaml_document_t *doc,
        yaml_node_t *options) {

    corsaro_wdcap_config_t *conf;
    yaml_node_t *key, *value;
    yaml_node_pair_t *pair;

    conf = (corsaro_wdcap_config_t *)malloc(sizeof(corsaro_wdcap_config_t));
    if (conf == NULL) {
        return -1;
    }

    CORSARO_INIT_PLUGIN_PROC_OPTS(conf->basic);
    conf->stripvlans = CORSARO_DEFAULT_WDCAP_STRIP_VLANS;
    conf->fileformat = NULL;

    if (options->type != YAML_MAPPING_NODE) {
        corsaro_log(p->logger,
                "wdcap plugin config should be a map.");
        free(conf);
        return -1;
    }

    for (pair = options->data.mapping.pairs.start;
            pair < options->data.mapping.pairs.top; pair ++) {

        key = yaml_document_get_node(doc, pair->key);
        value = yaml_document_get_node(doc, pair->value);

        /* TODO allow for custom log file? */

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "stripvlan") == 0) {
            if (strcmp((char *)value->data.scalar.value, "yes") == 0) {
                conf->stripvlans = CORSARO_WDCAP_STRIP_VLANS_ON;
            }
            if (strcmp((char *)value->data.scalar.value, "enabled") == 0) {
                conf->stripvlans = CORSARO_WDCAP_STRIP_VLANS_ON;
            }
            if (strcmp((char *)value->data.scalar.value, "on") == 0) {
                conf->stripvlans = CORSARO_WDCAP_STRIP_VLANS_ON;
            }

            if (strcmp((char *)value->data.scalar.value, "no") == 0) {
                conf->stripvlans = CORSARO_WDCAP_STRIP_VLANS_OFF;
            }
            if (strcmp((char *)value->data.scalar.value, "disabled") == 0) {
                conf->stripvlans = CORSARO_WDCAP_STRIP_VLANS_OFF;
            }
            if (strcmp((char *)value->data.scalar.value, "off") == 0) {
                conf->stripvlans = CORSARO_WDCAP_STRIP_VLANS_OFF;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "fileformat") == 0) {
            conf->fileformat = strdup((char *)value->data.scalar.value);
        }

    }
    p->config = conf;
    return 0;
}

int corsaro_wdcap_finalise_config(corsaro_plugin_t *p,
        corsaro_plugin_proc_options_t *stdopts) {
    corsaro_wdcap_config_t *conf;

    /* Configure standard 'global' options for any options that
     * were not overridden by plugin-specific config.
     */
    conf = (corsaro_wdcap_config_t *)(p->config);

    conf->basic.template = stdopts->template;
    conf->basic.monitorid = stdopts->monitorid;
    return 0;
}

void corsaro_wdcap_destroy_self(corsaro_plugin_t *p) {
    if (p->config) {
        corsaro_wdcap_config_t *conf = (corsaro_wdcap_config_t *)(p->config);
        if (conf->fileformat) {
            free(conf->fileformat);
        }
        free(p->config);
    }

    p->config = NULL;
}

void *corsaro_wdcap_init_processing(corsaro_plugin_t *p, int threadid) {

    wdcapstate_t *state;

    state = (wdcapstate_t *)calloc(1, sizeof(wdcapstate_t));
    if (state == NULL) {
        return NULL;
    }

    state->interval_start_ts = 0;
    state->threadid = threadid;
    state->writer = NULL;       // for now...
    return state;
}

int corsaro_wdcap_halt_processing(corsaro_plugin_t *p, void *local) {
    wdcapstate_t *state;

    state = (wdcapstate_t *)(local);
    if (state == NULL) {
        return 0;
    }

    if (state->writer) {
        trace_destroy_output(state->writer);
    }
    free(state);
    return 0;
}

static char *stradd(const char *str, char *bufp, char *buflim) {
    while(bufp < buflim && (*bufp = *str++) != '\0') {
        ++bufp;
    }
    return bufp;
}


char *corsaro_wdcap_derive_output_name(corsaro_plugin_t *p, void *local,
        uint32_t timestamp, int threadid) {

    /* Adapted from libwdcap but slightly modified to fit corsaro
     * environment and templating format.
     */

    corsaro_wdcap_config_t *conf;
    char scratch[9500];
    char outname[10000];
    char tsbuf[11];
    char *format, *ext;
    char *ptr, *w, *end;
    struct timeval tv;

    conf = (corsaro_wdcap_config_t *)(p->config);

    if (conf->fileformat) {
        format = conf->fileformat;
    } else {
        format = (char *)"pcapfile";
    }

    if (strcmp(format, "pcapfile") == 0) {
        ext = (char *)"pcap";
    } else {
        ext = format;
    }

    end = scratch + sizeof(scratch);
    ptr = conf->basic.template;

    /* Pre-pend the format */
    w = stradd(format, scratch, end);
    *w++ = ':';

    for (; *ptr; ++ptr) {
        if (*ptr == '%') {
            switch (*++ptr) {
                case '\0':
                    /* Reached end of naming scheme, stop */
                    --ptr;
                    break;
                case CORSARO_IO_MONITOR_PATTERN:
                    /* monitor name */
                    if (conf->basic.monitorid) {
                        w = stradd(conf->basic.monitorid, w, end);
                    }
                    continue;
                case CORSARO_IO_PLUGIN_PATTERN:
                    w = stradd("wdcap", w, end);
                    continue;
                case CORSARO_IO_TRACE_FORMAT_PATTERN:
                    w = stradd(ext, w, end);
                    continue;
                case 's':
                    /* Add unix timestamp */
                    snprintf(tsbuf, sizeof(tsbuf), "%u", timestamp);
                    w = stradd(tsbuf, w, end);
                    continue;
                default:
                    /* Everything should be handled by strftime */
                    --ptr;
            }
        }
        if (w == end)
            break;
        *w++ = *ptr;
    }

    if (w >= end) {
        /* Not enough space for the full filename */
        return NULL;
    }

    /* Attach a suitable file extension if the file is compressed */
    w = stradd(".gz", w, end);

    if (w >= end) {
        /* Not enough space for the full filename */
        return NULL;
    }

    if (threadid >= 0) {
        char thspace[1024];
        snprintf(thspace, 1024, "--%d", threadid);
        w = stradd(thspace, w, end);
    }

    if (w >= end) {
        /* Not enough space for the full filename */
        return NULL;
    }
    *w = '\0';

    tv.tv_sec = timestamp;
    strftime(outname, sizeof(outname), scratch, gmtime(&tv.tv_sec));
    return strdup(outname);
}

int corsaro_wdcap_open_output_file(corsaro_plugin_t *p, void *local,
        uint32_t timestamp, int threadid) {

    char *name = NULL;
    int ret = 0;
    corsaro_wdcap_config_t *conf = (corsaro_wdcap_config_t *)(p->config);
    libtrace_err_t err;
    wdcapstate_t *state = (wdcapstate_t *)local;

    if (state == NULL) {
        corsaro_log(p->logger,
                "unexpected NULL state in corsaro_wdcap_open_output_file.");
        return -1;
    }


    name = corsaro_wdcap_derive_output_name(p, local, timestamp, threadid);
    if (name == NULL) {
        corsaro_log(p->logger,
                "unable to create suitable output file name for wdcap plugin");
        corsaro_log(p->logger,
                "check that your template is not stupidly long...");
        return -1;
    }


    state->writer = corsaro_create_trace_writer(p->logger, name,
            CORSARO_TRACE_COMPRESS_LEVEL, CORSARO_TRACE_COMPRESS_METHOD);
    if (state->writer == NULL) {
        corsaro_log(p->logger,
                "unable to open output file for wdcap plugin");
        ret = -1;
    }
    free(name);
    return ret;
}

int corsaro_wdcap_start_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_start) {

    wdcapstate_t *state = (wdcapstate_t *)local;
    if (state == NULL) {
        corsaro_log(p->logger,
                "unexpected NULL state in corsaro_wdcap_start_interval.");
        return -1;
    }

    if (state->writer == NULL) {
        return corsaro_wdcap_open_output_file(p, local, int_start->time,
                state->threadid);
    }

    return 0;
}

int corsaro_wdcap_end_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_end) {

    return 0;
}

int corsaro_wdcap_rotate_output(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *rot_start) {

    wdcapstate_t *state = (wdcapstate_t *)local;
    if (state == NULL) {
        corsaro_log(p->logger,
                "unexpected NULL state in corsaro_wdcap_rotate_interval.");
        return -1;
    }

    if (state->writer) {
        corsaro_destroy_trace_writer(state->writer);
        state->writer = NULL;
    }
    return 0;
}

int corsaro_wdcap_process_packet(corsaro_plugin_t *p, void *local,
        libtrace_packet_t *packet, corsaro_packet_state_t *pstate) {

    wdcapstate_t *state = (wdcapstate_t *)local;
    corsaro_wdcap_config_t *conf = (corsaro_wdcap_config_t *)(p->config);

    if (state == NULL) {
        corsaro_log(p->logger,
                "unexpected NULL state in corsaro_wdcap_process_packet.");
        return -1;
    }

    if (conf == NULL) {
        corsaro_log(p->logger,
                "unexpected NULL config in corsaro_wdcap_process_packet.");
        return -1;
    }

    if (state->writer == NULL) {
        corsaro_log(p->logger,
                "unexpected NULL output in corsaro_wdcap_process_packet.");
        return -1;
    }

    if (conf->stripvlans == CORSARO_WDCAP_STRIP_VLANS_ON) {
        packet = trace_strip_packet(packet);
    }

    return corsaro_write_packet(p->logger, state->writer, packet);
}

int corsaro_wdcap_compare_results(corsaro_plugin_t *p, void *local,
        corsaro_plugin_result_t *res1, corsaro_plugin_result_t *res2) {

    uint64_t ts1, ts2;

    assert(res1->packet != NULL && res2->packet != NULL);

    ts1 = trace_get_erf_timestamp(res1->packet);
    ts2 = trace_get_erf_timestamp(res2->packet);

    if (ts1 < ts2) {
        return -1;
    } else if (ts1 > ts2) {
        return 1;
    }

    return 0;
}

void corsaro_wdcap_release_result(corsaro_plugin_t *p, void *local,
        corsaro_plugin_result_t *res) {

    if (res->packet) {
        trace_destroy_packet(res->packet);
    }
    res->packet = NULL;

    /* avrofmt and pluginfmt should still be NULL */
}

void *corsaro_wdcap_init_reading(corsaro_plugin_t *p, int sources) {

    /* We shouldn't need any special state to merge traces? */
    return NULL;
}

int corsaro_wdcap_halt_reading(corsaro_plugin_t *p, void *local) {

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
