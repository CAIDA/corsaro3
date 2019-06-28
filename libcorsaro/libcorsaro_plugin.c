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
#include "libcorsaro_plugin.h"

#ifdef WITH_PLUGIN_SIXT
#include "corsaro_flowtuple.h"
#endif

#ifdef WITH_PLUGIN_WDCAP
#include "corsaro_wdcap.h"
#endif

#ifdef WITH_PLUGIN_DOS
#include "corsaro_dos.h"
#endif

#ifdef WITH_PLUGIN_FILTERINGSTATS
#include "corsaro_filteringstats.h"
#endif

#ifdef WITH_PLUGIN_REPORT
#include "corsaro_report.h"
#endif

#define PLUGIN_INIT_ADD(plugin)                                                \
{                                                                              \
    tail = add_plugin(logger, tail, plugin##_alloc(), 1);                      \
    if (all == NULL) {                                                         \
        all = tail;                                                            \
    }                                                                          \
    plugin_cnt++;                                                              \
}


static int corsaro_plugin_verify(corsaro_logger_t *logger,
        corsaro_plugin_t *plugin)
{
    /* some sanity checking to make sure this plugin has been implemented
       with the features we need. #if 0 this for production */
    if (plugin == NULL) {
        corsaro_log(logger, "attempted to load a NULL plugin");
        return 0;
    }

    if (plugin->name == NULL) {
        corsaro_log(logger, "plugin has no name!");
        return 0;
    }

    if (plugin->id < 0 || plugin->id > CORSARO_PLUGIN_ID_MAX) {
        corsaro_log(logger, "plugin %s has invalid ID %d.", plugin->name,
                plugin->id);
        return 0;
    }

    if (plugin->magic <= 0x010101) {
        corsaro_log(logger, "plugin %s has an invalid magic number.",
                plugin->name);
        return 0;
    }

    /* Check all required methods are present */
    /* TODO add more methods here */

    if (plugin->parse_config == NULL) {
        corsaro_log(logger, "plugin %s has no parse_config() method.",
                plugin->name);
        return 0;
    }

    /* ->next is only set for references to plugins that are part of
     * a plugin list -- it should be NULL for the original plugin
     * definitions.
     */
    if (plugin->next != NULL) {
        corsaro_log(logger, "plugin %s is a copy, not an original.",
                plugin->name);
        return 0;
    }

    return 1;

}


static corsaro_plugin_t *add_plugin(corsaro_logger_t *logger,
        corsaro_plugin_t *plisttail,
        corsaro_plugin_t *p, uint8_t firstload) {

    corsaro_plugin_t *copy = NULL;

    if ((copy = malloc(sizeof(corsaro_plugin_t))) == NULL) {
        corsaro_log(logger, "unable to malloc memory for plugin");
        return NULL;
    }

    memcpy(copy, p, sizeof(corsaro_plugin_t));
    copy->next = NULL;

    /* This used to be optional, but probably no harm in checking each time. */
    if (firstload) {
        if (corsaro_plugin_verify(logger, copy) == 0) {
            free(copy);
            return NULL;
        }
    }

    if (plisttail != NULL) {
        if (plisttail->next != NULL) {
            corsaro_log(logger, "tail of plugin list is not NULL??");
        }
        plisttail->next = copy;
    }

    return copy;
}

static inline void populate_interval(corsaro_interval_t *interval,
        uint32_t number, uint32_t time)
{
    interval->corsaro_magic = CORSARO_MAGIC;
    interval->magic = CORSARO_MAGIC_INTERVAL;
    interval->number = number;
    interval->time = time;
}

corsaro_plugin_t *corsaro_load_all_plugins(corsaro_logger_t *logger) {
    corsaro_plugin_t *all = NULL;
    corsaro_plugin_t *tail = NULL;
    int plugin_cnt = 0;

#ifdef ED_PLUGIN_INIT_ALL_ENABLED
    ED_PLUGIN_INIT_ALL_ENABLED
#endif

    /* For now, I'm just going to maintain the plugins as a list until I
     * encounter a genuine use case where we need to do lots of lookups.
     */

    return all;
}

void corsaro_cleanse_plugin_list(corsaro_plugin_t *plist) {

    corsaro_plugin_t *p = plist;

    while (plist != NULL) {
        p = plist;
        plist = p->next;
        p->destroy_self(p);
        free(p);
    }
}

corsaro_plugin_t *corsaro_find_plugin(corsaro_plugin_t *plist, char *name) {
    corsaro_plugin_t *p = plist;

    while (p != NULL) {
        if (strlen(name) == strlen(p->name) && strncasecmp(name, p->name,
                strlen(p->name)) == 0) {
            return p;
        }
        p = p->next;
    }
    return NULL;
}

corsaro_plugin_t *corsaro_enable_plugin(corsaro_logger_t *logger,
        corsaro_plugin_t *plist, corsaro_plugin_t *parent) {

    corsaro_plugin_t *copy = NULL;

    copy = add_plugin(logger, plist, parent, 0);
    copy->enabled = 1;
    /* Save a reference to the global logger so we can log errors etc to it
     * if no specific logger is requested for this plugin.
     */
    copy->logger = logger;
    copy->local_logger = 0;
    corsaro_log(logger, "enabling %s plugin", copy->name);
    return copy;
}

void corsaro_disable_plugin(corsaro_plugin_t *p) {
    p->enabled = 0;
}

int corsaro_configure_plugin(corsaro_plugin_t *p, yaml_document_t *doc,
        yaml_node_t *options) {

    if (p->config) {
        free(p->config);
    }
    return p->parse_config(p, doc, options);
}

int corsaro_finish_plugin_config(corsaro_plugin_t *plist,
        corsaro_plugin_proc_options_t *stdopts, void *zmq_ctxt) {

    corsaro_plugin_t *p = plist;

    while (p != NULL) {
        if (p->config != NULL) {
            p->finalise_config(p, stdopts, zmq_ctxt);
        }
        p = p->next;
    }
    return 0;
}

corsaro_plugin_set_t *corsaro_start_plugins(corsaro_logger_t *logger,
        corsaro_plugin_t *plist, int count, int threadid) {
    int index = 0;

    corsaro_plugin_set_t *pset = (corsaro_plugin_set_t *)malloc(
            sizeof(corsaro_plugin_set_t));

    pset->active_plugins = plist;
    pset->plugincount = 0;
    pset->plugin_state = (void **) malloc(sizeof(void *) * count);
    pset->api = CORSARO_TRACE_API;
    pset->globlogger = logger;

    memset(pset->plugin_state, 0, sizeof(void *) * count);

    while (plist != NULL) {
        assert(index < count);

        pset->plugin_state[index] = plist->init_processing(plist,
                threadid);
        index += 1;
        plist = plist->next;
        pset->plugincount ++;
    }

    return pset;
}

corsaro_plugin_set_t *corsaro_start_merging_plugins(corsaro_logger_t *logger,
        corsaro_plugin_t *plist, int count, int maxsources, void *tagsock) {

    int index = 0;

    corsaro_plugin_set_t *pset = (corsaro_plugin_set_t *)malloc(
            sizeof(corsaro_plugin_set_t));

    pset->active_plugins = plist;
    pset->plugincount = 0;
    pset->plugin_state = (void **) malloc(sizeof(void *) * count);
    pset->api = CORSARO_MERGING_API;
    pset->globlogger = logger;

    memset(pset->plugin_state, 0, sizeof(void *) * count);

    while (plist != NULL) {
        assert(index < count);

        pset->plugin_state[index] = plist->init_merging(plist, maxsources,
                tagsock);

        index += 1;
        plist = plist->next;
        pset->plugincount ++;
    }

    return pset;

}

int corsaro_stop_plugins(corsaro_plugin_set_t *pset) {

    int index = 0;
    corsaro_plugin_t *p = pset->active_plugins;

    while (p != NULL) {
        if (pset->api == CORSARO_TRACE_API) {
            p->halt_processing(p, pset->plugin_state[index]);
        }
        if (pset->api == CORSARO_MERGING_API) {
            p->halt_merging(p, pset->plugin_state[index]);
        }

        pset->plugin_state[index] = NULL;
        p = p->next;
        index ++;
    }
    free(pset->plugin_state);
    free(pset);
    return 0;
}

int corsaro_push_packet_plugins(corsaro_plugin_set_t *pset,
        libtrace_packet_t *packet, corsaro_packet_tags_t *tags) {
    int index = 0;
    corsaro_plugin_t *p = pset->active_plugins;

    if (pset->api != CORSARO_TRACE_API) {
        return -1;
    }

    while (p != NULL) {
        p->process_packet(p, pset->plugin_state[index], packet, tags);
        p = p->next;
        index ++;
    }
    return 0;
}

void **corsaro_push_end_plugins(corsaro_plugin_set_t *pset, uint32_t intervalid,
        uint32_t ts, uint8_t complete) {
    corsaro_interval_t end;
    int index = 0;
    corsaro_plugin_t *p = pset->active_plugins;
    void **plugin_data = NULL;


    populate_interval(&end, intervalid, ts);
    end.isstart = 0;

    if (pset->api != CORSARO_TRACE_API) {
        return NULL;
    }

    plugin_data = (void **)(calloc(pset->plugincount, sizeof(void *)));
    while (p != NULL) {
        plugin_data[index] = p->end_interval(p, pset->plugin_state[index],
                &end, complete);
        p = p->next;
        index ++;
    }
    return plugin_data;
}

int corsaro_push_start_plugins(corsaro_plugin_set_t *pset, uint32_t intervalid,
        uint32_t ts) {
    corsaro_interval_t start;
    int index = 0;
    corsaro_plugin_t *p = pset->active_plugins;

    populate_interval(&start, intervalid, ts);
    start.isstart = 1;

    if (pset->api != CORSARO_TRACE_API) {
        return -1;
    }

    while (p != NULL) {
        p->start_interval(p, pset->plugin_state[index], &start);
        p = p->next;
        index ++;
    }
    return 0;
}

int corsaro_rotate_plugin_output(corsaro_logger_t *logger,
        corsaro_plugin_set_t *pset) {

    corsaro_log(logger, "rotating plugin output");
    corsaro_plugin_t *p = NULL;
    int errors = 0;
    int index = 0;

    if (pset == NULL) {
        corsaro_log(logger,
                "NULL plugin set provided when rotating output.");
        return -1;
    }

    p = pset->active_plugins;
    while (p != NULL) {
        corsaro_log(logger, "rotating output for plugin %s", p->name);

        if (p->rotate_output(p, pset->plugin_state[index])) {
            corsaro_log(logger,
                    "unable to rotate output file for plugin %s",
                    p->name);
            errors ++;
            p = p->next;
            index ++;
            continue;
        }

        p = p->next;
        index ++;
    }

    return errors;

}

int corsaro_merge_plugin_outputs(corsaro_logger_t *logger,
        corsaro_plugin_set_t *pset, corsaro_fin_interval_t *fin)
{

    corsaro_plugin_t *p = NULL;
    int index = 0;
    void **plugin_state_ptrs = NULL;
    int pindex = 0;
    int errors = 0;

    corsaro_log(logger, "commencing merge for all plugins %u:%u.",
            fin->interval_id, fin->timestamp);

    if (pset == NULL) {
        corsaro_log(logger,
                "NULL plugin set provided when merging output.");
        return 1;
    }

    p = pset->active_plugins;
    plugin_state_ptrs = calloc(fin->threads_ended, sizeof(void *));

    while (p != NULL) {
        for (pindex = 0; pindex < fin->threads_ended; pindex ++) {
            plugin_state_ptrs[pindex] = fin->thread_plugin_data[pindex][index];
        }

        if (p->merge_interval_results(p, pset->plugin_state[index],
                plugin_state_ptrs, fin) == -1) {
            corsaro_log(logger,
                    "unable to merge interval results for plugin %s",
                    p->name);
            errors ++;
        }

        p = p->next;
        index ++;
    }

    free(plugin_state_ptrs);
    corsaro_log(logger, "completed merge for all plugins %u:%u.",
            fin->interval_id, fin->timestamp);
    return errors;

}

int corsaro_is_backscatter_packet(libtrace_packet_t *packet) {
    void *temp = NULL;
    uint8_t proto;
    uint32_t remaining;

    libtrace_tcp_t *tcp_hdr = NULL;
    libtrace_icmp_t *icmp_hdr = NULL;

    /* get the transport header */
    if ((temp = trace_get_transport(packet, &proto, &remaining)) == NULL) {
        /* not enough payload */
        return 0;
    }

    /* check for tcp */
    if (proto == TRACE_IPPROTO_TCP && remaining >= 4) {
        tcp_hdr = (libtrace_tcp_t *)temp;

        /* look for SYNACK or RST */
        if ((tcp_hdr->syn && tcp_hdr->ack) || tcp_hdr->rst) {
            return 1;
        } else {
            return 0;
        }
    }
    /* check for icmp */
    else if (proto == TRACE_IPPROTO_ICMP && remaining >= 2) {
        icmp_hdr = (libtrace_icmp_t *)temp;
        if (icmp_hdr->type == 0 || icmp_hdr->type == 3 ||
                icmp_hdr->type == 4 || icmp_hdr->type == 5 ||
                icmp_hdr->type == 11 || icmp_hdr->type == 12 ||
                icmp_hdr->type == 14 || icmp_hdr->type == 16 ||
                icmp_hdr->type == 18) {
            return 1;
        } else {
            return 0;
        }
    }

    return 0;
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
