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
#include "libcorsaro3_plugin.h"

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
        corsaro_plugin_proc_options_t *stdopts) {

    corsaro_plugin_t *p = plist;

    while (p != NULL) {
        if (p->config != NULL) {
            p->finalise_config(p, stdopts);
        }
        p = p->next;
    }
    return 0;
}

/* XXX number of arguments is starting to get out of hand */
corsaro_plugin_set_t *corsaro_start_plugins(corsaro_logger_t *logger,
        corsaro_plugin_t *plist, int count, int api) {
    int index = 0;

    corsaro_plugin_set_t *pset = (corsaro_plugin_set_t *)malloc(
            sizeof(corsaro_plugin_set_t));

    pset->active_plugins = plist;
    pset->plugincount = 0;
    pset->plugin_state = (void **) malloc(sizeof(void *) * count);
    pset->api = api;
    pset->globlogger = logger;

    memset(pset->plugin_state, 0, sizeof(void *) * count);

    while (plist != NULL) {
        assert(index < count);

        if (api == CORSARO_TRACE_API) {
            pset->plugin_state[index] = plist->init_processing(plist);
        }
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

        pset->plugin_state[index] = NULL;
        p = p->next;
        index ++;
    }
    return 0;
}

int corsaro_push_packet_plugins(corsaro_plugin_set_t *pset,
        libtrace_packet_t *packet) {
    int index = 0;
    corsaro_plugin_t *p = pset->active_plugins;

    if (pset->api != CORSARO_TRACE_API) {
        return -1;
    }

    while (p != NULL) {
        /* TODO check return state -- a plugin may suggest all subsequent
         * plugins ignore this packet, so we need to support that.
         */
        p->process_packet(p, pset->plugin_state[index], packet);
        p = p->next;
        index ++;
    }
    return 0;
}

int corsaro_push_end_plugins(corsaro_plugin_set_t *pset, uint32_t intervalid,
        uint32_t ts) {
    corsaro_interval_t end;
    int index = 0;
    corsaro_plugin_t *p = pset->active_plugins;

    populate_interval(&end, intervalid, ts);

    if (pset->api != CORSARO_TRACE_API) {
        return -1;
    }

    while (p != NULL) {
        p->end_interval(p, pset->plugin_state[index], &end);
        p = p->next;
        index ++;
    }
    return 0;
}

int corsaro_push_start_plugins(corsaro_plugin_set_t *pset, uint32_t intervalid,
        uint32_t ts) {
    corsaro_interval_t start;
    int index = 0;
    corsaro_plugin_t *p = pset->active_plugins;

    populate_interval(&start, intervalid, ts);

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

int corsaro_push_rotate_file_plugins(corsaro_plugin_set_t *pset,
        uint32_t intervalid, uint32_t ts) {

    corsaro_interval_t rotstart;
    int index = 0;
    corsaro_plugin_t *p = pset->active_plugins;

    populate_interval(&rotstart, intervalid, ts);

    if (pset->api != CORSARO_TRACE_API) {
        return -1;
    }

    while (p != NULL) {
        p->rotate_output(p, pset->plugin_state[index], &rotstart);
        p = p->next;
        index ++;
    }
    return 0;
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
