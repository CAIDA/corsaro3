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

#ifdef WITH_PLUGIN_SIXT
#include "corsaro_flowtuple.h"
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

static inline void reset_packet_state(corsaro_packet_state_t *pstate) {
    pstate->flags = 0;
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
        corsaro_plugin_t *plist, int count, int api, int threadid) {
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
            pset->plugin_state[index] = plist->init_processing(plist,
                    threadid);
        }
        if (api == CORSARO_READER_API) {
            pset->plugin_state[index] = plist->init_reading(plist);
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
        if (pset->api == CORSARO_READER_API) {
            p->halt_reading(p, pset->plugin_state[index]);
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
    corsaro_packet_state_t pstate;

    if (pset->api != CORSARO_TRACE_API) {
        return -1;
    }

    reset_packet_state(&pstate);

    while (p != NULL) {
        p->process_packet(p, pset->plugin_state[index], packet, &pstate);
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

static inline int compare_results_common(corsaro_plugin_result_t *res1,
        corsaro_plugin_result_t *res2, corsaro_logger_t *logger) {

    corsaro_result_type_t t1, t2;

    t1 = res1->type;
    t2 = res2->type;

    /* EOF always comes last */
    if (t1 == CORSARO_RESULT_TYPE_EOF) {
        return 1;
    }

    if (t2 == CORSARO_RESULT_TYPE_EOF) {
        return -1;
    }

    /* Data should come before anything else, since we want to
     * consume / combine the 'marker' results in a single pass.
     * In other words, keep reading data from a result file until
     * we hit a marker, then wait until all other files have
     * reached the same marker.
     */
    if (t1 == CORSARO_RESULT_TYPE_DATA) {
        if (t2 == CORSARO_RESULT_TYPE_DATA) {
            return 0;
        }

        return -1;
    }

    if (t2 == CORSARO_RESULT_TYPE_DATA) {
        return 1;
    }

    /* Ideally, we wouldn't get non-matching interval markers. But
     * we can at least use the interval number to try and resolve
     * the issue.
     */
    if (t1 == CORSARO_RESULT_TYPE_START_INTERVAL) {
        corsaro_interval_t *int1 = (corsaro_interval_t *)(res1->resdata);
        corsaro_interval_t *int2 = (corsaro_interval_t *)(res2->resdata);

        if (t2 == CORSARO_RESULT_TYPE_START_INTERVAL) {
            if (int1->number < int2->number) {
                return -1;
            } else if (int1->number > int2->number) {
                return 1;
            } else {
                /* Don't care, these are the same interval. Return -1
                 * to avoid falling through to the plugin compare
                 * function.
                 */
                return -1;
            }
        } else if (t2 == CORSARO_RESULT_TYPE_END_INTERVAL) {
            if (int1->number < int2->number) {
                return -1;
            } else if (int1->number > int2->number) {
                return 1;
            } else {
                return -1;
            }
        }
    }

    if (t1 == CORSARO_RESULT_TYPE_END_INTERVAL) {
        corsaro_interval_t *int1 = (corsaro_interval_t *)(res1->resdata);
        corsaro_interval_t *int2 = (corsaro_interval_t *)(res2->resdata);

        if (t2 == CORSARO_RESULT_TYPE_END_INTERVAL) {
            if (int1->number < int2->number) {
                return -1;
            } else if (int1->number > int2->number) {
                return 1;
            } else {
                /* Don't care, these are the same interval. Return -1
                 * to avoid falling through to the plugin compare
                 * function.
                 */
                return -1;
            }
        } else if (t2 == CORSARO_RESULT_TYPE_START_INTERVAL) {
            if (int1->number < int2->number) {
                return -1;
            } else if (int1->number > int2->number) {
                return 1;
            } else {
                return 1;
            }
        }
    }

    /* Up to the plugin to handle group comparisons */
    if (t1 == CORSARO_RESULT_TYPE_START_GROUP) {
        if (t2 == CORSARO_RESULT_TYPE_START_GROUP) {
            return 0;
        } else if (t2 == CORSARO_RESULT_TYPE_END_GROUP) {
            return 0;
        }
    }

    if (t1 == CORSARO_RESULT_TYPE_END_GROUP) {
        if (t2 == CORSARO_RESULT_TYPE_END_GROUP) {
            return 0;
        } else if (t2 == CORSARO_RESULT_TYPE_START_GROUP) {
            return 0;
        }
    }

    /* If we get here, we've got two types that don't really make
     * sense to compare against each other?
     */

    corsaro_log(logger, "Bad result type comparison: %d vs %d", t1, t2);
    /* TODO better error handling -- this really shouldn't happen though */
    assert(0);

}

static int find_next_merge_result(corsaro_plugin_t *p, void *plocal,
        corsaro_file_in_t **readers, corsaro_plugin_result_t *results,
        int tcount) {

    int i, ret;
    corsaro_plugin_result_t *cand = NULL;
    int candind = -1;

    /* TODO implement */
    for (i = 0; i < tcount; i++) {
        if (readers[i] == NULL) {
            /* no more results from this source */
            continue;
        }

        if (results[i].type == CORSARO_RESULT_TYPE_BLANK) {
            /* need a fresh result */
            ret = p->read_result(p, plocal, readers[i], &(results[i]));
            if (ret == -1) {
                /* some error occurred? */
                /* close the reader I guess... */
                corsaro_file_rclose(readers[i]);
                readers[i] = NULL;
                results[i].type = CORSARO_RESULT_TYPE_EOF;
                continue;
            }
        }

        if (results[i].type == CORSARO_RESULT_TYPE_EOF) {
            /* Reached EOF for this source. */
            /* TODO delete the file?? */
            corsaro_file_rclose(readers[i]);
            readers[i] = NULL;
            results[i].type = CORSARO_RESULT_TYPE_EOF;
            continue;
        }

        if (cand == NULL) {
            cand = &(results[i]);
            candind = i;
            continue;
        }

        ret = compare_results_common(cand, &(results[i]), p->logger);

        if (ret > 0) {
            cand = &(results[i]);
            candind = i;
        } else if (ret == 0) {
            if (p->compare_results(p, plocal, cand, &(results[i])) > 0) {
                cand = &(results[i]);
                candind = i;
            }
        }
    }

    if (candind == -1) {
        /* All of our sources have no more results */
        /* return tcount to indicate that there are no more results, i.e. EOF
         * for all readers.
         */
        return tcount;
    }

    return candind;
}

static inline int is_boundary_result(corsaro_result_type_t rt) {

    if (rt == CORSARO_RESULT_TYPE_START_INTERVAL) {
        return 1;
    }

    if (rt == CORSARO_RESULT_TYPE_END_INTERVAL) {
        return 1;
    }

    if (rt == CORSARO_RESULT_TYPE_START_GROUP) {
        return 1;
    }

    if (rt == CORSARO_RESULT_TYPE_END_GROUP) {
        return 1;
    }

    return 0;

}

int corsaro_merge_plugin_outputs(corsaro_logger_t *logger,
        corsaro_plugin_t *plist, corsaro_fin_interval_t *fin, int count)
{

    corsaro_plugin_set_t *pset;
    corsaro_plugin_t *p = NULL;
    int index = 0;
    corsaro_file_in_t **readers = NULL;
    corsaro_file_t *output = NULL;
    corsaro_plugin_result_t *results = NULL;
    int i;
    int errors = 0;

    corsaro_log(logger, "commencing merge for all plugins %u:%u.", fin->interval_id, fin->timestamp);

    pset = corsaro_start_plugins(logger, plist, count, CORSARO_READER_API,
            9999);
    if (pset == NULL) {
        corsaro_log(logger,
                "error while starting plugins for merging output.");
        return 1;
    }

    readers = (corsaro_file_in_t **)calloc(1, fin->threads_ended *
            sizeof(corsaro_file_in_t *));
    results = (corsaro_plugin_result_t *)calloc(1, fin->threads_ended *
            sizeof(corsaro_plugin_result_t));

    p = pset->active_plugins;
    while (p != NULL) {
        int nextresind;

        corsaro_log(logger, "commencing merge for plugin %s", p->name);

        output = p->open_output_file(p, pset->plugin_state[index],
                fin->timestamp, -1);
        if (output == NULL) {
            corsaro_log(logger,
                    "unable to open %s output file for merge output.",
                    p->name);
            errors ++;
            p = p->next;
            continue;
        }

        for (i = 0; i < fin->threads_ended; i++) {
            char *fname = p->derive_output_name(p,
                    pset->plugin_state[index], fin->timestamp, i);
            readers[i] = corsaro_file_ropen(logger, fname);

            if (readers[i] == NULL) {
                corsaro_log(logger,
                        "error while opening %s file as input for merging.",
                        p->name);
                errors ++;
            }
        }

        do {
            nextresind = find_next_merge_result(p, pset->plugin_state[index],
                    readers, results, fin->threads_ended);

            if (nextresind >= fin->threads_ended) {
                /* no more results, close file and move onto next plugin */
                break;
            }

            if (p->write_result(p, pset->plugin_state[index],
                    &(results[nextresind]), output) < 0) {
                /* Something went wrong with the writing */
                corsaro_log(logger,
                        "error while writing %s result to merged result file.",
                        p->name);
                errors ++;

                /* This output file is probably screwed so just bail on this
                 * one and hope someone is checking the logs.
                 */
                break;
            }


            /* If the 'earliest' result is an interval marker, all next results
             * must be interval markers -- so every reader needs to read next
             * time round.
             */

            if (is_boundary_result(results[nextresind].type)) {
                for (i = 0; i < fin->threads_ended; i++) {
                    if (results[i].type == CORSARO_RESULT_TYPE_EOF) {
                        continue;
                    }
                    p->release_result(p, pset->plugin_state[index],
                            &(results[i]));
                    results[i].type = CORSARO_RESULT_TYPE_BLANK;
                }
            } else {

                /* Otherwise, 'earliest' is a single result -- just blank that
                 * result. */
                p->release_result(p, pset->plugin_state[index],
                        &(results[nextresind]));
                results[nextresind].type = CORSARO_RESULT_TYPE_BLANK;
            }

        } while (nextresind < fin->threads_ended);


        /* Should be unnecessary, but just to be safe */
        for (i = 0; i < fin->threads_ended; i++) {
            if (readers[i] != NULL) {
                corsaro_file_rclose(readers[i]);
            }
        }
        corsaro_file_close(output);

        p = p->next;
        index ++;
    }

    free(readers);
    free(results);
    corsaro_stop_plugins(pset);
    corsaro_log(logger, "completed merge for all plugins %u:%u.", fin->interval_id, fin->timestamp);
    return errors;

}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
