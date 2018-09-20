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

#include <errno.h>

#include <libtrace/hash_toeplitz.h>
#include "libcorsaro3_log.h"
#include "libcorsaro3_plugin.h"
#include "corsarotrace.h"

#include <yaml.h>
#include <zmq.h>

static corsaro_plugin_t *allplugins = NULL;

static int parse_onoff_option(corsaro_trace_global_t *glob, char *value,
        uint8_t *opt, const char *optstr) {

    if (strcmp(value, "yes") == 0 || strcmp(value, "true") == 0 ||
            strcmp(value, "on") == 0 || strcmp(value, "enabled") == 0) {
        *opt = 1;
    }

    else if (strcmp(value, "no") == 0 || strcmp(value, "false") == 0 ||
            strcmp(value, "off") == 0 || strcmp(value, "disabled") == 0) {
        *opt = 0;
    } else {
        corsaro_log(glob->logger,
                "invalid value for '%s' option: '%s'", optstr, value);
        corsaro_log(glob->logger,
                "try using 'yes' to enable %s or 'no' to disable it.", optstr);
        return -1;
    }

    return 0;

}

static int parse_plugin_config(corsaro_trace_global_t *glob,
        yaml_document_t *doc, yaml_node_t *pluginlist) {

    yaml_node_item_t *item;
    int plugincount = 0;

    for (item = pluginlist->data.sequence.items.start;
            item != pluginlist->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        yaml_node_pair_t *pair;

        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;
            corsaro_plugin_t *orig, *p;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            /* key = plugin name */
            /* value = map of plugin options */
            orig = corsaro_find_plugin(allplugins, (char *)key->data.scalar.value);
            if (orig == NULL) {
                corsaro_log(glob->logger, "unknown plugin '%s'",
                        (char *)key->data.scalar.value);
                corsaro_log(glob->logger,
                        "please check that plugin was compiled.");
                continue;
            }

            if ((p = corsaro_enable_plugin(glob->logger, glob->active_plugins,
                        orig)) == NULL) {
                corsaro_log(glob->logger, "Unable to enable plugin '%s'",
                        (char *)key->data.scalar.value);
                continue;
            }

            if (glob->active_plugins == NULL) {
                glob->active_plugins = p;
            }

            if (corsaro_configure_plugin(p, doc, value) == -1) {
                corsaro_log(glob->logger,
                        "Error while parsing configuration options for plugin '%s'",
                        p->name);
                corsaro_disable_plugin(p);
                continue;
            }

            plugincount ++;
        }
    }

    return plugincount;
}


static int grab_corsaro_filename_template(corsaro_trace_global_t *glob,
        yaml_document_t *doc, yaml_node_t *key, yaml_node_t *value) {

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "outtemplate")) {
        glob->template = strdup((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "logfilename")) {
        glob->logfilename = strdup((char *)value->data.scalar.value);
    }

    return 1;
}

static int parse_remaining_config(corsaro_trace_global_t *glob,
        yaml_document_t *doc, yaml_node_t *key, yaml_node_t *value) {

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "removespoofed")) {
        if (parse_onoff_option(glob, (char *)value->data.scalar.value,
                &(glob->removespoofed), "remove spoofed") < 0) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "removeerratic")) {
        if (parse_onoff_option(glob, (char *)value->data.scalar.value,
                &(glob->removeerratic), "remove erratic") < 0) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "removerouted")) {
        if (parse_onoff_option(glob, (char *)value->data.scalar.value,
                &(glob->removerouted), "remove routed") < 0) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "monitorid")) {
        glob->monitorid = strdup((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "subqueuename")) {
        glob->subqueuename = strdup((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "interval")) {
        glob->interval = strtoul((char *)value->data.scalar.value, NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "rotatefreq")) {
        glob->rotatefreq = strtoul((char *)value->data.scalar.value, NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "threads")) {
        glob->threads = strtoul((char *)value->data.scalar.value, NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "startboundaryts")) {
        glob->boundstartts = strtoul((char *)value->data.scalar.value, NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "endboundaryts")) {
        glob->boundendts = strtoul((char *)value->data.scalar.value, NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SEQUENCE_NODE
            && !strcmp((char *)key->data.scalar.value, "plugins")) {
        glob->plugincount = parse_plugin_config(glob, doc, value);
        if (glob->plugincount == 0) {
            return -1;
        }
    }

    return 1;
}

static void log_configuration(corsaro_trace_global_t *glob) {
    corsaro_log(glob->logger, "running on monitor %s", glob->monitorid);
    corsaro_log(glob->logger, "using %d processing threads", glob->threads);
    corsaro_log(glob->logger, "interval length is set to %u seconds",
            glob->interval);
    corsaro_log(glob->logger, "rotating files every %u intervals",
            glob->rotatefreq);
    corsaro_log(glob->logger, "subscribing to tagged packets on zeromq socket: %s",
            glob->subqueuename);

    if (glob->boundstartts != 0) {
        corsaro_log(glob->logger, "ignoring all packets before timestamp %u",
                glob->boundstartts);
    }

    if (glob->boundendts != 0) {
        corsaro_log(glob->logger, "stopping at timestamp %u",
                glob->boundendts);
    }

    if (glob->removespoofed) {
        corsaro_log(glob->logger, "removing spoofed traffic from packet stream");
    }

    if (glob->removeerratic) {
        corsaro_log(glob->logger, "removing erratic traffic from packet stream");
    }

    if (glob->removerouted) {
        corsaro_log(glob->logger, "only included traffic from RFC 5735 addresses");
    }

}

static int parse_corsaro_trace_config(corsaro_trace_global_t *glob,
        char *configfile,
        int (*parsefunc)(corsaro_trace_global_t *,
                yaml_document_t *doc, yaml_node_t *,
                yaml_node_t *)) {

    yaml_parser_t parser;
    yaml_document_t document;
    yaml_node_t *root, *key, *value;
    yaml_node_pair_t *pair;
    FILE *in = NULL;
    int ret = 0;

    if ((in = fopen(configfile, "r")) == NULL) {
        corsaro_log(glob->logger, "Failed to open config file: %s", strerror(errno));
        return -1;
    }

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, in);

    if (!yaml_parser_load(&parser, &document)) {
        corsaro_log(glob->logger, "Malformed config file");
        ret = -1;
        goto yamlfail;
    }

    root = yaml_document_get_root_node(&document);
    if (!root) {
        corsaro_log(glob->logger, "Config file is empty!");
        ret = -1;
        goto endconfig;
    }

    if (root->type != YAML_MAPPING_NODE) {
        corsaro_log(glob->logger, "Top level of config should be a map");
        ret = -1;
        goto endconfig;
    }

    for (pair = root->data.mapping.pairs.start;
            pair < root->data.mapping.pairs.top; pair ++) {

        key = yaml_document_get_node(&document, pair->key);
        value = yaml_document_get_node(&document, pair->value);

        ret = parsefunc(glob, &document, key, value);
        if (ret <= 0) {
            break;
        }
        ret = 0;
    }

endconfig:
    yaml_document_delete(&document);
    yaml_parser_delete(&parser);

yamlfail:
    fclose(in);
    return ret;
}


corsaro_trace_global_t *corsaro_trace_init_global(char *filename, int logmode) {
    corsaro_trace_global_t *glob = NULL;
    corsaro_plugin_proc_options_t stdopts;

    /* Allocate memory for global variables */
    glob = (corsaro_trace_global_t *)malloc(sizeof(corsaro_trace_global_t));

    if (glob == NULL) {
        fprintf(stderr,
            "corsarotrace: failed to malloc memory for global variables.\n");
        return NULL;
    }

    /* Initialise all globals */
    glob->active_plugins = NULL;
    glob->boundstartts = 0;
    glob->boundendts = 0;
    glob->interval = 60;
    glob->rotatefreq = 4;
    glob->template =  NULL;
    glob->monitorid = NULL;
    glob->logmode = logmode;
    glob->logfilename = NULL;
    glob->threads = 2;
    glob->plugincount = 0;

    glob->removeerratic = 0;
    glob->removespoofed = 0;
    glob->removerouted = 0;

    glob->logger = NULL;
    glob->subqueuename = NULL;
    glob->zmq_ctxt = zmq_ctx_new();
    glob->zmq_subsock = NULL;
    glob->zmq_workersocks = NULL;

    /* Need to grab the template first, in case we need it for logging.
     * This will mean we read the config file twice... :(
     */
    if (parse_corsaro_trace_config(glob, filename,
                grab_corsaro_filename_template) == -1) {
        fprintf(stderr,
            "corsarotrace: errors while parsing configuration file %s.\n",
            filename);
        corsaro_trace_free_global(glob);
        return NULL;
    }

    /* Create global logger */
    if (glob->logmode == GLOBAL_LOGMODE_STDERR) {
        glob->logger = init_corsaro_logger("corsarotrace", "");
    } else if (glob->logmode == GLOBAL_LOGMODE_SYSLOG) {
        glob->logger = init_corsaro_logger("corsarotrace", NULL);
    } else if (glob->logmode == GLOBAL_LOGMODE_FILE) {
        if (glob->logfilename == NULL) {
            fprintf(stderr,
                "corsarotrace: logfilename option must be present in config "
                "file if using 'file' logmode.\n");
            corsaro_trace_free_global(glob);
            return NULL;
        }

        glob->logger = init_corsaro_logger("corsarotrace", glob->logfilename);
    }

    if (glob->logger == NULL && glob->logmode != GLOBAL_LOGMODE_DISABLED) {
        fprintf(stderr, "corsarotrace: failed to create logger. Exiting.\n");
        corsaro_trace_free_global(glob);
        return NULL;
    }

    /* Load all compiled plugins */
    allplugins = corsaro_load_all_plugins(glob->logger);

    /* Parse config file */
    if (parse_corsaro_trace_config(glob, filename,
                parse_remaining_config) == -1) {
        corsaro_log(glob->logger,
            "corsarotrace: errors while parsing configuration file %s.",
            filename);
        corsaro_trace_free_global(glob);
        corsaro_cleanse_plugin_list(allplugins);
        return NULL;
    }

    log_configuration(glob);

    /* Ok to cleanse this now, the config parsing above should have made
     * copies of all the plugins that we need.
     */
    corsaro_cleanse_plugin_list(allplugins);

    /* Check essential options are set */
    if (glob->active_plugins == NULL) {
        corsaro_log(glob->logger, "warning, no plugins have been loaded.");
        corsaro_log(glob->logger, "program will likely do nothing.");
    }

    if (glob->template == NULL) {
        corsaro_log(glob->logger, "no output filename template has been provided, exiting.");
        corsaro_trace_free_global(glob);
        return NULL;
    }

    if (glob->interval == 0) {
        corsaro_log(glob->logger, "interval must be a non-zero, non-negative number of seconds, exiting.");
        corsaro_trace_free_global(glob);
        return NULL;
    }

    if (glob->subqueuename == NULL) {
        glob->subqueuename = strdup("ipc:///tmp/corsarotagger");
    }

    stdopts.template = glob->template;
    stdopts.monitorid = glob->monitorid;
    stdopts.procthreads = glob->threads;

    if (corsaro_finish_plugin_config(glob->active_plugins, &stdopts) < 0) {
        corsaro_log(glob->logger,
            "error while finishing plugin configuration. Exiting.");
        corsaro_trace_free_global(glob);
        return NULL;
    }

    return glob;

}

void corsaro_trace_free_global(corsaro_trace_global_t *glob) {

    int i;
    if (glob == NULL) {
        return;
    }

    corsaro_cleanse_plugin_list(glob->active_plugins);


    if (glob->monitorid) {
        free(glob->monitorid);
    }

    if (glob->template) {
        free(glob->template);
    }

    if (glob->logfilename) {
        free(glob->logfilename);
    }

    if (glob->subqueuename) {
        free(glob->subqueuename);
    }

    if (glob->zmq_ctxt) {
        zmq_ctx_destroy(glob->zmq_ctxt);
    }

    destroy_corsaro_logger(glob->logger);
    free(glob);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

