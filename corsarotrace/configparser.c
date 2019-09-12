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
#include "libcorsaro_log.h"
#include "libcorsaro_common.h"
#include "libcorsaro_plugin.h"
#include "corsarotrace.h"
#include "libcorsaro_libtimeseries.h"

#include <yaml.h>
#include <zmq.h>

static corsaro_plugin_t *allplugins = NULL;

static void parse_libtimeseries_config(corsaro_trace_global_t *glob,
        yaml_document_t *doc, yaml_node_t *backendlist) {

    yaml_node_item_t *item;

    for (item = backendlist->data.sequence.items.start;
            item != backendlist->data.sequence.items.top; item ++) {

        yaml_node_t *node = yaml_document_get_node(doc, *item);
        yaml_node_pair_t *pair;

        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;
            char *backend_type = NULL;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            /* key = backend name */
            /* value = map of backend options */

            backend_type = (char *)key->data.scalar.value;

            if (strcasecmp(backend_type, "ascii") == 0) {
                configure_libts_ascii_backend(glob->logger,
                        &(glob->libtsascii), doc, value);
            } else if (strcasecmp(backend_type, "kafka") == 0) {
                configure_libts_kafka_backend(glob->logger,
                        &(glob->libtskafka), doc, value);
            } else if (strcasecmp(backend_type, "dbats") == 0) {
                configure_libts_dbats_backend(glob->logger,
                        &(glob->libtsdbats), doc, value);
            } else {
                corsaro_log(glob->logger, "unknown libtimeseries backend '%s'",
                        backend_type);
                corsaro_log(glob->logger, "valid backends are 'ascii', 'kafka', or 'dbats'");
            }
        }
    }
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
        if (parse_onoff_option(glob->logger, (char *)value->data.scalar.value,
                &(glob->removespoofed), "remove spoofed") < 0) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "removeerratic")) {
        if (parse_onoff_option(glob->logger, (char *)value->data.scalar.value,
                &(glob->removeerratic), "remove erratic") < 0) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "removenotscan")) {
        if (parse_onoff_option(glob->logger, (char *)value->data.scalar.value,
                &(glob->removenotscan), "remove not scan") < 0) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "removerouted")) {
        if (parse_onoff_option(glob->logger, (char *)value->data.scalar.value,
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
            && !strcmp((char *)key->data.scalar.value, "controlsocketname")) {
        glob->control_uri = strdup((char *)value->data.scalar.value);
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
            && !strcmp((char *)key->data.scalar.value, "inputhwm")) {
        glob->inputhwm = strtoul((char *)value->data.scalar.value, NULL, 10);
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

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SEQUENCE_NODE
            && !strcmp((char *)key->data.scalar.value,
                        "libtimeseriesbackends")) {
        parse_libtimeseries_config(glob, doc, value);
    }

    return 1;
}

static void log_configuration(corsaro_trace_global_t *glob) {
    corsaro_log(glob->logger, "running on monitor %s", glob->monitorid);
    corsaro_log(glob->logger, "using %d processing threads", glob->threads);
    corsaro_log(glob->logger, "setting input queue high water mark to %u",
            glob->inputhwm);
    corsaro_log(glob->logger, "interval length is set to %u seconds",
            glob->interval);
    corsaro_log(glob->logger, "rotating files every %u intervals",
            glob->rotatefreq);
    corsaro_log(glob->logger, "subscribing to tagged packets on %s zeromq socket: %s",
            (glob->subsource == CORSARO_TRACE_SOURCE_FANNER ? "fanner" : "tagger"),
            glob->subqueuename);
    corsaro_log(glob->logger, "connecting to corsarotagger control socket: %s",
            glob->control_uri);

    if (glob->boundstartts != 0) {
        corsaro_log(glob->logger, "ignoring all packets before timestamp %u",
                glob->boundstartts);
    }

    if (glob->boundendts != 0) {
        corsaro_log(glob->logger, "stopping at timestamp %u",
                glob->boundendts);
    }


    if (glob->removenotscan) {
        corsaro_log(glob->logger, "removing traffic that is not an obvious scan from the packet stream");
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
    glob->first_pkt_ts = 0;
    glob->boundstartts = 0;
    glob->boundendts = 0;
    glob->interval = 60;
    glob->rotatefreq = 4;
    glob->template =  NULL;
    glob->monitorid = NULL;
    glob->logmode = logmode;
    glob->logfilename = NULL;
    glob->threads = 4;
    glob->plugincount = 0;
    glob->inputhwm = 25;

    glob->removeerratic = 0;
    glob->removespoofed = 0;
    glob->removerouted = 0;
    glob->removenotscan = 0;

    glob->subsource = CORSARO_TRACE_SOURCE_FANNER;
    glob->logger = NULL;
    glob->subqueuename = NULL;
    glob->control_uri = NULL;
    glob->zmq_ctxt = zmq_ctx_new();

    pthread_mutex_init(&(glob->mutex), NULL);

    init_libts_ascii_backend(&(glob->libtsascii));
    init_libts_dbats_backend(&(glob->libtsdbats));
    init_libts_kafka_backend(&(glob->libtskafka));

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

    if (glob->subqueuename == NULL) {
        glob->subqueuename = strdup("ipc:///tmp/corsarofanner");
    }

    /* XXX slightly dirty hack to determine whether our packets are
     *     coming from a fanner or directly from the tagger. Assumes
     *     that we're not going to use tcp for fanner publishing sockets.
     */
    if (strncmp(glob->subqueuename, "ipc://", 6) == 0) {
        glob->subsource = CORSARO_TRACE_SOURCE_FANNER;
    } else {
        glob->subsource = CORSARO_TRACE_SOURCE_TAGGER;
    }

    if (glob->control_uri == NULL) {
        glob->control_uri = strdup(DEFAULT_CONTROL_SOCKET_URI);
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

    stdopts.template = glob->template;
    stdopts.monitorid = glob->monitorid;
    stdopts.procthreads = glob->threads;
    stdopts.libtsascii = &(glob->libtsascii);
    stdopts.libtskafka = &(glob->libtskafka);
    stdopts.libtsdbats = &(glob->libtsdbats);

    if (corsaro_finish_plugin_config(glob->active_plugins, &stdopts,
            glob->zmq_ctxt) < 0) {
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

    destroy_libts_ascii_backend(&(glob->libtsascii));
    destroy_libts_kafka_backend(&(glob->libtskafka));
    destroy_libts_dbats_backend(&(glob->libtsdbats));

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

    if (glob->control_uri) {
        free(glob->control_uri);
    }

    if (glob->zmq_ctxt) {
        zmq_ctx_destroy(glob->zmq_ctxt);
    }

    pthread_mutex_destroy(&(glob->mutex));
    destroy_corsaro_logger(glob->logger);
    free(glob);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

