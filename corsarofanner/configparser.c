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
#include "libcorsaro_log.h"
#include "libcorsaro_common.h"
#include "corsarofanner.h"
#include <yaml.h>
#include <zmq.h>

static int parse_fanner_config(void *globalin, yaml_document_t *doc,
        yaml_node_t *key, yaml_node_t *value, corsaro_logger_t *logger) {

    corsaro_fanner_global_t *glob = (corsaro_fanner_global_t *)globalin;

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "subqueuename")) {
        glob->inputsockname = strdup((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "pubqueuename")) {
        glob->outsockname = strdup((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "inputhwm")) {
        glob->inputhwm = strtoul((char *)value->data.scalar.value, NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "threads")) {
        glob->threads = strtoul((char *)value->data.scalar.value, NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "outputhwm")) {
        glob->outputhwm = strtoul((char *)value->data.scalar.value, NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "logfilename")) {
        glob->logfilename = strdup((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "statfilename")) {
        glob->statfilename = strdup((char *)value->data.scalar.value);
    }

    return 1;
}

static void log_configuration(corsaro_fanner_global_t *glob) {
    corsaro_log(glob->logger, "setting input queue high water mark to %u",
            glob->inputhwm);
    corsaro_log(glob->logger, "setting output queue high water mark to %u",
            glob->outputhwm);
    corsaro_log(glob->logger, "subscribing to tagged packets on zeromq socket: %s",
            glob->inputsockname);
    corsaro_log(glob->logger, "fanning tagged packets out to zeromq socket: %s",
            glob->outsockname);
    corsaro_log(glob->logger, "using %u threads to consume tagged packets",
            glob->threads);

    if (glob->statfilename) {
        corsaro_log(glob->logger, "dumping internal statistics to %s",
                glob->statfilename);
    } else {
        corsaro_log(glob->logger, "NOT dumping internal statistics to a file");
    }
}

corsaro_fanner_global_t *corsaro_fanner_init_global(char *filename, int logmode)
{
    corsaro_fanner_global_t *glob = NULL;

    glob = (corsaro_fanner_global_t *)malloc(sizeof(corsaro_fanner_global_t));

    if (glob == NULL) {
        fprintf(stderr,
                "corsarofanner: failed to allocate memory for global variables!\n");
        return NULL;
    }

    glob->logmode = logmode;
    glob->logfilename = NULL;
    glob->inputhwm = 25;
    glob->outputhwm = 25;
    glob->logger = NULL;
    glob->threads = 4;
    glob->zmq_ctxt = zmq_ctx_new();
    glob->inputsockname = NULL;
    glob->outsockname = NULL;
    glob->statfilename = NULL;

    if (parse_corsaro_generic_config((void *)glob, filename, "corsarofanner",
                glob->logmode, parse_fanner_config) < 0) {
        fprintf(stderr, "corsarofanner: failed to parse configuration file %s.\n",
                filename);
        corsaro_fanner_free_global(glob);
        return NULL;
    }

    /* Create global logger */
    if (glob->logmode == GLOBAL_LOGMODE_STDERR) {
        glob->logger = init_corsaro_logger("corsarofanner", "");
    } else if (glob->logmode == GLOBAL_LOGMODE_SYSLOG) {
        glob->logger = init_corsaro_logger("corsarofanner", NULL);
    } else if (glob->logmode == GLOBAL_LOGMODE_FILE) {
        if (glob->logfilename == NULL) {
            fprintf(stderr,
                    "corsarofanner: logfilename option must be present in config "
                    "file if using 'file' logmode.\n");
            corsaro_fanner_free_global(glob);
            return NULL;
        }

        glob->logger = init_corsaro_logger("corsarofanner", glob->logfilename);
    }

    if (glob->logger == NULL && glob->logmode != GLOBAL_LOGMODE_DISABLED) {
        fprintf(stderr, "corsarofanner: failed to create logger. Exiting.\n");
        corsaro_fanner_free_global(glob);
        return NULL;
    }

    if (glob->outsockname == NULL) {
        glob->outsockname = strdup("ipc:///tmp/corsarofanner");
    }

    log_configuration(glob);
    return glob;
}

void corsaro_fanner_free_global(corsaro_fanner_global_t *glob) {
    if (glob == NULL) {
        return;
    }

    if (glob->logfilename) {
        free(glob->logfilename);
    }

    if (glob->inputsockname) {
        free(glob->inputsockname);
    }

    if (glob->outsockname) {
        free(glob->outsockname);
    }
    if (glob->zmq_ctxt) {
        zmq_ctx_destroy(glob->zmq_ctxt);
    }

    destroy_corsaro_logger(glob->logger);
    free(glob);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
