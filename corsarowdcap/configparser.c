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
#include "corsarowdcap.h"

#include <libtrace.h>
#include <yaml.h>

static int grab_corsaro_filename_template(corsaro_wdcap_global_t *glob,
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

static int parse_remaining_config(corsaro_wdcap_global_t *glob,
        yaml_document_t *doc, yaml_node_t *key, yaml_node_t *value) {

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
        && !strcmp((char *)key->data.scalar.value, "writestats")) {
        if (parse_onoff_option(glob->logger, (char *)value->data.scalar.value,
                &(glob->writestats), "write stats file") < 0) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "stripvlans")) {
        if (parse_onoff_option(glob->logger, (char *)value->data.scalar.value,
                &(glob->stripvlans), "strip vlans") < 0) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "monitorid")) {
        glob->monitorid = strdup((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "inputuri")) {
        glob->inputuri = strdup((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "fileformat")) {
        glob->fileformat = strdup((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "pidfile")) {
        glob->pidfile = strdup((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "interval")) {
        glob->interval = strtoul((char *)value->data.scalar.value, NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "consterfframing")) {
        glob->consterfframing = strtol((char *)value->data.scalar.value,
                NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "compresslevel")) {
        uint32_t level = strtoul((char *)value->data.scalar.value, NULL, 10);

        if (level > 9) {
            corsaro_log(glob->logger, "bad compression level %u, must be between 0 and 9 inclusive -- ignoring.", level);
        } else {
            glob->compress_level = level;
        }
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "compressmethod")) {
        if (strcmp((char *)value->data.scalar.value, "gzip") == 0) {
            glob->compress_method = TRACE_OPTION_COMPRESSTYPE_ZLIB;
        }
        if (strcmp((char *)value->data.scalar.value, "zlib") == 0) {
            glob->compress_method = TRACE_OPTION_COMPRESSTYPE_ZLIB;
        }
        if (strcmp((char *)value->data.scalar.value, "bzip") == 0) {
            glob->compress_method = TRACE_OPTION_COMPRESSTYPE_BZ2;
        }
        if (strcmp((char *)value->data.scalar.value, "bzip2") == 0) {
            glob->compress_method = TRACE_OPTION_COMPRESSTYPE_BZ2;
        }
        if (strcmp((char *)value->data.scalar.value, "lzo") == 0) {
            glob->compress_method = TRACE_OPTION_COMPRESSTYPE_LZO;
        }
        if (strcmp((char *)value->data.scalar.value, "lzma") == 0) {
            glob->compress_method = TRACE_OPTION_COMPRESSTYPE_LZMA;
        }

        /* TODO zstd and lz4, once libtrace supports them properly */
#if 0
        if (strcmp((char *)value->data.scalar.value, "zstd") == 0) {
            glob->compress_method = TRACE_OPTION_COMPRESSTYPE_ZSTD;
        }
        if (strcmp((char *)value->data.scalar.value, "lz4") == 0) {
            glob->compress_method = TRACE_OPTION_COMPRESSTYPE_LZ4;
        }
#endif
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "threads")) {
        glob->threads = strtoul((char *)value->data.scalar.value, NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "mergethreads")) {
        glob->merge_threads = strtoul((char *)value->data.scalar.value, NULL,
                10);
        if (glob->merge_threads < 1) {
            corsaro_log(glob->logger, "configuration error: you must have at least one merge thread!");
            corsaro_log(glob->logger, "setting mergethreads to 1...");
            glob->merge_threads = 1;
        }
    }

    return 1;
}

static void log_configuration(corsaro_wdcap_global_t *glob) {
    corsaro_log(glob->logger, "running on monitor %s", glob->monitorid);
    corsaro_log(glob->logger, "using %d processing threads", glob->threads);
    corsaro_log(glob->logger, "using %d merging threads", glob->merge_threads);
    corsaro_log(glob->logger, "reading from %s\n", glob->inputuri);
    corsaro_log(glob->logger, "interval length is set to %u seconds",
            glob->interval);
    if (glob->consterfframing >= 0) {
        corsaro_log(glob->logger, "assuming constant ERF framing length of %d",
                glob->consterfframing);
    }

    if (glob->compress_level == 0 ||
            glob->compress_method == TRACE_OPTION_COMPRESSTYPE_NONE) {
        corsaro_log(glob->logger, "writing uncompressed files");
    } else {
        char *method="unknown";
        switch(glob->compress_method) {
            case TRACE_OPTION_COMPRESSTYPE_ZLIB:
                method = "gzip";
                break;
            case TRACE_OPTION_COMPRESSTYPE_BZ2:
                method = "bzip2";
                break;
            case TRACE_OPTION_COMPRESSTYPE_LZO:
                method = "lzo";
                break;
            case TRACE_OPTION_COMPRESSTYPE_LZMA:
                method = "lzma";
                break;
        }
        corsaro_log(glob->logger, "writing %s-compressed files using level %u",
                method, glob->compress_level);
    }

    corsaro_log(glob->logger, "rotating files every interval");
    if (glob->fileformat) {
        corsaro_log(glob->logger, "writing files using the %s format",
                glob->fileformat);
    } else {
        corsaro_log(glob->logger, "writing files using the pcapfile format");
    }

    corsaro_log(glob->logger, "stripping vlans has been %s",
            glob->stripvlans ? "enabled" : "disabled");
    corsaro_log(glob->logger, "stats output file creation has been %s",
            glob->writestats ? "enabled" : "disabled");
    corsaro_log(glob->logger, "pid file is set to %s", glob->pidfile);
}

static int parse_corsaro_wdcap_config(corsaro_wdcap_global_t *glob,
        char *configfile,
        int (*parsefunc)(corsaro_wdcap_global_t *,
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


corsaro_wdcap_global_t *corsaro_wdcap_init_global(char *filename, int logmode) {
    corsaro_wdcap_global_t *glob = NULL;

    /* Allocate memory for global variables */
    glob = (corsaro_wdcap_global_t *)malloc(sizeof(corsaro_wdcap_global_t));

    if (glob == NULL) {
        fprintf(stderr,
            "corsarowdcap: failed to malloc memory for global variables.\n");
        return NULL;
    }

    /* Initialise all globals */
    glob->interval = 300;
    glob->template =  NULL;
    glob->monitorid = NULL;
    glob->logmode = logmode;
    glob->logfilename = NULL;
    glob->consterfframing = CORSARO_ERF_ETHERNET_FRAMING;
    glob->threads = 8;
    glob->merge_threads = 1;
    glob->logger = NULL;
    glob->trace = NULL;
    glob->inputuri = NULL;
    glob->stripvlans = CORSARO_DEFAULT_WDCAP_STRIP_VLANS;
    glob->writestats = CORSARO_DEFAULT_WDCAP_WRITE_STATS;
    glob->threads_ended = 0;
    glob->pidfile = NULL;

    glob->compress_level = 0;
    glob->compress_method = TRACE_OPTION_COMPRESSTYPE_NONE;

    pthread_mutex_init(&(glob->globmutex), NULL);

    /* Need to grab the template first, in case we need it for logging.
     * This will mean we read the config file twice... :(
     */
    if (parse_corsaro_wdcap_config(glob, filename,
                grab_corsaro_filename_template) == -1) {
        fprintf(stderr,
            "corsarowdcap: errors while parsing configuration file %s.\n",
            filename);
        corsaro_wdcap_free_global(glob);
        return NULL;
    }

    /* Create global logger */
    if (glob->logmode == GLOBAL_LOGMODE_STDERR) {
        glob->logger = init_corsaro_logger("corsarowdcap", "");
    } else if (glob->logmode == GLOBAL_LOGMODE_SYSLOG) {
        glob->logger = init_corsaro_logger("corsarowdcap", NULL);
    } else if (glob->logmode == GLOBAL_LOGMODE_FILE) {
        if (glob->logfilename == NULL) {
            fprintf(stderr,
                "corsarowdcap: logfilename option must be present in config "
                "file if using 'file' logmode.\n");
            corsaro_wdcap_free_global(glob);
            return NULL;
        }

        glob->logger = init_corsaro_logger("corsarowdcap", glob->logfilename);
    }

    if (glob->logger == NULL && glob->logmode != GLOBAL_LOGMODE_DISABLED) {
        fprintf(stderr, "corsarowdcap: failed to create logger. Exiting.\n");
        corsaro_wdcap_free_global(glob);
        return NULL;
    }

    /* Parse config file */
    if (parse_corsaro_wdcap_config(glob, filename,
                parse_remaining_config) == -1) {
        corsaro_log(glob->logger,
            "corsarowdcap: errors while parsing configuration file %s.",
            filename);
        corsaro_wdcap_free_global(glob);
        return NULL;
    }

    if (glob->pidfile == NULL) {
        glob->pidfile = strdup(CORSARO_WDCAP_DEFAULT_PIDFILE);
    }

    log_configuration(glob);

    if (glob->template == NULL) {
        corsaro_log(glob->logger, "no output filename template has been provided, exiting.");
        corsaro_wdcap_free_global(glob);
        return NULL;
    }

    if (glob->interval == 0) {
        corsaro_log(glob->logger, "interval must be a non-zero, non-negative number of seconds, exiting.");
        corsaro_wdcap_free_global(glob);
        return NULL;
    }

    return glob;

}

void corsaro_wdcap_free_global(corsaro_wdcap_global_t *glob) {

    int i;
    if (glob == NULL) {
        return;
    }

    if (glob->monitorid) {
        free(glob->monitorid);
    }

    if (glob->inputuri) {
        free(glob->inputuri);
    }

    if (glob->template) {
        free(glob->template);
    }

    if (glob->logfilename) {
        free(glob->logfilename);
    }

    if (glob->fileformat) {
        free(glob->fileformat);
    }

    if (glob->pidfile) {
        free(glob->pidfile);
    }

    pthread_mutex_destroy(&(glob->globmutex));
    destroy_corsaro_logger(glob->logger);
    free(glob);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

