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
#include "corsarotagger.h"

#include <zmq.h>
#include <yaml.h>

static int parse_netacq_tag_options(corsaro_logger_t *logger,
        netacq_opts_t *opts, yaml_document_t *doc, yaml_node_t *confmap) {

    yaml_node_t *key, *value;
    yaml_node_pair_t *pair;

    if (confmap->type != YAML_MAPPING_NODE) {
        corsaro_log(logger, "Netacq-edge tagging config should be a map!");
        return -1;
    }

    for (pair = confmap->data.mapping.pairs.start;
            pair < confmap->data.mapping.pairs.top; pair ++) {
        key = yaml_document_get_node(doc, pair->key);
        value = yaml_document_get_node(doc, pair->value);

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "blocksfile") == 0) {
            if (opts->blocks_file) {
                free(opts->blocks_file);
            }
            opts->blocks_file = strdup((char *)value->data.scalar.value);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "locationsfile") == 0) {
            if (opts->locations_file) {
                free(opts->locations_file);
            }
            opts->locations_file = strdup((char *)value->data.scalar.value);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "countryfile") == 0) {
            if (opts->country_file) {
                free(opts->country_file);
            }
            opts->country_file = strdup((char *)value->data.scalar.value);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "regionfile") == 0) {
            if (opts->region_file) {
                free(opts->region_file);
            }
            opts->region_file = strdup((char *)value->data.scalar.value);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "polygonmapfile") == 0) {
            if (opts->polygon_map_file) {
                free(opts->polygon_map_file);
            }
            opts->polygon_map_file = strdup((char *)value->data.scalar.value);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "polygontablefile") == 0) {
            char *copy;
            if (opts->polygon_table_files == NULL) {
                opts->polygon_table_files = libtrace_list_init(sizeof(char *));
            }
            copy = strdup((char *)key->data.scalar.value);
            libtrace_list_push_back(opts->polygon_table_files, &copy);
        }

    }

    opts->enabled = 1;
    return 0;
}

static int parse_pfx2as_tag_options(corsaro_logger_t *logger,
        pfx2asn_opts_t *opts, yaml_document_t *doc, yaml_node_t *confmap) {

    yaml_node_t *key, *value;
    yaml_node_pair_t *pair;

    if (confmap->type != YAML_MAPPING_NODE) {
        corsaro_log(logger, "Prefix->ASN tagging config should be a map!");
        return -1;
    }

    for (pair = confmap->data.mapping.pairs.start;
            pair < confmap->data.mapping.pairs.top; pair ++) {
        key = yaml_document_get_node(doc, pair->key);
        value = yaml_document_get_node(doc, pair->value);

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "prefixfile") == 0) {
            if (opts->pfx2as_file) {
                free(opts->pfx2as_file);
            }
            opts->pfx2as_file = strdup((char *)value->data.scalar.value);
        }

    }

    if (opts->pfx2as_file == NULL) {
        corsaro_log(logger,
                "Prefix->ASN tagging requires a 'prefixfile' config option.");
        return -1;
    }

    opts->enabled = 1;
    return 0;
}

static int parse_maxmind_tag_options(corsaro_logger_t *logger,
        maxmind_opts_t *opts, yaml_document_t *doc, yaml_node_t *confmap) {

    yaml_node_t *key, *value;
    yaml_node_pair_t *pair;

    if (confmap->type != YAML_MAPPING_NODE) {
        corsaro_log(logger, "Maxmind tagging config should be a map!");
        return -1;
    }

    for (pair = confmap->data.mapping.pairs.start;
            pair < confmap->data.mapping.pairs.top; pair ++) {
        key = yaml_document_get_node(doc, pair->key);
        value = yaml_document_get_node(doc, pair->value);

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "directory") == 0) {
            if (opts->directory) {
                free(opts->directory);
            }
            opts->directory = strdup((char *)value->data.scalar.value);
        }
        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "blocksfile") == 0) {
            if (opts->blocks_file) {
                free(opts->blocks_file);
            }
            opts->blocks_file = strdup((char *)value->data.scalar.value);
        }
        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "locationsfile") == 0) {
            if (opts->locations_file) {
                free(opts->locations_file);
            }
            opts->locations_file = strdup((char *)value->data.scalar.value);
        }
    }

    /* Sanity-checks */
    if (opts->directory == NULL) {
        if (opts->locations_file == NULL || opts->blocks_file == NULL) {
            corsaro_log(logger,
                    "Maxmind config: both 'locationsfile' and 'blocksfile' must be present in the config file (unless you have set 'directory' instead).");
            return -1;
        }
    } else {
        if (opts->locations_file || opts->blocks_file) {
            corsaro_log(logger,
                    "Maxmind config: 'directory' option is mutually exclusive with the 'blocksfiles' and 'locationsfile' options. Ignoring the latter options.");
        }
    }
    opts->enabled = 1;
    return 0;
}

static int parse_tagprov_config(corsaro_tagger_global_t *glob,
        yaml_document_t *doc, yaml_node_t *provlist) {

    yaml_node_item_t *item;
    int plugincount = 0;

    for (item = provlist->data.sequence.items.start;
            item != provlist->data.sequence.items.top; item ++) {
        yaml_node_t *node = yaml_document_get_node(doc, *item);
        yaml_node_pair_t *pair;

        for (pair = node->data.mapping.pairs.start;
                pair < node->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key, *value;

            ipmeta_provider_id_t provid = 0;

            key = yaml_document_get_node(doc, pair->key);
            value = yaml_document_get_node(doc, pair->value);

            /* key = provider name */
            /* value = map of provider options */
            if (strcmp((char *)key->data.scalar.value, "maxmind") == 0) {
                if (parse_maxmind_tag_options(glob->logger,
                        &(glob->maxtagopts), doc, value) != 0) {
                    corsaro_log(glob->logger,
                            "error while parsing config for Maxmind tagging");
                    continue;
                }
                provid = IPMETA_PROVIDER_MAXMIND;
            }
            if (strcmp((char *)key->data.scalar.value, "netacq-edge") == 0) {
                if (parse_netacq_tag_options(glob->logger,
                        &(glob->netacqtagopts), doc, value) != 0) {
                    corsaro_log(glob->logger,
                            "error while parsing config for Netacq-Edge tagging");
                    continue;
                }
                provid = IPMETA_PROVIDER_NETACQ_EDGE;
            }
            if (strcmp((char *)key->data.scalar.value, "pfx2as") == 0) {
                if (parse_pfx2as_tag_options(glob->logger,
                        &(glob->pfxtagopts), doc, value) != 0) {
                    corsaro_log(glob->logger,
                            "error while parsing config for Prefix->ASN tagging");
                    continue;
                }
                provid = IPMETA_PROVIDER_PFX2AS;
            }

            if (provid == 0) {
                corsaro_log(glob->logger,
                        "unrecognised tag provider name in config file: %s",
                        (char *)key->data.scalar.value);
                continue;
            }
        }
    }
    return 0;
}


static int add_uri(corsaro_tagger_global_t *glob, char *uri) {

    if (glob->totaluris == glob->alloceduris) {
        glob->inputuris = (char **)realloc(glob->inputuris,
                sizeof(char *) * (glob->alloceduris + 10));
        glob->alloceduris += 10;
    }

    if (glob->inputuris == NULL) {
        corsaro_log(glob->logger,
                "OOM while allocating space for input URIs.");
        return -1;
    }

    glob->inputuris[glob->totaluris] = strdup(uri);
    glob->totaluris ++;
    return 0;
}

static int parse_config(corsaro_tagger_global_t *glob,
        yaml_document_t *doc, yaml_node_t *key, yaml_node_t *value) {

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "inputuri")) {
        if (add_uri(glob, (char *)value->data.scalar.value) == -1) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "promisc")) {
        if (parse_onoff_option(glob->logger, (char *)value->data.scalar.value,
                &(glob->promisc), "promiscuous mode") < 0) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "dohashing")) {
        if (parse_onoff_option(glob->logger, (char *)value->data.scalar.value,
                &(glob->hasher_required), "hashing") < 0) {
            return -1;
        }
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "consterfframing")) {

        glob->consterfframing = (int)strtol((char *)value->data.scalar.value,
                NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "basicfilter")) {
        glob->filterstring = strdup((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "pubqueuename")) {
        glob->pubqueuename = strdup((char *)value->data.scalar.value);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "pktthreads")) {
        glob->pkt_threads = strtoul((char *)value->data.scalar.value, NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
            && !strcmp((char *)key->data.scalar.value, "tagthreads")) {
        glob->tag_threads = strtoul((char *)value->data.scalar.value, NULL, 10);
    }

    if (key->type == YAML_SCALAR_NODE && value->type == YAML_SEQUENCE_NODE
            && !strcmp((char *)key->data.scalar.value, "tagproviders")) {
        if (parse_tagprov_config(glob, doc, value) != 0) {
            return -1;
        }
    }

    return 1;
}

static void log_configuration(corsaro_tagger_global_t *glob) {
    corsaro_log(glob->logger, "using %d processing threads", glob->pkt_threads);
    corsaro_log(glob->logger, "using %d tagging threads", glob->tag_threads);

    if (glob->consterfframing >= 0) {
        corsaro_log(glob->logger, "using constant ERF framing size of %d",
                glob->consterfframing);
    }

    if (glob->filterstring) {
        corsaro_log(glob->logger, "applying BPF filter '%s'",
                glob->filterstring);
    }

    corsaro_log(glob->logger, "publishing tagged packets to zeromq at %s",
            glob->pubqueuename);

    if (glob->promisc) {
        corsaro_log(glob->logger, "enabling promiscuous mode on all inputs");
    }

    if (glob->pfxtagopts.enabled) {
        corsaro_log(glob->logger,
                "prefix->asn tagging will be applied to all packets");
    }

    if (glob->maxtagopts.enabled) {
        corsaro_log(glob->logger,
                "maxmind geo-location tagging will be applied to all packets");
    }

    if (glob->netacqtagopts.enabled) {
        corsaro_log(glob->logger,
                "netacq-edge geo-location tagging will be applied to all packets");
    }

}

static int parse_corsaro_tagger_config(corsaro_tagger_global_t *glob,
        char *configfile,
        int (*parsefunc)(corsaro_tagger_global_t *,
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


corsaro_tagger_global_t *corsaro_tagger_init_global(char *filename,
        int logmode) {
    corsaro_tagger_global_t *glob = NULL;

    /* Allocate memory for global variables */
    glob = (corsaro_tagger_global_t *)malloc(sizeof(corsaro_tagger_global_t));

    if (glob == NULL) {
        fprintf(stderr,
            "corsarotagger: failed to malloc memory for global variables.\n");
        return NULL;
    }

    /* Initialise all globals */
    glob->inputuris = NULL;
    glob->currenturi = 0;
    glob->totaluris = 0;
    glob->alloceduris = 0;
    glob->filterstring = NULL;
    glob->consterfframing = CORSARO_ERF_ETHERNET_FRAMING;
    glob->promisc = 0;
    glob->logmode = logmode;
    glob->logfilename = NULL;
    glob->pkt_threads = 2;
    glob->tag_threads = 2;

    glob->pubqueuename = NULL;
    glob->trace = NULL;
    glob->filter = NULL;
    glob->logger = NULL;

    glob->threaddata = NULL;
    glob->hasher = NULL;
    glob->hasher_data = NULL;
    glob->hasher_required = 0;

    memset(&(glob->pfxtagopts), 0, sizeof(pfx2asn_opts_t));
    memset(&(glob->maxtagopts), 0, sizeof(maxmind_opts_t));
    memset(&(glob->netacqtagopts), 0, sizeof(netacq_opts_t));

    glob->ipmeta = NULL;
    glob->maxmindipmeta = NULL;
    glob->netacqipmeta = NULL;
    glob->pfxipmeta = NULL;

    glob->zmq_ctxt = zmq_ctx_new();

    /* Create global logger */
    if (glob->logmode == GLOBAL_LOGMODE_STDERR) {
        glob->logger = init_corsaro_logger("corsarotagger", "");
    } else if (glob->logmode == GLOBAL_LOGMODE_SYSLOG) {
        glob->logger = init_corsaro_logger("corsarotagger", NULL);
    } else if (glob->logmode == GLOBAL_LOGMODE_FILE) {
        if (glob->logfilename == NULL) {
            fprintf(stderr,
                "corsarotagger: logfilename option must be present in config "
                "file if using 'file' logmode.\n");
            corsaro_tagger_free_global(glob);
            return NULL;
        }

        glob->logger = init_corsaro_logger("corsarotagger", glob->logfilename);
    }

    if (glob->logger == NULL && glob->logmode != GLOBAL_LOGMODE_DISABLED) {
        fprintf(stderr, "corsarotagger: failed to create logger. Exiting.\n");
        corsaro_tagger_free_global(glob);
        return NULL;
    }

    /* Parse config file */
    if (parse_corsaro_tagger_config(glob, filename,
                parse_config) == -1) {
        corsaro_log(glob->logger,
            "corsarotagger: errors while parsing configuration file %s.",
            filename);
        corsaro_tagger_free_global(glob);
        return NULL;
    }

    if (glob->pubqueuename == NULL) {
        glob->pubqueuename = strdup("ipc:///tmp/corsarotagger");
    }

    log_configuration(glob);

    if (glob->totaluris == 0) {
        corsaro_log(glob->logger, "no input URI has been provided, exiting.");
        corsaro_tagger_free_global(glob);
        return NULL;
    }

    glob->hasher = (fn_hasher)toeplitz_hash_packet;
    glob->hasher_data = calloc(1, sizeof(toeplitz_conf_t));

    /* Bidirectional hash -- set arg to 0 for unidirectional
     *
     * XXX is this a desirable config option?
     */
    toeplitz_init_config(glob->hasher_data, 1);

    return glob;

}

void corsaro_tagger_free_global(corsaro_tagger_global_t *glob) {

    int i;
    if (glob == NULL) {
        return;
    }

    if (glob->inputuris) {
        for (i = 0; i < glob->totaluris; i++) {
            free(glob->inputuris[i]);
        }
        free(glob->inputuris);
    }

    if (glob->logfilename) {
        free(glob->logfilename);
    }

    if (glob->trace) {
        trace_destroy(glob->trace);
    }

    if (glob->pubqueuename) {
        free(glob->pubqueuename);
    }

    if (glob->filter) {
        trace_destroy_filter(glob->filter);
    }

    if (glob->hasher_data) {
        free(glob->hasher_data);
    }

    if (glob->pfxtagopts.pfx2as_file) {
        free(glob->pfxtagopts.pfx2as_file);
    }

    if (glob->maxtagopts.directory) {
        free(glob->maxtagopts.directory);
    }

    if (glob->maxtagopts.blocks_file) {
        free(glob->maxtagopts.blocks_file);
    }

    if (glob->maxtagopts.locations_file) {
        free(glob->maxtagopts.locations_file);
    }

    if (glob->netacqtagopts.blocks_file) {
        free(glob->netacqtagopts.blocks_file);
    }

    if (glob->netacqtagopts.country_file) {
        free(glob->netacqtagopts.country_file);
    }

    if (glob->netacqtagopts.locations_file) {
        free(glob->netacqtagopts.locations_file);
    }

    if (glob->netacqtagopts.region_file) {
        free(glob->netacqtagopts.region_file);
    }

    if (glob->netacqtagopts.polygon_map_file) {
        free(glob->netacqtagopts.polygon_map_file);
    }

    if (glob->netacqtagopts.polygon_table_files) {
        libtrace_list_node_t *n;
        char *str;

        n = glob->netacqtagopts.polygon_table_files->head;
        while (n) {
            str = (char *)(n->data);
            free(str);
            n = n->next;
        }
        libtrace_list_deinit(glob->netacqtagopts.polygon_table_files);
    }

    if (glob->ipmeta) {
        ipmeta_free(glob->ipmeta);
    }

    if (glob->zmq_ctxt) {
        zmq_ctx_destroy(glob->zmq_ctxt);
    }

    if (glob->threaddata) {
        free(glob->threaddata);
    }

    destroy_corsaro_logger(glob->logger);
    free(glob);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

