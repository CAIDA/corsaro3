/*
 * corsaro
 *
 * Alistair King, CAIDA, UC San Diego
 * Shane Alcock, WAND, University of Waikato
 *
 * corsaro-info@caida.org
 *
 * Copyright (C) 2012-2019 The Regents of the University of California.
 * All Rights Reserved.
 *
 * This file is part of corsaro.
 *
 * Permission to copy, modify, and distribute this software and its
 * documentation for academic research and education purposes, without fee, and
 * without a written agreement is hereby granted, provided that
 * the above copyright notice, this paragraph and the following paragraphs
 * appear in all copies.
 *
 * Permission to make use of this software for other than academic research and
 * education purposes may be obtained by contacting:
 *
 * Office of Innovation and Commercialization
 * 9500 Gilman Drive, Mail Code 0910
 * University of California
 * La Jolla, CA 92093-0910
 * (858) 534-5815
 * invent@ucsd.edu
 *
 * This software program and documentation are copyrighted by The Regents of the
 * University of California. The software program and documentation are supplied
 * “as is”, without any accompanying services from The Regents. The Regents does
 * not warrant that the operation of the program will be uninterrupted or
 * error-free. The end-user understands that the program was developed for
 * research purposes and is advised not to rely exclusively on the program for
 * any reason.
 *
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,
 * EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED
 * HEREUNDER IS ON AN “AS IS” BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO
 * OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 */

#include <inttypes.h>
#include "libcorsaro_libtimeseries.h"
#include "libcorsaro_common.h"

void init_libts_ascii_backend(libts_ascii_backend_t *back) {
    back->filename = NULL;
    back->compresslevel = 1;
}

void init_libts_kafka_backend(libts_kafka_backend_t *back) {
    back->brokeruri = NULL;
    back->channelname = NULL;
    back->compresscodec = NULL;
    back->topicprefix = NULL;
}

void init_libts_dbats_backend(libts_dbats_backend_t *back) {
    back->path = NULL;
    back->flags = 0;
}

void clone_libts_ascii_backend(libts_ascii_backend_t *orig,
        libts_ascii_backend_t *clone) {

    clone->filename = strdup(orig->filename);
    clone->compresslevel = orig->compresslevel;
}

void clone_libts_kafka_backend(libts_kafka_backend_t *orig,
        libts_kafka_backend_t *clone) {

    clone->channelname = strdup(orig->channelname);
    clone->brokeruri = strdup(orig->brokeruri);
    clone->compresscodec = strdup(orig->compresscodec);
    clone->topicprefix = strdup(orig->topicprefix);
}

void clone_libts_dbats_backend(libts_dbats_backend_t *orig,
        libts_dbats_backend_t *clone) {

    clone->path = strdup(orig->path);
    clone->flags = orig->flags;
}

void display_libts_ascii_options(corsaro_logger_t *logger,
        libts_ascii_backend_t *ascii, char *prepend) {

    if (ascii->filename == NULL) {
        return;
    }

    corsaro_log(logger, "%s: using ASCII backend to write to %s",
            prepend, ascii->filename);
    corsaro_log(logger, "%s: ASCII compression level: %d",
            prepend, ascii->compresslevel);

}

void display_libts_kafka_options(corsaro_logger_t *logger,
        libts_kafka_backend_t *kafka, char *prepend) {

    if (kafka->brokeruri == NULL) {
        return;
    }

    corsaro_log(logger, "%s: using Kafka backend to write to %s",
            prepend, kafka->brokeruri);
    corsaro_log(logger, "%s: Kafka channel=%s, topicprefix=%s, compresscodec=%s",
            prepend, kafka->channelname, kafka->topicprefix,
            kafka->compresscodec);
}

void display_libts_dbats_options(corsaro_logger_t *logger,
        libts_dbats_backend_t *dbats, char *prepend) {

    if (dbats->path == NULL) {
        return;
    }

    corsaro_log(logger, "%s: using DBATS backend with path %s",
            prepend, dbats->path);
    corsaro_log(logger, "%s: DBATS flags are %s %s %s %s", prepend,
            dbats->flags & (1 << DBATS_FLAGS_UNCOMPRESSED) ? "uncompressed": "compressed",
            dbats->flags & (1 << DBATS_FLAGS_EXCLUSIVE) ? "exclusive": "inclusive",
            dbats->flags & (1 << DBATS_FLAGS_NOTXN) ? "no-txn": "txn",
            dbats->flags & (1 << DBATS_FLAGS_UPDATABLE) ? "updatable": "not-updatable");
}

/** Backend-enabling code that is common to all backend formats
 *
 *  @param logger       An instance of a corsaro logger to use for reporting
 *                      errors.
 *  @param ts           The libtimeseries instance for which the backend is to
 *                      be enabled.
 *  @param backend_name The name of the backend format, e.g. "ascii" or "kafka"
 *  @param backend_args A getopt-style string containing the configuration
 *                      arguments for the backend.
 *
 *  @return 1 if an error occurs, 0 if the backend is successfully enabled
 */
static inline int enable_libts_common(corsaro_logger_t *logger,
        timeseries_t *ts, char *backend_name, char *backend_args) {

    timeseries_backend_t *backend = NULL;

    backend = timeseries_get_backend_by_name(ts, backend_name);
    if (backend == NULL) {
        corsaro_log(logger, "%s backend is not supported by libtimeseries?",
                backend_name);
        return 1;
    }

    if (timeseries_enable_backend(backend, backend_args) != 0) {
        corsaro_log(logger, "unable to enable %s backend with args '%s'",
                backend_name, backend_args);
        return 1;
    }
    return 0;
}

int enable_libts_ascii_backend(corsaro_logger_t *logger,
        timeseries_t *ts, libts_ascii_backend_t *ascii) {
    char *args = NULL;
    int ret;

    /* Simply return success if the config says this backend is inactive */
    if (ascii->filename == NULL) {
        return 0;
    }

    args = create_libts_ascii_option_string(logger, ascii);
    if (args == NULL) {
        return 1;
    }

    ret = enable_libts_common(logger, ts, "ascii", args);
    free(args);
    return ret;
}

int enable_libts_kafka_backend(corsaro_logger_t *logger,
        timeseries_t *ts, libts_kafka_backend_t *kafka) {
    char *args = NULL;
    int ret;

    /* Simply return success if the config says this backend is inactive */
    if (kafka->brokeruri == NULL) {
        return 0;
    }

    args = create_libts_kafka_option_string(logger, kafka);
    if (args == NULL) {
        return 1;
    }

    ret = enable_libts_common(logger, ts, "kafka", args);
    free(args);
    return ret;
}

int enable_libts_dbats_backend(corsaro_logger_t *logger,
        timeseries_t *ts, libts_dbats_backend_t *dbats) {
    char *args = NULL;
    int ret;

    /* Simply return success if the config says this backend is inactive */
    if (dbats->path == NULL) {
        return 0;
    }

    args = create_libts_dbats_option_string(logger, dbats);
    if (args == NULL) {
        return 1;
    }

    ret = enable_libts_common(logger, ts, "dbats", args);
    free(args);
    return ret;
}

void destroy_libts_ascii_backend(libts_ascii_backend_t *back) {
    if (back->filename) {
        free(back->filename);
    }
}

void destroy_libts_kafka_backend(libts_kafka_backend_t *back) {
    if (back->brokeruri) {
        free(back->brokeruri);
    }
    if (back->channelname) {
        free(back->channelname);
    }
    if (back->compresscodec) {
        free(back->compresscodec);
    }
    if (back->topicprefix) {
        free(back->topicprefix);
    }
}

void destroy_libts_dbats_backend(libts_dbats_backend_t *back) {
    if (back->path) {
        free(back->path);
    }
}

int configure_libts_ascii_backend(corsaro_logger_t *logger,
        libts_ascii_backend_t *back, yaml_document_t *doc, yaml_node_t *node) {

    yaml_node_t *key, *value;
    yaml_node_pair_t *pair;

    if (node->type != YAML_MAPPING_NODE) {
        corsaro_log(logger, "Libtimeseries ASCII backend config should be a map.");
        return -1;
    }

    for (pair = node->data.mapping.pairs.start;
            pair < node->data.mapping.pairs.top; pair ++) {

        char *val;
        key = yaml_document_get_node(doc, pair->key);
        value = yaml_document_get_node(doc, pair->value);

        val = (char *)value->data.scalar.value;

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "file") == 0) {
            if (back->filename) {
                free(back->filename);
            }
            back->filename = strdup(val);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "compress") == 0) {
            back->compresslevel = atoi(val);
            if (back->compresslevel < 0 || back->compresslevel > 9) {
                corsaro_log(logger, "Libtimeseries ASCII backend: compress value of %d is invalid", back->compresslevel);
                corsaro_log(logger, "(must be 0-9 inclusive)");
                corsaro_log(logger, "setting compress level to 1 instead");
                back->compresslevel = 1;
            }
        }
    }
    return 0;
}

int configure_libts_kafka_backend(corsaro_logger_t *logger,
        libts_kafka_backend_t *back, yaml_document_t *doc, yaml_node_t *node) {

    yaml_node_t *key, *value;
    yaml_node_pair_t *pair;

    if (node->type != YAML_MAPPING_NODE) {
        corsaro_log(logger, "Libtimeseries Kafka backend config should be a map.");
        return -1;
    }

    for (pair = node->data.mapping.pairs.start;
            pair < node->data.mapping.pairs.top; pair ++) {

        char *val;
        key = yaml_document_get_node(doc, pair->key);
        value = yaml_document_get_node(doc, pair->value);

        val = (char *)value->data.scalar.value;

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "brokeruri") == 0) {
            if (back->brokeruri) {
                free(back->brokeruri);
            }
            back->brokeruri = strdup(val);
        }
        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "channelname") == 0) {
            if (back->channelname) {
                free(back->channelname);
            }
            back->channelname = strdup(val);
        }
        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "compresscodec") == 0) {
            if (back->compresscodec) {
                free(back->compresscodec);
            }
            back->compresscodec = strdup(val);
        }
        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "topicprefix") == 0) {
            if (back->topicprefix) {
                free(back->topicprefix);
            }
            back->topicprefix = strdup(val);
        }
    }

    if (back->brokeruri) {
        if (back->channelname == NULL) {
            back->channelname = strdup("default");
        }
        if (back->compresscodec == NULL) {
            back->compresscodec = strdup("snappy");
        }
        if (back->topicprefix == NULL) {
            back->topicprefix = strdup("");
        }
    }

    return 0;
}

int configure_libts_dbats_backend(corsaro_logger_t *logger,
        libts_dbats_backend_t *back, yaml_document_t *doc, yaml_node_t *node) {

    yaml_node_t *key, *value;
    yaml_node_pair_t *pair;

    if (node->type != YAML_MAPPING_NODE) {
        corsaro_log(logger, "Libtimeseries DBATS backend config should be a map.");
        return -1;
    }

    for (pair = node->data.mapping.pairs.start;
            pair < node->data.mapping.pairs.top; pair ++) {

        char *val;
        key = yaml_document_get_node(doc, pair->key);
        value = yaml_document_get_node(doc, pair->value);
        uint8_t onoffopt = 0;

        val = (char *)value->data.scalar.value;

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "path") == 0) {
            if (back->path) {
                free(back->path);
            }
            back->path = strdup(val);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "compression") == 0) {
            if (parse_onoff_option(logger, val, &onoffopt, "compression")
                    == 0) {
                if (onoffopt == 0) {
                    back->flags |= (1 << DBATS_FLAGS_UNCOMPRESSED);
                }
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "exclusive") == 0) {
            if (parse_onoff_option(logger, val, &onoffopt, "exclusive")
                    == 0) {
                if (onoffopt == 1) {
                    back->flags |= (1 << DBATS_FLAGS_EXCLUSIVE);
                }
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "transactions") == 0) {
            if (parse_onoff_option(logger, val, &onoffopt, "transactions")
                    == 0) {
                if (onoffopt == 0) {
                    back->flags |= (1 << DBATS_FLAGS_NOTXN);
                }
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "updatable") == 0) {
            if (parse_onoff_option(logger, val, &onoffopt, "updatable")
                    == 1) {
                if (onoffopt == 1) {
                    back->flags |= (1 << DBATS_FLAGS_UPDATABLE);
                }
            }
        }
    }
    return 0;
}

#define ADD_TO_STRING(ptr, opt, limit, backend) \
    if (strlen(opt) > limit - ptr) { \
        corsaro_log(logger, "Libtimeseries %s backend: arguments exceed 4096 bytes in total?", backend); \
        corsaro_log(logger, " - disabling %s backend", backend); \
        return NULL; \
    } \
    strncat(ptr, opt, limit-ptr); \
    ptr += strlen(opt);

char *create_libts_ascii_option_string(corsaro_logger_t *logger,
        libts_ascii_backend_t *back) {

    char tmpbuf[4096];
    char opt[1024];
    char *ptr = tmpbuf;
    char *limit = tmpbuf + 4096 - 1;

    tmpbuf[0] = '\0';
    if (back->filename == NULL) {
        return NULL;
    }

    if (snprintf(opt, 1024, "-f %s ", back->filename) >= 1024) {
        corsaro_log(logger, "Overly large filename for libtimeseries ASCII backend");
        corsaro_log(logger, " -- disabling ASCII backend");
        return NULL;
    }

    ADD_TO_STRING(ptr, opt, limit, "ASCII");

    if (snprintf(opt, 1024, "-c %d ", back->compresslevel) >= 1024) {
        corsaro_log(logger, "Overly large numeric value for libtimeseries ASCII backend (compress level)");
        corsaro_log(logger, " -- disabling ASCII backend");
        return NULL;
    }

    ADD_TO_STRING(ptr, opt, limit, "ASCII");
    return strdup(tmpbuf);
}

char *create_libts_kafka_option_string(corsaro_logger_t *logger,
        libts_kafka_backend_t *back) {

    char tmpbuf[4096];
    char opt[1024];
    char *ptr = tmpbuf;
    char *limit = tmpbuf + 4096 - 1;

    if (back->brokeruri == NULL) {
        return NULL;
    }

    tmpbuf[0] = '\0';
    if (snprintf(opt, 1024, "-b %s ", back->brokeruri) >= 1024) {
        corsaro_log(logger, "Overly large broker URI for libtimeseries Kafka backend");
        corsaro_log(logger, " -- disabling Kafka backend");
        return NULL;
    }

    ADD_TO_STRING(ptr, opt, limit, "Kafka");

    if (snprintf(opt, 1024, "-c %s ", back->channelname) >= 1024) {
        corsaro_log(logger, "Overly large channel name for libtimeseries Kafka backend");
        corsaro_log(logger, " -- disabling Kafka backend");
        return NULL;
    }

    ADD_TO_STRING(ptr, opt, limit, "Kafka");

    if (snprintf(opt, 1024, "-C %s ", back->compresscodec) >= 1024) {
        corsaro_log(logger, "Overly large compression codec for libtimeseries Kafka backend");
        corsaro_log(logger, " -- disabling Kafka backend");
        return NULL;
    }

    ADD_TO_STRING(ptr, opt, limit, "Kafka");

    if (snprintf(opt, 1024, "-p %s ", back->topicprefix) >= 1024) {
        corsaro_log(logger, "Overly large topic prefix for libtimeseries Kafka backend");
        corsaro_log(logger, " -- disabling Kafka backend");
        return NULL;
    }

    ADD_TO_STRING(ptr, opt, limit, "Kafka");
    return strdup(tmpbuf);
}

char *create_libts_dbats_option_string(corsaro_logger_t *logger,
        libts_dbats_backend_t *back) {

    char tmpbuf[4096];
    char opt[1024];
    char *ptr = tmpbuf;
    char *limit = tmpbuf + 4096 - 1;

    if (back->path == NULL) {
        return NULL;
    }

    tmpbuf[0] = '\0';
    if (snprintf(opt, 1024, "-p %s ", back->path) >= 1024) {
        corsaro_log(logger, "Overly large path for libtimeseries DBATS backend - disabling DBATS backend");
        return NULL;
    }

    ADD_TO_STRING(ptr, opt, limit, "DBATS");

    if (back->flags & (1 << DBATS_FLAGS_UNCOMPRESSED)) {
        ADD_TO_STRING(ptr, "-f FLAG_UNCOMRESSED ", limit, "DBATS");
    }

    if (back->flags & (1 << DBATS_FLAGS_EXCLUSIVE)) {
        ADD_TO_STRING(ptr, "-f FLAG_EXCLUSIVE ", limit, "DBATS");
    }

    if (back->flags & (1 << DBATS_FLAGS_NOTXN)) {
        ADD_TO_STRING(ptr, "-f FLAG_NO_TXN ", limit, "DBATS");
    }

    if (back->flags & (1 << DBATS_FLAGS_UPDATABLE)) {
        ADD_TO_STRING(ptr, "-f FLAG_UPDATABLE ", limit, "DBATS");
    }
    return strdup(tmpbuf);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
