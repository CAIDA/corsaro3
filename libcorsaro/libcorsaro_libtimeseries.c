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

void init_libts_tsmq_backend(libts_tsmq_backend_t *back) {
    back->brokeruri = NULL;
    back->retries = 3;
    back->acktimeout = 60000;
    back->lookuptimeout = 30 * 60 * 1000;
    back->settimeout = 2 * 60 * 1000;
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

void clone_libts_tsmq_backend(libts_tsmq_backend_t *orig,
        libts_tsmq_backend_t *clone) {

    clone->brokeruri = strdup(orig->brokeruri);
    clone->retries = orig->retries;
    clone->acktimeout = orig->acktimeout;
    clone->lookuptimeout = orig->lookuptimeout;
    clone->settimeout = orig->settimeout;
}

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

int enable_libts_tsmq_backend(corsaro_logger_t *logger,
        timeseries_t *ts, libts_tsmq_backend_t *tsmq) {
    char *args = NULL;
    int ret;

    if (tsmq->brokeruri == NULL) {
        return 0;
    }

    args = create_libts_tsmq_option_string(logger, tsmq);
    if (args == NULL) {
        return 1;
    }

    ret = enable_libts_common(logger, ts, "tsmq", args);
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

void destroy_libts_tsmq_backend(libts_tsmq_backend_t *back) {
    if (back->brokeruri) {
        free(back->brokeruri);
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
                if (onoffopt == 0) {
                    back->flags |= (1 << DBATS_FLAGS_UPDATABLE);
                }
            }
        }
    }
    return 0;
}

int configure_libts_tsmq_backend(corsaro_logger_t *logger,
        libts_tsmq_backend_t *back, yaml_document_t *doc, yaml_node_t *node) {

    yaml_node_t *key, *value;
    yaml_node_pair_t *pair;

    if (node->type != YAML_MAPPING_NODE) {
        corsaro_log(logger, "Libtimeseries TSMQ backend config should be a map.");
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
                && strcmp((char *)key->data.scalar.value, "retries") == 0) {
            back->retries = atoi(val);
            if (back->retries < 0) {
                corsaro_log(logger, "Libtimeseries TSMQ backend: retries value of %d is invalid", back->retries);
                corsaro_log(logger, "(must be non-negative");
                corsaro_log(logger, "setting retries value to 3 instead");
                back->retries = 3;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "acktimeout") == 0) {
            back->acktimeout = atoi(val);
            if (back->acktimeout < 0) {
                corsaro_log(logger, "Libtimeseries TSMQ backend: ACK timeout value of %d is invalid", back->acktimeout);
                corsaro_log(logger, "(must be non-negative");
                corsaro_log(logger, "setting ACK timeout value to 5 sec instead");
                back->acktimeout = 5000;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "lookuptimeout") == 0) {
            back->lookuptimeout = atoi(val);
            if (back->lookuptimeout < 0) {
                corsaro_log(logger, "Libtimeseries TSMQ backend: lookup timeout of %d is invalid", back->lookuptimeout);
                corsaro_log(logger, "(must be non-negative");
                corsaro_log(logger, "setting lookup timeout to 60 sec instead");
                back->lookuptimeout = 60 * 1000;
            }
        }
        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value, "settimeout") == 0) {
            back->settimeout = atoi(val);
            if (back->settimeout < 0) {
                corsaro_log(logger, "Libtimeseries TSMQ backend: set timeout of %d is invalid", back->settimeout);
                corsaro_log(logger, "(must be non-negative");
                corsaro_log(logger, "setting set timeout to 30 sec instead");
                back->settimeout = 30 * 1000;
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

char *create_libts_tsmq_option_string(corsaro_logger_t *logger,
        libts_tsmq_backend_t *back) {

    char tmpbuf[4096];
    char opt[1024];
    char *ptr = tmpbuf;
    char *limit = tmpbuf + 4096 - 1;

    if (back->brokeruri == NULL) {
        return NULL;
    }

    tmpbuf[0] = '\0';
    if (snprintf(opt, 1024, "-b %s ", back->brokeruri) >= 1024) {
        corsaro_log(logger, "Overly large broker URI for libtimeseries TSMQ backend -- disabling TSMQ backend");
        return NULL;
    }

    ADD_TO_STRING(ptr, opt, limit, "TSMQ");

    if (snprintf(opt, 1024, "-r %d ", back->retries) >= 1024) {
        corsaro_log(logger, "Overly large numeric option for libtimeseries TSMQ backend (retries)");
        corsaro_log(logger, " -- disabling TSMQ backend");
        return NULL;
    }
    ADD_TO_STRING(ptr, opt, limit, "TSMQ");

    if (snprintf(opt, 1024, "-a %d ", back->acktimeout) >= 1024) {
        corsaro_log(logger, "Overly large numeric option for libtimeseries TSMQ backend (acktimeout)");
        corsaro_log(logger, " -- disabling TSMQ backend");
        return NULL;
    }
    ADD_TO_STRING(ptr, opt, limit, "TSMQ");

    if (snprintf(opt, 1024, "-l %d ", back->lookuptimeout) >= 1024) {
        corsaro_log(logger, "Overly large numeric option for libtimeseries TSMQ backend (lookuptimeout)");
        corsaro_log(logger, " -- disabling TSMQ backend");
        return NULL;
    }
    ADD_TO_STRING(ptr, opt, limit, "TSMQ");

    if (snprintf(opt, 1024, "-s %d ", back->settimeout) >= 1024) {
        corsaro_log(logger, "Overly large numeric option for libtimeseries TSMQ backend (settimeout)");
        corsaro_log(logger, " -- disabling TSMQ backend");
        return NULL;
    }
    ADD_TO_STRING(ptr, opt, limit, "TSMQ");

    return strdup(tmpbuf);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
