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


#ifndef LIBCORSARO_LIBTIMESERIES_H_
#define LIBCORSARO_LIBTIMESERIES_H_

#include "libcorsaro_log.h"
#include <inttypes.h>
#include <yaml.h>
#include <timeseries.h>

enum {
    DBATS_FLAGS_UNCOMPRESSED,
    DBATS_FLAGS_EXCLUSIVE,
    DBATS_FLAGS_NOTXN,
    DBATS_FLAGS_UPDATABLE
};

typedef struct libts_ascii_backend {
    char *filename;         /* NULL if inactive */
    int compresslevel;
} libts_ascii_backend_t;

typedef struct libts_kafka_backend {
    char *brokeruri;        /* NULL if inactive */
    char *channelname;
    char *compresscodec;
    char *topicprefix;
} libts_kafka_backend_t;

typedef struct libts_dbats_backend {
    char *path;             /* NULL if inactive */
    uint32_t flags;
} libts_dbats_backend_t;

typedef struct libts_tsmq_backend {
    char *brokeruri;        /* NULL if inactive */
    int retries;
    int acktimeout;
    int lookuptimeout;
    int settimeout;
} libts_tsmq_backend_t;

void init_libts_ascii_backend(libts_ascii_backend_t *back);
void init_libts_kafka_backend(libts_kafka_backend_t *back);
void init_libts_dbats_backend(libts_dbats_backend_t *back);
void init_libts_tsmq_backend(libts_tsmq_backend_t *back);

int configure_libts_ascii_backend(corsaro_logger_t *logger,
        libts_ascii_backend_t *back,
        yaml_document_t *doc, yaml_node_t *node);
int configure_libts_kafka_backend(corsaro_logger_t *logger,
        libts_kafka_backend_t *back,
        yaml_document_t *doc, yaml_node_t *node);
int configure_libts_dbats_backend(corsaro_logger_t *logger,
        libts_dbats_backend_t *back,
        yaml_document_t *doc, yaml_node_t *node);
int configure_libts_tsmq_backend(corsaro_logger_t *logger,
        libts_tsmq_backend_t *back,
        yaml_document_t *doc, yaml_node_t *node);

void clone_libts_ascii_backend(libts_ascii_backend_t *orig,
        libts_ascii_backend_t *clone);
void clone_libts_kafka_backend(libts_kafka_backend_t *orig,
        libts_kafka_backend_t *clone);
void clone_libts_dbats_backend(libts_dbats_backend_t *orig,
        libts_dbats_backend_t *clone);
void clone_libts_tsmq_backend(libts_tsmq_backend_t *orig,
        libts_tsmq_backend_t *clone);

int enable_libts_ascii_backend(corsaro_logger_t *logger,
        timeseries_t *ts, libts_ascii_backend_t *ascii);
int enable_libts_kafka_backend(corsaro_logger_t *logger,
        timeseries_t *ts, libts_kafka_backend_t *kafka);
int enable_libts_dbats_backend(corsaro_logger_t *logger,
        timeseries_t *ts, libts_dbats_backend_t *dbats);
int enable_libts_tsmq_backend(corsaro_logger_t *logger,
        timeseries_t *ts, libts_tsmq_backend_t *tsmq);

void destroy_libts_ascii_backend(libts_ascii_backend_t *back);
void destroy_libts_kafka_backend(libts_kafka_backend_t *back);
void destroy_libts_dbats_backend(libts_dbats_backend_t *back);
void destroy_libts_tsmq_backend(libts_tsmq_backend_t *back);

char *create_libts_ascii_option_string(corsaro_logger_t *logger,
        libts_ascii_backend_t *back);
char *create_libts_kafka_option_string(corsaro_logger_t *logger,
        libts_kafka_backend_t *back);
char *create_libts_dbats_option_string(corsaro_logger_t *logger,
        libts_dbats_backend_t *back);
char *create_libts_tsmq_option_string(corsaro_logger_t *logger,
        libts_tsmq_backend_t *back);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
