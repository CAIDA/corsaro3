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

/** API for managing configuration of libtimeseries and each of its
 *  supported backends.
 */

/** Flags supported by DBATS as configuration options */
enum {
    DBATS_FLAGS_UNCOMPRESSED,
    DBATS_FLAGS_EXCLUSIVE,
    DBATS_FLAGS_NOTXN,
    DBATS_FLAGS_UPDATABLE
};

/** Configuration options supported by the ASCII backend */
typedef struct libts_ascii_backend {
    char *filename;         /* NULL if inactive */
    int compresslevel;
} libts_ascii_backend_t;

/** Configuration options supported by the Kafka backend */
typedef struct libts_kafka_backend {
    char *brokeruri;        /* NULL if inactive */
    char *channelname;
    char *compresscodec;
    char *topicprefix;
} libts_kafka_backend_t;

/** Configuration options supported by the DBATS backend */
typedef struct libts_dbats_backend {
    char *path;             /* NULL if inactive */
    uint32_t flags;         /* Bitmask where each bit corresponds to one of
                             * the DBATS_FLAGS_* values  */
} libts_dbats_backend_t;

/** Configuration options supported by the TSMQ backend */
typedef struct libts_tsmq_backend {
    char *brokeruri;        /* NULL if inactive */
    int retries;
    int acktimeout;         /* in milliseconds */
    int lookuptimeout;      /* in milliseconds */
    int settimeout;         /* in milliseconds */
} libts_tsmq_backend_t;

/** Initialises a set of configuration options for an ASCII backend.
 *
 *  An initialised backend is inactive until appropriately configured.
 *
 *  @param back     The backend to initialise.
 */
void init_libts_ascii_backend(libts_ascii_backend_t *back);
void init_libts_kafka_backend(libts_kafka_backend_t *back);
void init_libts_dbats_backend(libts_dbats_backend_t *back);
void init_libts_tsmq_backend(libts_tsmq_backend_t *back);

/** Parses YAML config for an ASCII backend and updates the backend
 *  configuration accordingly.
 *
 *  @param logger       An instance of a corsaro logger to use for reporting
 *                      errors.
 *  @param back         The backend to configure.
 *  @param doc          A reference to the YAML document being parsed.
 *  @param node         The YAML node containing the configuration for the
 *                      backend.
 *
 *  @return -1 if the YAML syntax in invalid, 0 if configuration is successful.
 */
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

/** Logs the current configuration options for an ASCII backend.
 *
 *  @param logger       An instance of a corsaro logger to log to.
 *  @param ascii        The ASCII backend that is having its config logged.
 *  @param prepend      A string to prepend to every log message, i.e.
 *                      an identifier for the process that is using
 *                      libtimeseries.
 */
void display_libts_ascii_options(corsaro_logger_t *logger,
        libts_ascii_backend_t *ascii, char *prepend);
void display_libts_kafka_options(corsaro_logger_t *logger,
        libts_kafka_backend_t *kafka, char *prepend);
void display_libts_dbats_options(corsaro_logger_t *logger,
        libts_dbats_backend_t *dbats, char *prepend);
void display_libts_tsmq_options(corsaro_logger_t *logger,
        libts_tsmq_backend_t *tsmq, char *prepend);

/** Performs a deep copy of an existing ASCII backend configuration.
 *
 *  This will include duplicating any strings that are present in the
 *  original configuration.
 *
 *  @param orig     The ASCII backend configuration to be copied.
 *  @param clone    A new ASCII backend configuration to copy into.
 */
void clone_libts_ascii_backend(libts_ascii_backend_t *orig,
        libts_ascii_backend_t *clone);
void clone_libts_kafka_backend(libts_kafka_backend_t *orig,
        libts_kafka_backend_t *clone);
void clone_libts_dbats_backend(libts_dbats_backend_t *orig,
        libts_dbats_backend_t *clone);
void clone_libts_tsmq_backend(libts_tsmq_backend_t *orig,
        libts_tsmq_backend_t *clone);

/** Enables the ASCII backend within libtimeseries, using the configuration
 *  provided.
 *
 *  @param logger   An instance of a corsaro logger to use for reporting
 *                  errors.
 *  @param ts       The libtimeseries instance for which the ASCII backend is
 *                  to be enabled.
 *  @param ascii    The ASCII backend configuration to apply to libtimeseries.
 *
 *  @return 1 if an error occurs, 0 if no error occurs.
 *
 *  @note If the backend configuration suggests the backend should be inactive,
 *        the backend will not be enabled but the function will return 0.
 *        This allows you to silently "enable" inactive or unconfigured
 *        backends without getting an error as a return code.
 */
int enable_libts_ascii_backend(corsaro_logger_t *logger,
        timeseries_t *ts, libts_ascii_backend_t *ascii);
int enable_libts_kafka_backend(corsaro_logger_t *logger,
        timeseries_t *ts, libts_kafka_backend_t *kafka);
int enable_libts_dbats_backend(corsaro_logger_t *logger,
        timeseries_t *ts, libts_dbats_backend_t *dbats);
int enable_libts_tsmq_backend(corsaro_logger_t *logger,
        timeseries_t *ts, libts_tsmq_backend_t *tsmq);

/** Destroys an ASCII backend configuration, freeing any associated memory.
 *
 *  @param back         The ASCII backend configuration to be destroyed.
 */
void destroy_libts_ascii_backend(libts_ascii_backend_t *back);
void destroy_libts_kafka_backend(libts_kafka_backend_t *back);
void destroy_libts_dbats_backend(libts_dbats_backend_t *back);
void destroy_libts_tsmq_backend(libts_tsmq_backend_t *back);

/** Constructs a getopt-style argument string from an ASCII backend
 *  configuration that can be used to enable the backend via the
 *  libtimeseries API.
 *
 *  Note that this string is allocated on the heap, so must be
 *  freed by the caller when they are finished with it.
 *
 *  @param logger   An instance of a corsaro logger to use for reporting
 *                  errors.
 *  @param back     The ASCII backend configuration to construct the argument
 *                  string from.
 *  @return the constructed argument string or NULL if an error occurred.
 */
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
