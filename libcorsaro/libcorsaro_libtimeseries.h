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

/** Initialises a set of configuration options for an ASCII backend.
 *
 *  An initialised backend is inactive until appropriately configured.
 *
 *  @param back     The backend to initialise.
 */
void init_libts_ascii_backend(libts_ascii_backend_t *back);
void init_libts_kafka_backend(libts_kafka_backend_t *back);
void init_libts_dbats_backend(libts_dbats_backend_t *back);

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

/** Destroys an ASCII backend configuration, freeing any associated memory.
 *
 *  @param back         The ASCII backend configuration to be destroyed.
 */
void destroy_libts_ascii_backend(libts_ascii_backend_t *back);
void destroy_libts_kafka_backend(libts_kafka_backend_t *back);
void destroy_libts_dbats_backend(libts_dbats_backend_t *back);

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

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
