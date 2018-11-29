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

#ifndef CORSAROTRACE_H_
#define CORSAROTRACE_H_

#include <libtrace.h>
#include <libtrace_parallel.h>

#include "libcorsaro3.h"
#include "libcorsaro3_log.h"
#include "libcorsaro3_filtering.h"
#include "libcorsaro3_tagging.h"
#include "libcorsaro3_memhandler.h"

typedef struct corsaro_tagger_local corsaro_tagger_local_t;

/** Structure for storing global state for a corsarotagger instance */
typedef struct corsaro_tagger_glob {

    /** The logger instance to use when logging error messages */
    corsaro_logger_t *logger;

    /* The name of the file to use for logging (if logging to a file */
    char *logfilename;

    /** An array of URI strings to read packets from */
    char **inputuris;

    /** A string describing a BPF filter to apply to all received packets */
    char *filterstring;

    /** The name of the zeromq socket to publish tagged packets to */
    char *pubqueuename;

    /** The index of the input URI that we are currently reading from */
    int currenturi;

    /** The total number of valid entries in the inputuris array */
    int totaluris;

    /** The number of entries that can be stored in the inputuris array */
    int alloceduris;

    /** A libtrace input handle for the current input source */
    libtrace_t *trace;

    /** A libtrace filter handle for the active BPF filter */
    libtrace_filter_t *filter;

    /** A boolean flag describing whether promiscuous mode should be enabled
     *  on the input sources */
    uint8_t promisc;

    /** The logging method to be used by corsarotagger */
    uint8_t logmode;

    /** The number of packet processing threads to use */
    uint8_t threads;

    /** The configuration options for the libipmeta prefix to ASN module */
    pfx2asn_opts_t pfxtagopts;
    /** The configuration options for the libipmeta Maxmind geolocation
     *  module */
    maxmind_opts_t maxtagopts;
    /** The configuration options for the libipmeta Netacq-edge geolocation
     *  module */
    netacq_opts_t netacqtagopts;

    /** A libipmeta instance that can be used to add geolocation and ASN
     *  tags for an IP address
     */
    ipmeta_t *ipmeta;

    /** A instance of the Maxmind geolocation provider for libipmeta */
    ipmeta_provider_t *maxmindipmeta;
    /** A instance of the Netacq-edge geolocation provider for libipmeta */
    ipmeta_provider_t *netacqipmeta;
    /** A instance of the prefix to ASN provider for libipmeta */
    ipmeta_provider_t *pfxipmeta;

    /** A libtrace hasher function that can be used to distribute received
     *  packets to processing threads.
     */
    fn_hasher hasher;

    /** Custom data for the libtrace hasher function */
    void *hasher_data;

    /** Boolean flag that is set to true if the input sources require the
     *  use of a libtrace hasher.
     */
    uint8_t hasher_required;

    /** The zeromq context used to create zeromq sockets */
    void *zmq_ctxt;

    /** An array of thread-local state data, one entry for each processing
     *  thread.
     */
    corsaro_tagger_local_t *threaddata;
} corsaro_tagger_global_t;

/** Structure for storing thread-local state for a single processing thread */
struct corsaro_tagger_local {

    /** A corsaro tagger instance */
    corsaro_packet_tagger_t *tagger;

    /** A zeromq socket to publish tagged packets onto */
    void *pubsock;

    /** A boolean flag indicating whether this thread has halted */
    uint8_t stopped;

    /** Number of errors that have occurred during the lifetime of this
     *  thread.
     */
    uint64_t errorcount;

    /** Cumulative number of packets missed by this thread */
    uint64_t lastmisscount;
    /** Cumulative number of packets that have been accepted by this thread */
    uint64_t lastaccepted;

    uint8_t *bufferspace;

    uint32_t buffersize;

    uint32_t bufferused;

};


/** Initialises the global state for a corsarotagger instance, based on
 *  the YAML configuration found in the given config file.
 *
 *  @param filename         The path to the configuration file.
 *  @param logmode          The logging method to use (can be one of
 *                          GLOBAL_LOGMODE_STDERR, GLOBAL_LOGMODE_FILE,
 *                          GLOBAL_LOGMODE_SYSLOG or GLOBAL_LOGMODE_NONE.
 *  @return A pointer to an initialised global state structure, or NULL if
 *          a fatal error occurred.
 */
corsaro_tagger_global_t *corsaro_tagger_init_global(char *filename,
        int logmode);

/** Destroys the global state for a corsarotagger instance.
 *
 *  @param glob             The global state to destroy.
 */
void corsaro_tagger_free_global(corsaro_tagger_global_t *glob);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
