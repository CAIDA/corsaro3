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

typedef struct corsaro_tagger_glob {
    corsaro_logger_t *logger;
    char *logfilename;
    char **inputuris;
    char *filterstring;
    char *pubqueuename;

    int currenturi;
    int totaluris;
    int alloceduris;
    libtrace_t *trace;
    libtrace_filter_t *filter;

    uint8_t promisc;
    uint8_t logmode;
    uint8_t threads;

    pfx2asn_opts_t pfxtagopts;
    maxmind_opts_t maxtagopts;
    netacq_opts_t netacqtagopts;

    ipmeta_t *ipmeta;
    ipmeta_provider_t *maxmindipmeta;
    ipmeta_provider_t *netacqipmeta;
    ipmeta_provider_t *pfxipmeta;

    fn_hasher hasher;
    void *hasher_data;
    uint8_t hasher_required;

    void *zmq_ctxt;

    corsaro_tagger_local_t *threaddata;
} corsaro_tagger_global_t;

struct corsaro_tagger_local {
    corsaro_packet_tagger_t *tagger;
    void *pubsock;
    uint8_t stopped;
    uint8_t sentfirstts;
    uint64_t errorcount;

    uint64_t lastmisscount;
    uint64_t lastaccepted;

    corsaro_memhandler_t *msg_source;
    corsaro_memhandler_t *ptag_source;
};

corsaro_tagger_global_t *corsaro_tagger_init_global(char *filename,
        int logmode);
void corsaro_tagger_free_global(corsaro_tagger_global_t *glob);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
