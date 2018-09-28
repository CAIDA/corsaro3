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

#define CORSARO_WDCAP_STRIP_VLANS_OFF 0
#define CORSARO_WDCAP_STRIP_VLANS_ON 1
#define CORSARO_DEFAULT_WDCAP_STRIP_VLANS CORSARO_WDCAP_STRIP_VLANS_ON

#include "libcorsaro3_trace.h"
#include "libcorsaro3_log.h"
#include "libcorsaro3.h"

typedef struct corsaro_wdcap_local corsaro_wdcap_local_t;

typedef struct corsaro_wdcap_global {

    corsaro_logger_t *logger;
    char *logfilename;
    char *inputuri;
    libtrace_t *trace;
    uint8_t logmode;
    uint8_t threads;
    uint32_t interval;
    uint32_t rotatefreq;
    char *monitorid;
    char *template;
    char *fileformat;
    uint8_t stripvlans;

    corsaro_wdcap_local_t *threaddata;

} corsaro_wdcap_global_t;

struct corsaro_wdcap_local {
    libtrace_out_t *writer;
    pthread_t tid;
    uint32_t interval_start_ts;
    char *interimfilename;

    corsaro_interval_t current_interval;
    uint32_t next_report;
    uint32_t last_ts;

    uint64_t lastmisscount;
    uint64_t lastaccepted;
    corsaro_wdcap_global_t *glob;
};

corsaro_wdcap_global_t *corsaro_wdcap_init_global(char *filename,
        int logmode);
void corsaro_wdcap_free_global(corsaro_wdcap_global_t *glob);

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
