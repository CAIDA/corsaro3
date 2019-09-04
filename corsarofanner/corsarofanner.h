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

#ifndef CORSAROFANNER_H_
#define CORSAROFANNER_H_

#include "libcorsaro_log.h"

typedef struct corsaro_fanner_global {
    corsaro_logger_t *logger;
    uint8_t logmode;
    char *logfilename;
    uint16_t inputhwm;
    uint16_t outputhwm;
    void *zmq_ctxt;
    char *inputsockname;
    char *outsockname;
    int threads;
} corsaro_fanner_global_t;

void corsaro_fanner_free_global(corsaro_fanner_global_t *glob);
corsaro_fanner_global_t *corsaro_fanner_init_global(char *filename,
        int logmode);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
