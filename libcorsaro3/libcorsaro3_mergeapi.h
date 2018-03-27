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

#ifndef LIBCORSARO_MERGEAPI_H_
#define LIBCORSARO_MERGEAPI_H_

#include "libcorsaro3_log.h"
#include "libcorsaro3_avro.h"
#include "libcorsaro3_trace.h"
#include "libcorsaro3_plugin.h"

typedef struct corsaro_merge_reader {

    corsaro_logger_t *logger;
    corsaro_interim_format_t fmt;
    union {
        libtrace_t *trace;
        corsaro_avro_reader_t *avro;
        void *plugin;
    } r;

} corsaro_merge_reader_t;

typedef struct corsaro_merge_writer {

    corsaro_logger_t *logger;
    corsaro_interim_format_t fmt;
    union {
        libtrace_out_t *trace;
        corsaro_avro_writer_t *avro;
        void *plugin;
    } w;

} corsaro_merge_writer_t;

corsaro_merge_reader_t *corsaro_create_merge_reader(corsaro_plugin_t *p,
        void *local, char *sourcefilename, corsaro_interim_format_t fmt);
void corsaro_close_merge_reader(corsaro_merge_reader_t *reader,
        corsaro_plugin_t *p, void *local);
int corsaro_read_next_merge_result(corsaro_merge_reader_t *reader,
        corsaro_plugin_t *p, void *local, corsaro_plugin_result_t *res);

corsaro_merge_writer_t *corsaro_create_merge_writer(corsaro_plugin_t *p,
        void *local, char *outputfilename, corsaro_interim_format_t fmt);
void corsaro_close_merge_writer(corsaro_merge_writer_t *writer,
        corsaro_plugin_t *p, void *local);
int corsaro_write_next_merge_result(corsaro_merge_writer_t *writer,
        corsaro_plugin_t *p, void *local, corsaro_plugin_result_t *res);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

