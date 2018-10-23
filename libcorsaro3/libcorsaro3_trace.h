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

#ifndef LIBCORSARO_TRACE_H_
#define LIBCORSARO_TRACE_H_

#include <aio.h>
#include <libaio.h>

#include <libtrace.h>
#include <wandio.h>

#include "libcorsaro3_log.h"

#define CORSARO_TRACE_COMPRESS_LEVEL 1
#define CORSARO_TRACE_COMPRESS_METHOD  TRACE_OPTION_COMPRESSTYPE_ZLIB

/* IO Priority API -- allows us to tweak IO priority for threads */
#define IOPRIO_BITS (16)
#define IOPRIO_CLASS_SHIFT (13)
#define IOPRIO_PRIO_MASK ((1UL << IOPRIO_CLASS_SHIFT) - 1)

#define IOPRIO_PRIO_CLASS(mask) ((mask) >> IOPRIO_CLASS_SHIFT)
#define IOPRIO_PRIO_DATA(mask) ((mask) & IOPRIO_PRIO_MASK)
#define IOPRIO_PRIO_VALUE(class, data) (((class) << IOPRIO_CLASS_SHIFT) | data)

enum {
    IOPRIO_CLASS_NONE,
    IOPRIO_CLASS_RT,
    IOPRIO_CLASS_BE,
    IOPRIO_CLASS_IDLE
};

enum {
    IOPRIO_WHO_PROCESS = 1,
    IOPRIO_WHO_PGRP,
    IOPRIO_WHO_USER
};


typedef struct corsaro_fast_trace_writer {
    int io_fd;
    int whichbuf;
    int waiting;
    uint64_t written;

//    struct aiocb aio[2];
    io_context_t ctx;
    struct iocb aio[2];
    char *localbuf[2];
    int offset[2];
    int bufsize[2];

} corsaro_fast_trace_writer_t;

libtrace_t *corsaro_create_trace_reader(corsaro_logger_t *logger,
        char *tracename);
libtrace_out_t *corsaro_create_trace_writer(corsaro_logger_t *logger,
        char *tracename, int level, trace_option_compresstype_t method);
corsaro_fast_trace_writer_t *corsaro_create_fast_trace_writer(
        corsaro_logger_t *logger, char *filename);
void corsaro_destroy_trace_reader(libtrace_t *trace);
void corsaro_destroy_trace_writer(libtrace_out_t *trace);
void corsaro_destroy_fast_trace_writer(corsaro_fast_trace_writer_t *writer,
        corsaro_logger_t *logger);
int corsaro_read_next_packet(corsaro_logger_t *logger,
        libtrace_t *trace, libtrace_packet_t *packet);
int corsaro_write_packet(corsaro_logger_t *logger,
        libtrace_out_t *trace, libtrace_packet_t *packet);

int corsaro_fast_write_erf_packet(corsaro_logger_t *logger,
        corsaro_fast_trace_writer_t *writer, libtrace_packet_t *packet);

int corsaro_set_lowest_io_priority(void);
int corsaro_set_highest_io_priority(void);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
