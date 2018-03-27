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

#include <libtrace.h>

#include "libcorsaro3_log.h"

libtrace_t *corsaro_create_trace_reader(corsaro_logger_t *logger,
        char *tracename);
libtrace_out_t *corsaro_create_trace_writer(corsaro_logger_t *logger,
        char *tracename);
void corsaro_destroy_trace_reader(libtrace_t *trace);
void corsaro_destroy_trace_writer(libtrace_out_t *trace);
int corsaro_read_next_packet(corsaro_logger_t *logger,
        libtrace_t *trace, libtrace_packet_t *packet);
int corsaro_write_packet(corsaro_logger_t *logger,
        libtrace_out_t *trace, libtrace_packet_t *packet);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
