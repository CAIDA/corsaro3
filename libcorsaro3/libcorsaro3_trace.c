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

#include <libtrace.h>
#include "libcorsaro3_log.h"
#include "libcorsaro3_trace.h"

libtrace_t *corsaro_create_trace_reader(corsaro_logger_t *logger,
        char *tracename) {

    /* Relying on libtrace to be able to auto-detect the format here */
    libtrace_t *trace;
    libtrace_err_t err;

    trace = trace_create(tracename);
    if (trace_is_err(trace)) {
        err = trace_get_err(trace);
        corsaro_log(logger,
                "error while opening trace file %s for reading: %s",
                tracename, err.problem);
        trace_destroy(trace);
        return NULL;
    }

    if (trace_start(trace) == -1) {
        err = trace_get_err(trace);
        corsaro_log(logger,
                "error while initialising trace file %s for reading: %s",
                tracename, err.problem);
        trace_destroy(trace);
        return NULL;
    }

    return trace;
}

libtrace_out_t *corsaro_create_trace_writer(corsaro_logger_t *logger,
        char *tracename, int level, trace_option_compresstype_t method) {

    /* Relying on libtrace to be able to auto-detect the format here */
    libtrace_out_t *trace;
    libtrace_err_t err;

    trace = trace_create_output(tracename);
    if (trace_is_err_output(trace)) {
        err = trace_get_err_output(trace);
        corsaro_log(logger,
                "error while opening trace file %s for reading: %s",
                tracename, err.problem);
        trace_destroy_output(trace);
        return NULL;
    }

    if (trace_config_output(trace, TRACE_OPTION_OUTPUT_COMPRESS,
                &(level)) == -1) {
        err = trace_get_err_output(trace);
        corsaro_log(logger,
                "error while setting compress level %d for trace file %s: %s",
                level, tracename, err.problem);
        trace_destroy_output(trace);
        return NULL;
    }

    if (trace_config_output(trace, TRACE_OPTION_OUTPUT_COMPRESSTYPE,
                &(method)) == -1) {
        err = trace_get_err_output(trace);
        corsaro_log(logger,
                "error while setting compress method %d for trace file %s: %s",
                method, tracename, err.problem);
        trace_destroy_output(trace);
        return NULL;
    }

    if (trace_start_output(trace) == -1) {
        err = trace_get_err_output(trace);
        corsaro_log(logger,
                "error while initialising trace file %s for reading: %s",
                tracename, err.problem);
        trace_destroy_output(trace);
        return NULL;
    }

    return trace;
}

void corsaro_destroy_trace_reader(libtrace_t *trace) {
    trace_destroy(trace);
}

void corsaro_destroy_trace_writer(libtrace_out_t *trace) {
    trace_destroy_output(trace);
}

int corsaro_read_next_packet(corsaro_logger_t *logger,
        libtrace_t *trace, libtrace_packet_t *packet) {

    int ret;
    libtrace_err_t err;
    if ((ret = trace_read_packet(trace, packet)) < 0) {
        err = trace_get_err(trace);
        corsaro_log(logger,
                "error while reading packet from trace file: %s",
                err.problem);
        return -1;
    }

    return ret;
}

int corsaro_write_packet(corsaro_logger_t *logger,
        libtrace_out_t *trace, libtrace_packet_t *packet) {

    int ret;
    libtrace_err_t err;
    if ((ret = trace_write_packet(trace, packet)) < 0) {
        err = trace_get_err_output(trace);
        corsaro_log(logger,
                "error while writing packet to trace file: %s",
                err.problem);
        return -1;
    }

    return ret;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
