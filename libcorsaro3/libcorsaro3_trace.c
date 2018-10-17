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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>

#include <wandio.h>
#include <libtrace.h>
#include "libcorsaro3_log.h"
#include "libcorsaro3_trace.h"

typedef struct pcapfile_header_t {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* timestamp accuracy */
    uint32_t snaplen;        /* aka "wirelen" */
    uint32_t network;        /* data link type */
} pcapfile_header_t;

typedef struct dag_record {
    uint64_t  ts;           /**< ERF timestamp */
    uint8_t   type;         /**< GPP record type */
    uint8_t   flags;        /**< Flags */
    uint16_t  rlen;         /**< Record len (capture+framing) */
    uint16_t  lctr;         /**< Loss counter */
    uint16_t  wlen;         /**< Wire length */
} dag_record_t;

typedef struct pcap_header {
    uint32_t ts_sec;        /* Seconds portion of the timestamp */
    uint32_t ts_usec;       /* Microseconds portion of the timestamp */
    uint32_t caplen;        /* Capture length of the packet */
    uint32_t wirelen;       /* The wire length of the packet */
} pcap_header_t;

#define BYTESWAP32(n) \
    (((n & 0xFFU) << 24) | ((n & 0xFF00U) << 8) | ((n & 0xFF0000U) >> 8) \
        ((n & 0xFF000000U) >> 24))

#define BYTESWAP64(n) \
    ((BYTESWAP32((n & 0xFFFFFFFF00000000ULL) >> 32)) | \
        ((uint64_t)BYTESWAP32(n & 0xFFFFFFFFULL) << 32))

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

corsaro_fast_trace_writer_t *corsaro_create_fast_trace_writer(
        corsaro_logger_t *logger, char *filename) {

    corsaro_fast_trace_writer_t *writer;
    struct pcapfile_header_t filehdr;

    writer = (corsaro_fast_trace_writer_t *)calloc(1,
            sizeof(corsaro_fast_trace_writer_t));

    writer->io = wandio_wcreate(filename, TRACE_OPTION_COMPRESSTYPE_NONE,
            0, O_CREAT | O_WRONLY);
    if (!writer->io) {
        corsaro_log(logger, "unable to open fast output file %s: %s",
                filename, strerror(errno));
        free(writer);
        return NULL;
    }

    filehdr.magic_number = 0xa1b2c3d4;
    filehdr.version_major = 2;
    filehdr.version_minor = 4;
    filehdr.thiszone = 0;
    filehdr.sigfigs = 0;
    filehdr.snaplen = 65536;
    filehdr.network = TRACE_DLT_EN10MB;

    wandio_wwrite(writer->io, &filehdr, sizeof(filehdr));

    return writer;
}

void corsaro_destroy_fast_trace_writer(corsaro_fast_trace_writer_t *writer) {

    wandio_wdestroy(writer->io);
    free(writer);
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

int corsaro_fast_write_erf_packet(corsaro_logger_t *logger,
        corsaro_fast_trace_writer_t *writer, libtrace_packet_t *packet) {

    char tmpbuf[70000];
    dag_record_t *erfptr;
    pcap_header_t *pcaphdr;
    uint64_t erfts;
    int ret;

    erfptr = (dag_record_t *)packet->header;
    pcaphdr = (pcap_header_t *)tmpbuf;

#if __BYTE_ORDER == __BIG_ENDIAN
    erfts = BYTESWAP64(erfptr->ts);
#else
    erfts = erfptr->ts;
#endif

    pcaphdr->ts_sec = (uint32_t)(erfts >> 32);
    pcaphdr->ts_usec = (uint32_t)(((erfts & 0xFFFFFFFF) * 1000000) >> 32);

    while (pcaphdr->ts_usec >= 1000000) {
        pcaphdr->ts_usec -= 1000000;
        pcaphdr->ts_sec ++;
    }

    // erf header size + 2 bytes of padding
    /* XXX if we ever start using ERF extension headers, we will also need to
     * account for those in this calculation.
     */
    pcaphdr->caplen = ntohs(erfptr->rlen) - 18;
    pcaphdr->wirelen = ntohs(erfptr->wlen) - 4;

    if (pcaphdr->wirelen < pcaphdr->caplen) {
        pcaphdr->caplen = pcaphdr->wirelen;
    }

    memcpy(tmpbuf + sizeof(pcap_header_t), packet->payload, pcaphdr->caplen);

    /* XXX This write will block, if we hit an I/O bottleneck */
    ret = wandio_wwrite(writer->io, tmpbuf, pcaphdr->caplen +
            sizeof(pcap_header_t));
    if (ret != pcaphdr->caplen + sizeof(pcap_header_t)) {
        return -1;
    }
    return ret;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
