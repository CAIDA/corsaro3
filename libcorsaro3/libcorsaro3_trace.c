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

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <assert.h>
#include <aio.h>

#include <wandio.h>
#include <libtrace.h>
#include "libcorsaro3_log.h"
#include "libcorsaro3_trace.h"

#define FAST_WRITER_BUFFER_SIZE (24 * 1024 * 1024)
#define MIN_WRITE_TRIGGER (4 * 1024 * 1024)

#define THISBUF(w) (w->whichbuf)
#define OTHERBUF(w) (w->whichbuf == 0 ? 1 : 0)

#define SPACEREM(w) \
    (w->bufsize[THISBUF(w)] - w->offset[THISBUF(w)])

typedef struct pcapfile_header_t {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* timestamp accuracy */
    uint32_t snaplen;        /* aka "wirelen" */
    uint32_t network;        /* data link type */
} PACKED pcapfile_header_t;

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
} PACKED pcap_header_t;

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

corsaro_fast_trace_writer_t *corsaro_create_fast_trace_writer() {

    corsaro_fast_trace_writer_t *writer;
    writer = (corsaro_fast_trace_writer_t *)calloc(1,
            sizeof(corsaro_fast_trace_writer_t));

    writer->localbuf[0] = malloc(FAST_WRITER_BUFFER_SIZE);
    writer->localbuf[1] = malloc(FAST_WRITER_BUFFER_SIZE);
    writer->bufsize[0] = FAST_WRITER_BUFFER_SIZE;
    writer->bufsize[1] = FAST_WRITER_BUFFER_SIZE;

    writer->io_fd = -1;

    return writer;
}

int corsaro_start_fast_trace_writer(corsaro_logger_t *logger,
        corsaro_fast_trace_writer_t *writer, char *filename) {

    struct pcapfile_header_t filehdr;
    uid_t userid = 0;
    gid_t groupid = 0;
    char *sudoenv = NULL;

    writer->io_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND,
            0666);
    if (writer->io_fd < 0) {
        corsaro_log(logger,
                "unable to open wdcap output file %s: %s", filename,
                strerror(errno));
        return -1;
    }
    sudoenv = getenv("SUDO_UID");
    if (sudoenv != NULL) {
        userid = strtol(sudoenv, NULL, 10);
    }
    sudoenv = getenv("SUDO_GID");
    if (sudoenv != NULL) {
        groupid = strtol(sudoenv, NULL, 10);
    }

    if (userid != 0 && fchown(writer->io_fd, userid, groupid) == -1) {
        corsaro_log(logger,
                "unable to set ownership on fast output file %s: %s",
                filename, strerror(errno));
        close(writer->io_fd);
        return -1;
    }

    writer->waiting = 0;
    writer->whichbuf = 0;
    writer->written = 0;
    writer->offset[0] = 0;
    writer->offset[1] = 0;

    filehdr.magic_number = 0xa1b2c3d4;
    filehdr.version_major = 2;
    filehdr.version_minor = 4;
    filehdr.thiszone = 0;
    filehdr.sigfigs = 0;
    filehdr.snaplen = 65536;
    filehdr.network = TRACE_DLT_EN10MB;

    memcpy(writer->localbuf[0], &filehdr, sizeof(filehdr));
    writer->offset[0] = sizeof(filehdr);
}

static inline int schedule_aiowrite(corsaro_fast_trace_writer_t *writer,
        corsaro_logger_t *logger) {

    struct iocb *iocbs[1];
    size_t towrite, rem;

    memset(&(writer->aio[THISBUF(writer)]), 0, sizeof(struct aiocb));
    writer->aio[THISBUF(writer)].aio_buf = writer->localbuf[THISBUF(writer)];
    writer->aio[THISBUF(writer)].aio_nbytes = writer->offset[THISBUF(writer)];
    writer->aio[THISBUF(writer)].aio_fildes = writer->io_fd;
    writer->aio[THISBUF(writer)].aio_offset = 0;
    writer->aio[THISBUF(writer)].aio_reqprio = 1;

    if (aio_write(&(writer->aio[THISBUF(writer)])) < 0) {
        corsaro_log(logger,
                "error calling aio_write() in fast writer: %s",
                strerror(errno));
        return -1;
    }

    writer->waiting = 1;
    writer->whichbuf = OTHERBUF(writer);
    return 1;
}

static inline int check_aiowrite_status(corsaro_fast_trace_writer_t *writer,
        corsaro_logger_t *logger) {
    int err = aio_error(&(writer->aio[OTHERBUF(writer)]));

    if (err == 0) {
        /* TODO deal with partial writes */

        assert(aio_return(&(writer->aio[OTHERBUF(writer)])) ==
                writer->offset[OTHERBUF(writer)]);
        writer->waiting = 0;
        writer->offset[OTHERBUF(writer)] = 0;
        return 1;
    } else if (err != EINPROGRESS) {
        corsaro_log(logger,
                "error while performing async fast write: %s",
                strerror(err));
        writer->waiting = 0;
        return -1;
    }

    return 0;
}

void corsaro_reset_fast_trace_writer(corsaro_fast_trace_writer_t *writer,
        corsaro_logger_t *logger) {

    while (writer->waiting) {
        if (check_aiowrite_status(writer, logger) == 0) {
            usleep(100);
        }
    }

    if (writer->offset[THISBUF(writer)] > 0) {
        schedule_aiowrite(writer, logger);
    }

    while (writer->waiting) {
        if (check_aiowrite_status(writer, logger) == 0) {
            usleep(100);
        }
    }

    writer->io_fd = -1;
}

void corsaro_destroy_fast_trace_writer(corsaro_fast_trace_writer_t *writer,
        corsaro_logger_t *logger) {

    int flags;

    if (writer->io_fd != -1) {
        corsaro_reset_fast_trace_writer(writer, logger);
    }
    close(writer->io_fd);
    if (writer->localbuf[0]) {
        free(writer->localbuf[0]);
    }
    if (writer->localbuf[1]) {
        free(writer->localbuf[1]);
    }
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

    dag_record_t *erfptr;
    pcap_header_t *pcaphdr;
    uint16_t pcapcaplen;
    uint64_t erfts;
    int ret;
    char tmpbuf[200];

    erfptr = (dag_record_t *)packet->header;
    pcaphdr = (pcap_header_t *)tmpbuf;

#if __BYTE_ORDER == __BIG_ENDIAN
    erfts = BYTESWAP64(erfptr->ts);
#else
    erfts = erfptr->ts;
#endif

    pcapcaplen = ntohs(erfptr->rlen) - 18;

    if (writer->waiting) {
        if (check_aiowrite_status(writer, logger) < 0) {
            return -1;
        }
    }

    while (SPACEREM(writer) < sizeof(pcap_header_t) + pcapcaplen) {
        corsaro_log(logger,
                "extending fast write buffer (%u not enough)",
                writer->bufsize[THISBUF(writer)]);

        writer->localbuf[THISBUF(writer)] = realloc(
                writer->localbuf[THISBUF(writer)],
                writer->bufsize[THISBUF(writer)] + FAST_WRITER_BUFFER_SIZE);
        writer->bufsize[THISBUF(writer)] += FAST_WRITER_BUFFER_SIZE;
        if (writer->localbuf[THISBUF(writer)] == NULL) {
            corsaro_log(logger,
                    "out of memory when extending fast write buffer");
            return -1;
        }
    }

    pcaphdr = (pcap_header_t *)(writer->localbuf[THISBUF(writer)] +
            writer->offset[THISBUF(writer)]);

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
    pcaphdr->caplen = pcapcaplen;
    pcaphdr->wirelen = ntohs(erfptr->wlen) - 4;

    if (pcaphdr->wirelen < pcaphdr->caplen) {
        pcaphdr->caplen = pcaphdr->wirelen;
    }

    writer->offset[THISBUF(writer)] += sizeof(pcap_header_t);

    memcpy(writer->localbuf[THISBUF(writer)] + writer->offset[THISBUF(writer)],
            packet->payload, pcaphdr->caplen);

    writer->offset[THISBUF(writer)] += pcaphdr->caplen;
    if (writer->waiting || writer->offset[THISBUF(writer)] < MIN_WRITE_TRIGGER) {
        return 1;
    }

    /* THISBUF is ready to be passed off to the async writer */
    return schedule_aiowrite(writer, logger);
}

int corsaro_set_lowest_io_priority(void) {
    pid_t tid = (pid_t) syscall (SYS_gettid);
    if (syscall(SYS_ioprio_set, IOPRIO_WHO_PROCESS, tid,
            IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE,7)) != 0) {
        return -1;
    }
    return 0;
}

int corsaro_set_highest_io_priority(void) {
    pid_t tid = (pid_t) syscall (SYS_gettid);
    if (syscall(SYS_ioprio_set, IOPRIO_WHO_PROCESS, tid,
            IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE,0)) != 0) {
        return -1;
    }
    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
