/*
 * corsaro
 *
 * Alistair King, CAIDA, UC San Diego
 * Shane Alcock, WAND, University of Waikato
 *
 * corsaro-info@caida.org
 *
 * Copyright (C) 2012-2019 The Regents of the University of California.
 * All Rights Reserved.
 *
 * This file is part of corsaro.
 *
 * Permission to copy, modify, and distribute this software and its
 * documentation for academic research and education purposes, without fee, and
 * without a written agreement is hereby granted, provided that
 * the above copyright notice, this paragraph and the following paragraphs
 * appear in all copies.
 *
 * Permission to make use of this software for other than academic research and
 * education purposes may be obtained by contacting:
 *
 * Office of Innovation and Commercialization
 * 9500 Gilman Drive, Mail Code 0910
 * University of California
 * La Jolla, CA 92093-0910
 * (858) 534-5815
 * invent@ucsd.edu
 *
 * This software program and documentation are copyrighted by The Regents of the
 * University of California. The software program and documentation are supplied
 * “as is”, without any accompanying services from The Regents. The Regents does
 * not warrant that the operation of the program will be uninterrupted or
 * error-free. The end-user understands that the program was developed for
 * research purposes and is advised not to rely exclusively on the program for
 * any reason.
 *
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,
 * EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED
 * HEREUNDER IS ON AN “AS IS” BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO
 * OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
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
#include "libcorsaro.h"
#include "libcorsaro_log.h"
#include "libcorsaro_trace.h"

/** Use 24 MB as an initial buffer size for the fast writers */
#define FAST_WRITER_BUFFER_SIZE (24 * 1024 * 1024)

/** Amount of data required in a buffer before scheduling an async write */
#define MIN_WRITE_TRIGGER (4 * 1024 * 1024)

/** Quick macro for figuring out the index of the buffer that we should
 *  append new packets into.
 */
#define THISBUF(w) (w->whichbuf)

/** Quick macro for figuring out the index of the buffer that is currently
 *  being written by the async I/O API */
#define OTHERBUF(w) (w->whichbuf == 0 ? 1 : 0)

/** Calculates the amount of buffer space remaining in the current storage
 *  buffer.
 */
#define SPACEREM(w) \
    (w->bufsize[THISBUF(w)] - w->offset[THISBUF(w)])

/** Local definition of a pcap file header */
typedef struct pcapfile_header_t {
    uint32_t magic_number;   /**< magic number */
    uint16_t version_major;  /**< major version number */
    uint16_t version_minor;  /**< minor version number */
    int32_t  thiszone;       /**< GMT to local correction */
    uint32_t sigfigs;        /**< timestamp accuracy */
    uint32_t snaplen;        /**< packet truncation size */
    uint32_t network;        /**< data link type */
} PACKED pcapfile_header_t;

/** Local definition of a basic ERF header */
typedef struct dag_record {
    uint64_t  ts;           /**< ERF timestamp */
    uint8_t   type;         /**< GPP record type */
    uint8_t   flags;        /**< Flags */
    uint16_t  rlen;         /**< Record len (capture+framing) */
    uint16_t  lctr;         /**< Loss counter */
    uint16_t  wlen;         /**< Wire length */
} dag_record_t;

/** Local definiton of a pcap packet header */
typedef struct pcap_header {
    uint32_t ts_sec;        /**< Seconds portion of the timestamp */
    uint32_t ts_usec;       /**< Microseconds portion of the timestamp */
    uint32_t caplen;        /**< Capture length of the packet */
    uint32_t wirelen;       /**< The wire length of the packet */
} PACKED pcap_header_t;

/** Byteswaps a 32 bit integer */
#define BYTESWAP32(n) \
    (((n & 0xFFU) << 24) | ((n & 0xFF00U) << 8) | ((n & 0xFF0000U) >> 8) \
        ((n & 0xFF000000U) >> 24))

/** Byteswaps a 64 bit integer */
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

    /* No configuration required -- we're just doing a standard read */

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

    libtrace_out_t *trace;
    libtrace_err_t err;

    /* tracename must be a full URI, otherwise this is going to fail */

    trace = trace_create_output(tracename);
    if (trace_is_err_output(trace)) {
        err = trace_get_err_output(trace);
        corsaro_log(logger,
                "error while opening trace file %s for reading: %s",
                tracename, err.problem);
        trace_destroy_output(trace);
        return NULL;
    }

    /* Configure compression options */
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

    /* To avoid reallocating these buffers for every file, we allow
     * users to re-use a single fast writer.
     */
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

    /* If the program calling this function is running as root via sudo,
     * it's nicer if the resulting trace files actually end up being owned
     * by the user who ran the program rather than root. The following code
     * will do just that. (but only do this if the current user is root)
     */
    if (getuid() == 0) {
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
    }

    /* Reset our buffers -- anything still in the buffers will be lost, so
     * hopefully the caller remembered to call
     * corsaro_reset_fast_trace_writer() beforehand if they had been using
     * this writer for a previous trace file.
     */
    writer->waiting = 0;
    writer->whichbuf = 0;
    writer->offset[0] = 0;
    writer->offset[1] = 0;

    /* Start our new file with a pcap file header.
     *
     * XXX if we end up supporting other trace formats as output, this may
     *     need to happen somewhere else.
     */
    filehdr.magic_number = 0xa1b2c3d4;
    filehdr.version_major = 2;
    filehdr.version_minor = 4;
    filehdr.thiszone = 0;
    filehdr.sigfigs = 0;
    filehdr.snaplen = 65536;
    filehdr.network = TRACE_DLT_EN10MB;

    memcpy(writer->localbuf[0], &filehdr, sizeof(filehdr));
    writer->offset[0] = sizeof(filehdr);
    return 0;
}

static inline int schedule_aiowrite(corsaro_fast_trace_writer_t *writer,
        corsaro_logger_t *logger) {

    /* Prepare our aiocb which will tell the async I/O API what exactly
     * we want to write to disk.
     */
    memset(&(writer->aio[THISBUF(writer)]), 0, sizeof(struct aiocb));
    writer->aio[THISBUF(writer)].aio_buf = writer->localbuf[THISBUF(writer)];
    writer->aio[THISBUF(writer)].aio_nbytes = writer->offset[THISBUF(writer)];
    writer->aio[THISBUF(writer)].aio_fildes = writer->io_fd;
    /* aio_offset = 0 only because we set O_APPEND */
    writer->aio[THISBUF(writer)].aio_offset = 0;
    writer->aio[THISBUF(writer)].aio_reqprio = 1;

    if (aio_write(&(writer->aio[THISBUF(writer)])) < 0) {
        corsaro_log(logger,
                "error calling aio_write() in fast writer: %s",
                strerror(errno));
        return -1;
    }

    /* Switch to the other buffer to keep storing incoming packets */
    writer->waiting = 1;
    writer->whichbuf = OTHERBUF(writer);
    return 1;
}

static inline int check_aiowrite_status(corsaro_fast_trace_writer_t *writer,
        corsaro_logger_t *logger) {
    int err = aio_error(&(writer->aio[OTHERBUF(writer)]));

    if (err == 0) {
        /* Write has completed */
        int r = aio_return(&(writer->aio[OTHERBUF(writer)]));

        if (r == writer->offset[OTHERBUF(writer)]) {
            writer->waiting = 0;
            writer->offset[OTHERBUF(writer)] = 0;
            return 1;
        }

        /* Partial write (probably due to disk being full?) */
        assert(r < writer->offset[OTHERBUF(writer)]);

        writer->whichbuf = OTHERBUF(writer);

        /* Try to send the remaining content again */
        writer->offset[THISBUF(writer)] -= r;
        memmove(writer->localbuf[THISBUF(writer)],
                writer->localbuf[THISBUF(writer)] + r,
                writer->offset[THISBUF(writer)]);
        return schedule_aiowrite(writer, logger);

    } else if (err != EINPROGRESS) {
        corsaro_log(logger,
                "error while performing async fast write: %s",
                strerror(err));
        writer->waiting = 0;
        return -1;
    }
    /* If err == EINPROGRESS, then write has not yet completed */
    return 0;
}

int corsaro_reset_fast_trace_writer(corsaro_logger_t *logger,
        corsaro_fast_trace_writer_t *writer) {

    int ret;
    /* Wait for the current outstanding write to complete */
    while (writer->waiting) {
        /* XXX technically this could block, but has not been a problem
         * so far */
        if (check_aiowrite_status(writer, logger) == 0) {
            usleep(100);
        }
    }

    /* If we have any stored data in our current buffer, schedule that to
     * be written too.
     */
    if (writer->offset[THISBUF(writer)] > 0) {
        schedule_aiowrite(writer, logger);
    }

    /* Wait for that last write to complete */
    while (writer->waiting) {
        if (check_aiowrite_status(writer, logger) == 0) {
            usleep(100);
        }
    }

    /* Save the fd so we can return it to the user */
    ret = writer->io_fd;

    /* DO NOT CLOSE THE FD -- this will definitely block and cause
     * performance issues for high speed writers */
    writer->io_fd = -1;
    return ret;
}

void corsaro_destroy_fast_trace_writer(corsaro_logger_t *logger,
        corsaro_fast_trace_writer_t *writer) {


    if (writer->io_fd != -1) {
        int fd;
        fd = corsaro_reset_fast_trace_writer(logger, writer);
        /* We're OK to close here because destroying the writer implies that
         * there is no more work to be done, so blocking won't be a problem.
         */
        close(fd);
    }
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
    char tmpbuf[200];

    erfptr = (dag_record_t *)packet->header;
    pcaphdr = (pcap_header_t *)tmpbuf;

#if __BYTE_ORDER == __BIG_ENDIAN
    erfts = BYTESWAP64(erfptr->ts);
#else
    erfts = erfptr->ts;
#endif

    /* 18 = ERF header length + 2 bytes of padding */
    /* XXX if we ever start using ERF extension headers, we will also need to
     * account for those in this calculation.
     */
    pcapcaplen = ntohs(erfptr->rlen) - CORSARO_ERF_ETHERNET_FRAMING;

    /* Check if any outstanding writes have completed */
    if (writer->waiting) {
        if (check_aiowrite_status(writer, logger) < 0) {
            return -1;
        }
    }

    while (SPACEREM(writer) < sizeof(pcap_header_t) + pcapcaplen) {
        /* Buffer doesn't have enough space to fit the current packet,
         * extend it. Hopefully we don't do this often (if at all).
         */
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

    /* Fill in the pcap header for our converted packet */
    pcaphdr = (pcap_header_t *)(writer->localbuf[THISBUF(writer)] +
            writer->offset[THISBUF(writer)]);

    pcaphdr->ts_sec = (uint32_t)(erfts >> 32);
    pcaphdr->ts_usec = (uint32_t)(((erfts & 0xFFFFFFFF) * 1000000) >> 32);

    while (pcaphdr->ts_usec >= 1000000) {
        pcaphdr->ts_usec -= 1000000;
        pcaphdr->ts_sec ++;
    }

    pcaphdr->caplen = pcapcaplen;

    /* ERF wire length includes the Ethernet frame check sequence, pcap does
     * not.
     */
    pcaphdr->wirelen = ntohs(erfptr->wlen) - 4;

    /* This will remove the FCS if the original packet has not been
     * snapped in any way.
     */
    if (pcaphdr->wirelen < pcaphdr->caplen) {
        pcaphdr->caplen = pcaphdr->wirelen;
    }

    writer->offset[THISBUF(writer)] += sizeof(pcap_header_t);

    /* Write the packet contents into the buffer, starting from the
     * Ethernet header */
    memcpy(writer->localbuf[THISBUF(writer)] + writer->offset[THISBUF(writer)],
            packet->payload, pcaphdr->caplen);

    writer->offset[THISBUF(writer)] += pcaphdr->caplen;

    if (writer->waiting || writer->offset[THISBUF(writer)] < MIN_WRITE_TRIGGER) {
        /* Either we're still waiting on the other buffer to finish being written
         * or we don't have enough in our buffer to warrant scheduling a write
         * just yet.
         */
        return 1;
    }

    /* THISBUF is ready to be passed off to the async writer */
    return schedule_aiowrite(writer, logger);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
