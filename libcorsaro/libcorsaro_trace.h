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

#include <libtrace.h>
#include <wandio.h>

#include "libcorsaro_log.h"

/** Structure to store state for asynchronous trace file output.
 *
 *  A "fast" writer trades in the flexibility and abstraction of a
 *  libtrace-based writer for speed and asynchronous behaviour. It
 *  will only work for very specific (albeit common) situations but
 *  is the only way that we can realisitically hope to keep up with
 *  high packet rates when capturing network traffic.
 *
 *  We maintain two buffers for storing data to be written to disk.
 *  One buffer contains data that has been handed off to the async
 *  I/O API and is in the process of being written. The other
 *  contains all the data that has been passed to writer while we are
 *  waiting for the current async write to complete.
 *
 *  When an async write completes, the two buffers swap roles so we
 *  always have one buffer that is being written and one buffer that
 *  is saving data for the next write operation.
 */
typedef struct corsaro_fast_trace_writer {
    /** The file descriptor that is being used to write to the file */
    int io_fd;

    /** The index of the buffer that we are adding new data TO */
    int whichbuf;

    /** Flag that indicates whether we currently have an async write
     *  operation outstanding.
     */
    int waiting;

    /** Async I/O control blocks for each of the buffers */
    struct aiocb aio[2];

    /** The two buffers themselves */
    char *localbuf[2];

    /** The amount of data currently in each of the two buffers */
    int offset[2];

    /** The size of each buffer */
    int bufsize[2];

} corsaro_fast_trace_writer_t;

/** Creates a standard single-threaded libtrace reader for a trace file.
 *
 *  @param logger       A corsaro logger instance to use for logging errors.
 *  @param tracename    The path to the trace file to be opened for reading.
 *
 *  @return a pointer to a libtrace input that can be used to read packets
 *          from the trace file, or NULL if an error occurred.
 */
libtrace_t *corsaro_create_trace_reader(corsaro_logger_t *logger,
        char *tracename);

/** Creates a libtrace writer that can be used to write a packet trace to disk.
 *
 *  @param logger       A corsaro logger instance to use for logging errors.
 *  @param tracefile    A libtrace URI describing the trace format to use and the
 *                      intended path for the output trace file.
 *  @param level        The compression level (0 - 9) to use when writing compressed
 *                      trace files.
 *  @param method       The compression method to use when writing the packet trace.
 *                      Set to TRACE_OPTION_COMPRESSTYPE_NONE for no compression.
 *
 *  @return a pointer to a libtrace output that can be used to write packets to
 *          a trace file, or NULL if an error occurred.
 */
libtrace_out_t *corsaro_create_trace_writer(corsaro_logger_t *logger,
        char *tracename, int level, trace_option_compresstype_t method);


/** Creates an asynchronous trace file writer that can be used to write a packet
 *  trace to disk with minimal blocking.
 *
 *  @note make sure you "start" the fast writer before trying to write packets.
 *
 *  @return A pointer to a fast trace writer instance, or NULL if an error
 *          occurred.
 */
corsaro_fast_trace_writer_t *corsaro_create_fast_trace_writer();


/** Destroys a libtrace reader, freeing any resources that it has allocated and
 *  closing the trace file that it was reading from.
 *
 *  @param trace        The libtrace reader to be destroyed.
 */
void corsaro_destroy_trace_reader(libtrace_t *trace);

/** Destroys a libtrace writer, freeing any resources that it has allocated and
 *  closing the trace file that it was writing to.
 *
 *  @param trace        The libtrace writer to be destroyed.
 */
void corsaro_destroy_trace_writer(libtrace_out_t *trace);

/** Destroys an asynchronous trace file writer, freeing any resources that it has
 *  allocated.
 *
 *  @note This function will close the file descriptor that was being used to
 *        write to the trace file.
 *
 *  @param logger       A corsaro logger instance to use for logging errors.
 *  @param writer       The fast writer to be destroyed.
 */
void corsaro_destroy_fast_trace_writer(corsaro_logger_t *logger,
        corsaro_fast_trace_writer_t *writer);

/** Reads the next available packet from a libtrace reader and stores its contents
 *  in the provided packet structure.
 *
 *  @param logger       A corsaro logger instance to use for logging errors.
 *  @param trace        The libtrace reader to read the next packet from.
 *  @param packet       A libtrace packet structure to store the packet in.
 *
 *  @return The size of the packet read, or -1 if an error occurs.
 */
int corsaro_read_next_packet(corsaro_logger_t *logger,
        libtrace_t *trace, libtrace_packet_t *packet);


/** Writes the given packet to disk using a libtrace writer.
 *
 *  @param logger       A corsaro logger instance to use for logging errors.
 *  @param trace        The libtrace writer to use when writing the packet.
 *  @param packet       The libtrace packet to be written to disk..
 *
 *  @return The size of the packet written, or -1 if an error occurs.
 */
int corsaro_write_packet(corsaro_logger_t *logger,
        libtrace_out_t *trace, libtrace_packet_t *packet);

/** Prepares an asynchronous trace file writer to write packets to a specified
 *  file on disk.
 *
 *  @param logger       A corsaro logger instance to use for logging errors.
 *  @param writer       The fast writer to be configured.
 *  @param filename     The name of the trace file to create on disk.
 *
 *  @return 0 if the file is opened successfully, -1 otherwise.
 *
 *  @note calling this function will reset the contents of the local buffers
 *        for the fast writer, losing any buffered data that has not been
 *        scheduled to be written. Use corsaro_reset_fast_trace_writer() to
 *        ensure that all buffered data has been passed off to the async I/O.
 */
int corsaro_start_fast_trace_writer(corsaro_logger_t *logger,
        corsaro_fast_trace_writer_t *writer, char *filename);

/** Ensures that any buffered data has been scheduled to be written via
 *  asynchronous write.
 *
 *  Call this prior to using corsaro_start_fast_trace_writer() to open a new
 *  trace file, otherwise your former trace file may end up being truncated.
 *
 *  @note The file descriptor associated with the previous trace file is NOT
 *        closed by this function. It is instead returned so that the user can
 *        close it at a time of their choosing. We do this because a close()
 *        operation on an async I/O socket may block for a significant amount of
 *        time and it therefore may be better for the user to close the socket
 *        in a different thread. Therefore, you MUST ensure that you close the
 *        returned file descriptor elsewhere in your code otherwise you will leak
 *        file descriptors.
 *
 *  @param logger       A corsaro logger instance to use for logging errors.
 *  @param writer       The fast writer to flush / reset.
 *
 *  @return the file descriptor that was being used to write to disk, or -1 if
 *          no file had been opened by the writer.
 */
int corsaro_reset_fast_trace_writer(corsaro_logger_t *logger,
        corsaro_fast_trace_writer_t *writer);

/** Converts an ERF packet into the pcap format and passes it off to an
 *  asynchronous trace file writer to be written to disk.
 *
 *  @note The ERF packet must be standard Ethernet with no extension headers.
 *
 *  @note Only call this function on a fast writer that has been prepared via
 *        a call to corsaro_start_fast_trace_writer().
 *
 *  @param logger       A corsaro logger instance to use for logging errors.
 *  @param writer       The fast writer to use for writing the packet to disk.
 *  @param packet       The ERF packet to be converted and written.
 *
 *  @return 1 if successful, -1 if an error occurred.
 */
int corsaro_fast_write_erf_packet(corsaro_logger_t *logger,
        corsaro_fast_trace_writer_t *writer, libtrace_packet_t *packet);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
