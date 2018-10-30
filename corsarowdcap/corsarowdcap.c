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

#include "config.h"
#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

#include <zmq.h>
#include <libtrace.h>
#include <libtrace_parallel.h>

#include "corsarowdcap.h"
#include "libcorsaro3_log.h"
#include "libcorsaro3_trace.h"

/** corsarowdcap
 *
 *  Uses parallel libtrace to capture network traffic in parallel,
 *  then writes those packets (in chronological order) to a file
 *  on disk. The file is regularly rotated on interval boundaries
 *  to maintain sensible file sizes.
 *
 *  This program is specifically optimised for dealing with high
 *  traffic rates, such as those observed by the CAIDA UCSD network
 *  telescope. To meet the requirements of such environments, we've
 *  had to make some compromises in terms of flexibility that may
 *  not be suitable for general purpose capture.
 *
 */

/** Program design -- (warning, long!)
 *
 *  Most of the complexity in corsarowdcap comes from its heavy
 *  parallelism. Once you get that, everything else should seem
 *  pretty straightforward.
 *
 *  Conceptually, we can consider corsarowdcap to be a program of
 *  two halves: reading packets from the input source, and writing
 *  packets to an output trace file.
 *
 *  Parallel libtrace handles most of the heavy lifting for the
 *  reading side. We create a parallel libtrace input, tell it how
 *  many threads to dedicate to reading and processing packets and
 *  provide callback functions that are triggered whenever a
 *  processing thread receives a packet.
 *
 *  Things get more complex when we have to consider how we are going
 *  to write those packets to our output file. Ideally, the file
 *  needs to contain packets in chronological order and all packets
 *  for a particular interval must be written to the correct file;
 *  that is, we cannot close an output file until we are sure that
 *  all of the packets for that interval have been written into it.
 *
 *  If you have, say, 8 libtrace processing threads all reading packets
 *  in parallel, how can you ensure that these requirements are met
 *  while also ensuring that corsarowdcap "holds onto" each packet
 *  for the minimum time possible to avoid internal buffer overflows
 *  and therefore packets being dropped by input source. Therefore,
 *  we need to minimise any blocking operations in the processing
 *  threads -- this includes blocking I/O as well as attempts to
 *  lock mutexes.
 *
 *  The first step is to accept that this is going to be a two-phase
 *  job. The first phase simply focuses on getting copies of the
 *  observed packets onto disk, without worrying about the ordering
 *  requirements. This is time-critical, so has to be as fast as
 *  possible. We do this by having each processing thread write its
 *  packets to an "interim" output file, which we rotate with the
 *  same frequency as the intended final output. Each individual thread
 *  receives its packets in chronological order, so each interim file
 *  is already sorted and we can be sure that whenever a thread sees
 *  a packet for the next interval, there are no more packets coming
 *  for the previous interval.
 *
 *  The second phase is to use a separate thread to periodically
 *  merge the interim output files from the processing threads to
 *  create a single correctly-ordered trace file for each interval.
 *  Each processing thread will signal to the merging thread when they
 *  have completed an interval. Only once all processing threads are
 *  done with a particular interval, can the merging thread can combine
 *  the interim files (after all, individual threads may fall behind
 *  for some reason). When the combined output is complete, the
 *  relevant interim files can be deleted. Merging is much less time
 *  critical than the raw packet processing, but still needs to
 *  complete before the next interval is ready to avoid an
 *  ever-increasing backlog of merge jobs.
 */


#define CORSARO_WDCAP_INTERNAL_QUEUE "inproc://wdcapinternal"

libtrace_callback_set_t *processing = NULL;
volatile int corsaro_halted = 0;

/** Signal handler for SIGTERM and SIGINT
 *
 *  @param sig      The signal received (unused)
 *
 *  Sets 'corsaro_halted' to 1, which will cause the program to begin
 *  a clean exit.
 */
static void cleanup_signal(int sig) {
    (void)sig;
    corsaro_halted = 1;
}

/** Provides usage guidance for this program.
 *
 *  @param prog     The program name
 */
void usage(char *prog) {
    printf("Usage: %s [ -l logmode ] -c configfile \n\n", prog);
    printf("Accepted logmodes:\n");
    printf("\tterminal\n\tfile\n\tsyslog\n\tdisabled\n");

}

/** Concatenates a string onto an existing string buffer, starting
 *  from a given pointer. Basically a strcat() where you supply the
 *  end of the string that you are appending to, rather than having
 *  the function have to find it beforehand.
 *
 *  @param str      The string to add to the existing buffer.
 *  @param bufp     The location in the buffer to start writing the
 *                  new string into.
 *  @param buflim   A pointer to the end of the destination buffer. All
 *                  concatenation will cease when this pointer is
 *                  reached, i.e. the resulting string may be truncated.
 *
 *  @return the pointer to the character *after* the last character
 *          written, which can be used for subsequent calls to stradd.
 */
static char *stradd(const char *str, char *bufp, char *buflim) {
    while(bufp < buflim && (*bufp = *str++) != '\0') {
        ++bufp;
    }
    return bufp;
}

/** Uses the output filename template to create a suitable output file
 *  name for either an interim output file or the final merged output file.
 *  Also replaces all special formatting options in the template with
 *  the appropriate value.
 *
 *  Can be used both to generate a file name for writing, as well as by
 *  the merging thread to figure out the names of the interim files that
 *  it should read.
 *
 *  Supports a variety of format modifiers, including everything
 *  recognised by strftime() (for naming files based on the interval
 *  timestamp) plus a few custom ones specific to corsarowdcap (which
 *  are described in the README).
 *
 *  @param glob         The global state for this corsarowdcap instance.
 *  @param timestamp    The timestamp at the start of the current interval.
 *  @param threadid     The cardinal ID for the thread that is the writer of
 *                      this output file. Set to -1 if the writer is the
 *                      merging thread.
 *  @param needformat   If 1, prepend the trace file format followed by a
 *                      colon to the output filename to create a valid
 *                      libtrace URI.
 *  @param needdone     If 1, append the '.done' extension to the filename.
 *                      This is used to create special empty files which
 *                      indicate to archival scripts that an output file is
 *                      complete and ready to be archived.
 *  @return A pointer to a string allocated via strdup() that contains the
 *  output file name derived from the given parameters. This name must be
 *  later freed by the caller to avoid leaking the memory holding the string.
 */
static char *corsaro_wdcap_derive_output_name(corsaro_wdcap_global_t *glob,
        uint32_t timestamp, int threadid, int needformat, int needdone) {

    /* Adapted from libwdcap but slightly modified to fit corsaro
     * environment and templating format.
     */

    char scratch[9500];
    char outname[10000];
    char tsbuf[11];
    char *format, *ext;
    char *ptr, *w, *end;
    struct timeval tv;

    if (glob->fileformat) {
        format = glob->fileformat;
    } else {
        format = (char *)"pcapfile";
    }

    if (strcmp(format, "pcapfile") == 0) {
        ext = (char *)"pcap";
    } else {
        ext = format;
    }

    end = scratch + sizeof(scratch);
    ptr = glob->template;

    if (needformat) {
        /* Prepend the format -- libtrace output URIs must contain the format
         * but input URIs do not necessarily need it. */
        w = stradd(format, scratch, end);
        *w++ = ':';
    } else {
        w = scratch;
    }

    for (; *ptr; ++ptr) {
        if (*ptr == '%') {
            switch (*++ptr) {
                case '\0':
                    /* Reached end of naming scheme, stop */
                    --ptr;
                    break;
                case CORSARO_IO_MONITOR_PATTERN:
                    /* monitor name */
                    if (glob->monitorid) {
                        w = stradd(glob->monitorid, w, end);
                    }
                    continue;
                case CORSARO_IO_PLUGIN_PATTERN:
                    /* kinda redundant now, but I've kept this for backwards
                     * compatibility.
                     */
                    w = stradd("wdcap", w, end);
                    continue;
                case CORSARO_IO_TRACE_FORMAT_PATTERN:
                    /* Adds the trace file format to the file name, usually
                     * used as an extension (e.g. foo.pcap).
                     */
                    w = stradd(ext, w, end);
                    continue;
                case 's':
                    /* Add unix timestamp */
                    snprintf(tsbuf, sizeof(tsbuf), "%u", timestamp);
                    w = stradd(tsbuf, w, end);
                    continue;
                default:
                    /* Everything should be handled by strftime */
                    --ptr;
            }
        }
        if (w == end)
            break;
        *w++ = *ptr;
    }

    if (w >= end) {
        /* Not enough space for the full filename */
        return NULL;
    }

    /* Interim output files need an extra bit on the end to distinguish
     * the output files for each processing thread.
     */
    if (threadid >= 0) {
        char thspace[1024];
        snprintf(thspace, 1024, "--%d", threadid);
        w = stradd(thspace, w, end);
    } else if (needdone) {
        /* needdone only applies to merged output files, not interim ones. */
        char *dotdone = ".done";
        w = stradd(dotdone, w, end);
    }

    if (w >= end) {
        /* Not enough space for the full filename */
        return NULL;
    }

    /* Make sure we terminate our string */
    *w = '\0';

    /* Use strftime() to resolve any remaining format modifiers. Note
     * that we use UTC for any date-time conversions.
     */
    tv.tv_sec = timestamp;
    strftime(outname, sizeof(outname), scratch, gmtime(&tv.tv_sec));
    return strdup(outname);
}


/** Initialises local thread state data for a processing thread.
 *
 *  @param tls          The thread local data to be initialised.
 *  @param threadid     The cardinal ID for this thread.
 *  @param glob         The global state for this corsarowdcap instance.
 */
static inline void init_wdcap_thread_data(corsaro_wdcap_local_t *tls,
		int threadid, corsaro_wdcap_global_t *glob) {

	tls->writer = corsaro_create_fast_trace_writer();
	tls->interimfilename = NULL;
	tls->glob = glob;

	tls->lastmisscount = 0;
	tls->lastaccepted = 0;

	tls->last_ts = 0;
	tls->next_report = 0;
	tls->current_interval.time = 0;
    tls->zmq_pushsock = NULL;

}

/** Destroys the internal members of a processing thread's local state.
 *
 *  @param tls      The thread local state to be destroyed
 */
static inline void clear_wdcap_thread_data(corsaro_wdcap_local_t *tls) {

	if (tls->writer) {
		corsaro_destroy_fast_trace_writer(tls->writer, tls->glob->logger);
	}

    if (tls->interimfilename) {
        free(tls->interimfilename);
    }

    if (tls->zmq_pushsock) {
        zmq_close(tls->zmq_pushsock);
    }
}

/** Thread-start callback for the processing threads. Invoked when the
 *  input trace is started but before any packets are read.
 *
 *  @param trace        The input trace that has just started.
 *  @param t            The libtrace processing thread that this callback
 *                      applies to.
 *  @param global       The global state for this corsarowdcap instance.
 *
 *  @return The thread local state for the newly-started thread.
 */
static void *init_trace_processing(libtrace_t *trace, libtrace_thread_t *t,
        void *global) {
    corsaro_wdcap_global_t *glob = (corsaro_wdcap_global_t *)global;
    corsaro_wdcap_local_t *tls;
    int zero = 0;

    /* Our thread local state is allocated and stored in the global
     * state -- this is because we want to be able to delay closing
     * our zeromq socket until after the merging thread has finished.
     */
    tls = &(glob->threaddata[trace_get_perpkt_thread_id(t)]);

    tls->zmq_pushsock = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
    /* This option ensures that sockets don't linger after we close them */
	if (zmq_setsockopt(tls->zmq_pushsock, ZMQ_LINGER, &zero,
			sizeof(zero)) < 0) {
		corsaro_log(glob->logger,
				"error configuring push socket for wdcap processing thread: %s",
				strerror(errno));
		goto initfail;
	}

	if (zmq_connect(tls->zmq_pushsock, CORSARO_WDCAP_INTERNAL_QUEUE) < 0) {
		corsaro_log(glob->logger,
				"error binding push socket for wdcap processing thread: %s",
				strerror(errno));
		goto initfail;
	}

    return tls;

initfail:
    /* If we get here, something went wrong with initialising our zeromq
     * socket so let's bring things to a halt.
     */
    zmq_close(tls->zmq_pushsock);
    tls->zmq_pushsock = NULL;
    corsaro_halted = 1;
    return tls;
}

/** Processing thread callback for a libtrace 'tick', i.e. a regular timed
 *  event that occurs independent of incoming packets.
 *
 *  In corsarowdcap, we use the tick callback to do periodic monitoring
 *  to make sure we aren't dropping packets due to being too slow.
 *
 *  @param trace        The libtrace input that this thread is using.
 *  @param t            The processing thread.
 *  @param global       The global state for this corsarowdcap instance.
 *  @param local        The thread local state for this thread.
 *  @param tick         The timestamp of the tick (an ERF timestamp).
 */
static void process_tick(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *local, uint64_t tick) {

    corsaro_wdcap_global_t *glob = (corsaro_wdcap_global_t *)global;
    corsaro_wdcap_local_t *tls = (corsaro_wdcap_local_t *)local;
    libtrace_stat_t *stats;

    stats = trace_create_statistics();
    trace_get_thread_statistics(trace, t, stats);

    /* Libtrace stats are cumulative so we need to compare against
     * the previous stat counter.
     */
    if (stats->missing > tls->lastmisscount) {
        corsaro_log(glob->logger,
                "thread %d dropped %lu packets in last second (accepted %lu)",
                trace_get_perpkt_thread_id(t),
                stats->missing - tls->lastmisscount,
                stats->accepted - tls->lastaccepted);
        tls->lastmisscount = stats->missing;
    }
    tls->lastaccepted = stats->accepted;

    free(stats);
}

/** Per-packet callback for a processing thread.
 *
 *  Writes the received packet to the interim output file. If the packet
 *  has a timestamp after the current interval, we first send an interval
 *  over message to the merging thread and move on to a new interim
 *  output file.
 *
 *  @param trace        The libtrace input that this thread is using.
 *  @param t            The processing thread.
 *  @param global       The global state for this corsarowdcap instance.
 *  @param local        The thread local state for this thread.
 *  @param packet       The packet received from the libtrace input.
 *
 *  @return the packet to signify to libtrace that we are finished with
 *          the packet and it can be released back to the capture device.
 */

static libtrace_packet_t *per_packet(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *local, libtrace_packet_t *packet) {

    corsaro_wdcap_global_t *glob = (corsaro_wdcap_global_t *)global;
    corsaro_wdcap_local_t *tls = (corsaro_wdcap_local_t *)local;
    struct timeval ptv;
    corsaro_wdcap_message_t mergemsg;
    int ret;

	if (tls->current_interval.time == 0) {
        /* This is the first packet we've seen, so we need to initialise
         * our first interval.
         */
		const libtrace_packet_t *first;
		const struct timeval *firsttv;

        /* This is slightly tricky, in that we need to make sure all
         * threads start from the same interval (even if the thread's
         * first packet is from the next interval). This ensures that
         * the merging thread can recognise the first interval as
         * complete even in situations where we start our capture very
         * close to an interval boundary.
         */
		if (trace_get_first_packet(trace, t, &first, &firsttv) == -1) {
			corsaro_log(glob->logger,
					"unable to get first packet for input %s?",
					glob->inputuri);
			corsaro_halted = 1;
			return packet;
		}

		if (glob->interval <= 0) {
			corsaro_log(glob->logger,
					"interval has been assigned a bad value of %u",
					glob->interval);
			corsaro_halted = 1;
			return packet;
		}

        tls->current_interval.time = firsttv->tv_sec -
                (firsttv->tv_sec % glob->interval);
        tls->next_report = tls->current_interval.time + glob->interval;
    }

    ptv = trace_get_timeval(packet);

    while (tls->next_report && ptv.tv_sec >= tls->next_report) {
        /* Tell merger that we've reached the end of the interval */
        mergemsg.type = CORSARO_WDCAP_MSG_INTERVAL_DONE;
        mergemsg.timestamp = tls->current_interval.time;

        /* VERY IMPORTANT: do not close the fd for the interim file
         * here. close() is a blocking operation, even if the rest
         * of the I/O is asynchronous, so we run the risk of dropping
         * packets while we're waiting for those to complete.
         *
         * Instead, we're going to get the merging thread to do the
         * close for us, since it is a lot less time-sensitive than
         * the processing threads.
         */
        mergemsg.src_fd = tls->writer->io_fd;

        /* Prepare to rotate our interim output file */
        if (tls->writer) {
            corsaro_reset_fast_trace_writer(tls->writer, glob->logger);
            free(tls->interimfilename);
            tls->interimfilename = NULL;
        }

        if (zmq_send(tls->zmq_pushsock, &mergemsg, sizeof(mergemsg), 0) < 0) {
            corsaro_log(glob->logger,
                    "error sending interval over message to merging thread: %s",
                    strerror(errno));
            corsaro_halted = 1;
            return packet;
        }
		tls->current_interval.number ++;
		tls->current_interval.time = tls->next_report;
		tls->next_report += glob->interval;
    }

    if (tls->interimfilename == NULL) {
        /* Need to open up a new interim file */
        tls->interimfilename = corsaro_wdcap_derive_output_name(tls->glob,
                tls->current_interval.time,
                trace_get_perpkt_thread_id(t), 0, 0);
        if (tls->interimfilename == NULL) {
            corsaro_log(glob->logger,
                    "unable to create suitable output file name for wdcap");
            corsaro_halted = 1;
            return packet;
        }

        ret = corsaro_start_fast_trace_writer(glob->logger, tls->writer,
                tls->interimfilename);
        if (ret == -1) {
            corsaro_log(glob->logger,
                    "unable to open output file for wdcap");
            corsaro_halted = 1;
            return packet;
        }
    }

    /* WARNING: only enable VLAN stripping if you definitely have VLAN
     * tags that need to be stripped. Even if your packets have no VLAN
     * tags, this is a relatively expensive operation so you're much
     * better off just disabling stripping instead.
     */
	if (glob->stripvlans == CORSARO_WDCAP_STRIP_VLANS_ON) {
		packet = trace_strip_packet(packet);
	}

    /* Write the packet to the interim file using asynchronous I/O */
	tls->last_ts = ptv.tv_sec;
	if (corsaro_fast_write_erf_packet(glob->logger, tls->writer,
            packet) < 0) {
		corsaro_halted = 1;
	}
	return packet;
}

/** Creates and starts a parallel libtrace input.
 *
 *  @param glob     The global state for this corsarowdcap instance.
 *
 *  @return -1 if a problem occured, 0 if successful.
 */
static int start_trace_input(corsaro_wdcap_global_t *glob) {

    /* This function is basically boiler-plate parallel libtrace code */

    glob->trace = trace_create(glob->inputuri);
    if (trace_is_err(glob->trace)) {
        libtrace_err_t err = trace_get_err(glob->trace);
        corsaro_log(glob->logger, "unable to create trace object: %s",
                err.problem);
        return -1;
    }

    trace_set_perpkt_threads(glob->trace, glob->threads);

    /* Will trigger a tick every second */
    trace_set_tick_interval(glob->trace, 1000);

    if (!processing) {
        processing = trace_create_callback_set();
        trace_set_starting_cb(processing, init_trace_processing);
        trace_set_packet_cb(processing, per_packet);
        trace_set_tick_interval_cb(processing, process_tick);
    }

    if (trace_pstart(glob->trace, glob, processing, NULL) == -1) {
        libtrace_err_t err = trace_get_err(glob->trace);
        corsaro_log(glob->logger, "unable to start reading from trace object: %s",
                err.problem);
        return -1;
    }

    corsaro_log(glob->logger, "successfully started input trace %s",
            glob->inputuri);

    return 0;
}

/** Determines which of the available packets in the interim files should
 *  be added to the merged output file next.
 *
 *  Merged output file order is chronological, so the packet with the
 *  lowest timestamp will always be chosen.
 *
 *  @param mergestate       The state for the merging thread.
 *  @param inpcount         The number of interim files that are being
 *                          combined to create the merged output.
 *  @param logger           A corsaro logger instance for writing error logs.
 *
 *  @return the index of the interim file reader that the next packet should
 *          be drawn from, or -1 if all readers have run out of packets.
 */
static int choose_next_merge_packet(corsaro_wdcap_merger_t *mergestate,
        int inpcount, corsaro_logger_t *logger) {

    int i, candind = -1;

    /* XXX naive method -- if performance is an issue, consider maintaining
     * a sorted list/map of packet timestamps instead which will reduce
     * the number of comparisons we do (on average)
     */

    for (i = 0; i < inpcount; i++) {
        if (mergestate->readers[i].status == CORSARO_WDCAP_INTERIM_EOF) {
            continue;
        }

        if (mergestate->readers[i].status == CORSARO_WDCAP_INTERIM_NOPACKET) {
            /* We've used the most recent packet for this reader, so read
             * the next one.
             */
            int ret = corsaro_read_next_packet(logger,
                    mergestate->readers[i].source,
                    mergestate->readers[i].nextp);
            if (ret <= 0) {
                /* No more packets in this interim file, flag it as done. */
                mergestate->readers[i].status = CORSARO_WDCAP_INTERIM_EOF;
                continue;
            }
            mergestate->readers[i].nextp_ts = trace_get_erf_timestamp(
                    mergestate->readers[i].nextp);
            mergestate->readers[i].status = CORSARO_WDCAP_INTERIM_PACKET;
        }

        if (candind == -1) {
            /* This is the first valid packet seen this round, so start
             * with this reader as having the "earliest" packet.
             */
            candind = i;
            continue;
        }

        if (mergestate->readers[i].nextp_ts <
                mergestate->readers[candind].nextp_ts) {
            /* This reader's next packet is earlier than our current
             * earliest packet.
             */
            candind = i;
        }
    }

    return candind;
}


static int write_merged_output(corsaro_wdcap_global_t *glob,
        corsaro_wdcap_merger_t *mergestate, uint32_t timestamp) {

    int candind, i, ret = 0;
    char *outname = NULL;
    int success = 0;

    for (i = 0; i < glob->threads; i++) {
        mergestate->readers[i].uri = corsaro_wdcap_derive_output_name(glob,
                timestamp, i, 1, 0);
        mergestate->readers[i].source = corsaro_create_trace_reader(
                glob->logger, mergestate->readers[i].uri);
        if (mergestate->readers[i].source == NULL) {
            mergestate->readers[i].nextp = NULL;
            mergestate->readers[i].nextp_ts = (uint64_t)-1;
            mergestate->readers[i].status = CORSARO_WDCAP_INTERIM_EOF;
        } else {
            mergestate->readers[i].nextp = trace_create_packet();
            mergestate->readers[i].nextp_ts = (uint64_t)-1;
            mergestate->readers[i].status = CORSARO_WDCAP_INTERIM_NOPACKET;

            if (mergestate->readers[i].nextp == NULL) {
                ret = -1;
                goto fail;
            }
        }
    }

    outname = corsaro_wdcap_derive_output_name(glob, timestamp, -1, 1, 0);
    mergestate->writer = corsaro_create_trace_writer(glob->logger,
            outname, CORSARO_TRACE_COMPRESS_LEVEL,
            TRACE_OPTION_COMPRESSTYPE_NONE);
    if (mergestate->writer == NULL) {
        ret = -1;
        goto fail;
    }

    do {
        candind = choose_next_merge_packet(mergestate, glob->threads,
                glob->logger);
        if (candind == -1) {
            break;
        }
        if (corsaro_write_packet(glob->logger, mergestate->writer,
                mergestate->readers[candind].nextp) < 0) {
            ret = -1;
            goto fail;
        }
        mergestate->readers[candind].status = CORSARO_WDCAP_INTERIM_NOPACKET;
    } while (candind != -1);

    success = 1;

fail:
    if (mergestate->writer) {
        corsaro_destroy_trace_writer(mergestate->writer);
        mergestate->writer = NULL;
    }

    if (success) {
        /* All packets have been written to the merged file, now create a special
         * ".done" file so that our archiving scripts can tell that the file is
         * complete. */
        char *donefilename;
        FILE *f;

        donefilename = corsaro_wdcap_derive_output_name(glob, timestamp, -1, 0, 1);
        f = fopen(donefilename, "w");
        /* File can be empty, just has to exist */
        fclose(f);
    }

    for (i = 0; i < glob->threads; i++) {
        if (mergestate->readers[i].nextp) {
            trace_destroy_packet(mergestate->readers[i].nextp);
        }
        if (mergestate->readers[i].source) {
            char *tok, *uri;
            corsaro_destroy_trace_reader(mergestate->readers[i].source);
            uri = mergestate->readers[i].uri;

            tok = strchr(uri, ':');
            if (tok == NULL) {
                tok = uri;
            } else {
                tok ++;
            }
            remove(tok);
        }
        free(mergestate->readers[i].uri);
    }

    if (outname) {
        free(outname);
    }

    return ret;
}

static int merge_finished_interval(corsaro_wdcap_global_t *glob,
        corsaro_wdcap_merger_t *mergestate, uint32_t timestamp) {

    corsaro_wdcap_interval_t *fin = mergestate->waiting;
    corsaro_wdcap_interval_t *prev = NULL;

    if (glob->threads == 1) {
        write_merged_output(glob, mergestate, timestamp);
        return 0;
    }

    while (fin != NULL) {
        if (fin->timestamp == timestamp) {
            break;
        }
        prev = fin;
        fin = fin->next;
    }

    if (fin == NULL) {
        fin = (corsaro_wdcap_interval_t *)malloc(
                sizeof(corsaro_wdcap_interval_t));
        fin->timestamp = timestamp;
        fin->threads_done = 1;
        fin->next = NULL;

        if (prev) {
            prev->next = fin;
        } else {
            mergestate->waiting = fin;
        }
    } else {
        fin->threads_done ++;

        if (fin->threads_done == glob->threads) {
            if (fin != mergestate->waiting) {
                corsaro_log(glob->logger, "Warning: corsarowdcap has completed an interval out of order (missing %u, got %u)",
                        mergestate->waiting->timestamp, timestamp);
            }
            write_merged_output(glob, mergestate, timestamp);
            mergestate->waiting = fin->next;
            free(fin);
        }
    }

    return 0;

}

static void *start_merging_thread(void *data) {
	corsaro_wdcap_global_t *glob = (corsaro_wdcap_global_t *)data;
	corsaro_wdcap_merger_t mergestate;
	corsaro_wdcap_message_t msg;
	int zero = 0;

    mergestate.writer = NULL;
	mergestate.readers = calloc(glob->threads,
			sizeof(corsaro_wdcap_interim_reader_t));

    mergestate.waiting = NULL;
	mergestate.zmq_pullsock = glob->zmq_pullsock;

    corsaro_log(glob->logger, "wdcap merging thread is active");
	while (1) {
		if (zmq_recv(mergestate.zmq_pullsock, &msg, sizeof(msg), 0) < 0) {
			corsaro_log(glob->logger,
				"error receiving message on wdcap merge socket: %s",
				strerror(errno));
			break;
		}

        if (msg.type == CORSARO_WDCAP_MSG_STOP) {
            break;
        } else if (msg.type == CORSARO_WDCAP_MSG_INTERVAL_DONE) {
            close(msg.src_fd);
            merge_finished_interval(glob, &mergestate, msg.timestamp);
        } else {
            printf("%d\n", msg.type);
            exit(0);
        }
    }

mergeover:

    while (mergestate.waiting) {
        corsaro_wdcap_interval_t *fin = mergestate.waiting;

        mergestate.waiting = fin->next;
        free(fin);
    }

    free(mergestate.readers);
	pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    char *configfile = NULL;
    char *logmodestr = NULL;
	corsaro_wdcap_global_t *glob = NULL;
	int logmode = GLOBAL_LOGMODE_STDERR;
	struct sigaction sigact;
    sigset_t sig_before, sig_block_all;
    libtrace_stat_t *stats;
	int i, zero=0;
	pthread_t mergetid;
    corsaro_wdcap_message_t haltmsg;

    if (setenv("LIBTRACEIO", "nothreads", 1) != 0) {
        fprintf(stderr, "corsarowdcap: unable to set libwandio environment");
        return -1;
    }

	while (1) {
        int optind;
        struct option long_options[] = {
            { "help", 0, 0, 'h' },
            { "config", 1, 0, 'c'},
            { "log", 1, 0, 'l'},
            { NULL, 0, 0, 0 }
        };

        int c = getopt_long(argc, argv, "l:c:h", long_options,
                &optind);
        if (c == -1) {
            break;
        }

        switch(c) {
            case 'l':
                logmodestr = optarg;
                break;
            case 'c':
                configfile = optarg;
                break;
            case 'h':
                usage(argv[0]);
                return 1;
            default:
                fprintf(stderr, "corsarowdcap: unsupported option: %c\n", c);
                usage(argv[0]);
                return 1;
        }
    }

    if (configfile == NULL) {
        fprintf(stderr, "corsarowdcap: no config file specified. Use -c to specify one.\n");
        usage(argv[0]);
        return 1;
    }

	if (logmodestr != NULL) {
        if (strcmp(logmodestr, "stderr") == 0 ||
                strcmp(logmodestr, "terminal") == 0) {
            logmode = GLOBAL_LOGMODE_STDERR;
        } else if (strcmp(logmodestr, "file") == 0) {
            logmode = GLOBAL_LOGMODE_FILE;
        } else if (strcmp(logmodestr, "syslog") == 0) {
            logmode = GLOBAL_LOGMODE_SYSLOG;
        } else if (strcmp(logmodestr, "disabled") == 0 ||
                strcmp(logmodestr, "off") == 0 ||
                strcmp(logmodestr, "none") == 0) {
            logmode = GLOBAL_LOGMODE_DISABLED;
        } else {
            fprintf(stderr, "corsarowdcap: unexpected logmode: %s\n",
                    logmodestr);
            usage(argv[0]);
            return 1;
        }
    }
    sigact.sa_handler = cleanup_signal;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    signal(SIGPIPE, SIG_IGN);

	glob = corsaro_wdcap_init_global(configfile, logmode);
	if (glob == NULL) {
        return 1;
    }
	glob->zmq_ctxt = zmq_ctx_new();

	glob->zmq_pullsock = zmq_socket(glob->zmq_ctxt, ZMQ_PULL);
	if (zmq_setsockopt(glob->zmq_pullsock, ZMQ_LINGER, &zero,
			sizeof(zero)) < 0) {
		corsaro_log(glob->logger,
				"error configuring pull socket for wdcap merge thread: %s",
				strerror(errno));
        zmq_close(glob->zmq_pullsock);
        glob->zmq_pullsock = NULL;
		goto endwdcap;
	}

	if (zmq_bind(glob->zmq_pullsock, CORSARO_WDCAP_INTERNAL_QUEUE) < 0) {
		corsaro_log(glob->logger,
				"error connecting pull socket for wdcap merge thread: %s",
				strerror(errno));
        glob->zmq_pullsock = NULL;
		goto endwdcap;
	}

	glob->zmq_pushsock = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
	if (zmq_setsockopt(glob->zmq_pushsock, ZMQ_LINGER, &zero,
			sizeof(zero)) < 0) {
		corsaro_log(glob->logger,
				"error configuring push socket for wdcap main thread: %s",
				strerror(errno));
        zmq_close(glob->zmq_pushsock);
        glob->zmq_pushsock = NULL;
		goto endwdcap;
	}

	if (zmq_connect(glob->zmq_pushsock, CORSARO_WDCAP_INTERNAL_QUEUE) < 0) {
		corsaro_log(glob->logger,
				"error connecting push socket for wdcap main thread: %s",
				strerror(errno));
        zmq_close(glob->zmq_pushsock);
        glob->zmq_pushsock = NULL;
		goto endwdcap;
	}

	pthread_create(&mergetid, NULL, start_merging_thread, glob);

	glob->threaddata = calloc(glob->threads, sizeof(corsaro_wdcap_local_t));

    for (i = 0; i < glob->threads; i++) {
        init_wdcap_thread_data(&(glob->threaddata[i]), i, glob);
    }

	sigemptyset(&sig_block_all);
	if (pthread_sigmask(SIG_SETMASK, &sig_block_all, &sig_before) < 0) {
		corsaro_log(glob->logger, "unable to disable signals before starting threads.");
		goto endwdcap;
	}

	if (start_trace_input(glob) < 0) {
		corsaro_log(glob->logger, "failed to start packet source %s.",
				glob->inputuri);
		trace_destroy(glob->trace);
		glob->trace = NULL;
		goto endwdcap;
	}

	if (pthread_sigmask(SIG_SETMASK, &sig_before, NULL) < 0) {
		corsaro_log(glob->logger, "unable to re-enable signals after starting threads.");
		goto endwdcap;
	}

	while (!corsaro_halted) {
		sleep(1);
	}

	trace_pstop(glob->trace);
	trace_join(glob->trace);

	trace_destroy(glob->trace);
	glob->trace = NULL;

endwdcap:
    if (glob->zmq_pushsock) {
        haltmsg.type = CORSARO_WDCAP_MSG_STOP;
        if (zmq_send(glob->zmq_pushsock, &haltmsg, sizeof(haltmsg), 0) < 0) {
            corsaro_log(glob->logger,
                    "error sending halt message to merge thread: %s",
                    strerror(errno));
        }
        zmq_close(glob->zmq_pushsock);
    }

	for (i = 0; i < glob->threads; i++) {
		clear_wdcap_thread_data(&(glob->threaddata[i]));
	}


	free(glob->threaddata);
	pthread_join(mergetid, NULL);
	corsaro_log(glob->logger, "all threads have joined, exiting.");

    if (glob->zmq_pullsock) {
        zmq_close(glob->zmq_pullsock);
    }

	zmq_ctx_destroy(glob->zmq_ctxt);
	corsaro_wdcap_free_global(glob);


	if (processing) {
		trace_destroy_callback_set(processing);
	}
	return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
