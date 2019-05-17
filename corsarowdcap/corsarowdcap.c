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
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <zmq.h>
#include <libtrace.h>
#include <libtrace_parallel.h>

#include "corsarowdcap.h"
#include "libcorsaro_log.h"
#include "libcorsaro_trace.h"
#include "utils.h"

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


libtrace_callback_set_t *processing = NULL;
volatile int corsaro_halted = 0;
volatile int corsaro_restart = 0;
volatile int corsaro_last_restart = 0;
volatile int child_halted = 0;

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

static void restart_signal(int sig) {
    struct timespec tv;
    (void)sig;
    clock_gettime(CLOCK_MONOTONIC, &tv);

    /* If we've just restarted, don't bother doing so again -- make
     * whoever is triggering the restart to wait at least a second */
    if (tv.tv_sec > corsaro_last_restart) {
        corsaro_restart = 1;
        corsaro_last_restart = tv.tv_sec;
    }
}


static void child_signal(int sig) {
    int status;
    (void)sig;

    /* We need to call wait() to be able to properly reap any finished
     * child processes */
    while(waitpid(-1, &status, WNOHANG) > 0) {
        child_halted += 1;
    }
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
 *  @param exttype      If 1, append the '.done' extension to the filename.
 *                      This is used to create special empty files which
 *                      indicate to archival scripts that an output file is
 *                      complete and ready to be archived.
 *                      If 2, append the '.stats' extension to the filename.
 *                      This is used to create the stats files.
 *  @return A pointer to a string allocated via strdup() that contains the
 *  output file name derived from the given parameters. This name must be
 *  later freed by the caller to avoid leaking the memory holding the string.
 */
char *corsaro_wdcap_derive_output_name(corsaro_wdcap_global_t *glob,
        uint32_t timestamp, int threadid, int needformat, int exttype) {

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
    } else if (exttype == 1) {
        /* needdone only applies to merged output files, not interim ones. */
        w = stradd(".done", w, end);
    } else if (exttype == 2) {
        w = stradd(".stats", w, end);
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

    tls->ending = 0;

}

/** Initialises local thread state data for a merging thread.
 *
 *  @param tls          The thread local data to be initialised.
 *  @param threadid     The cardinal ID for this thread.
 *  @param glob         The global state for this corsarowdcap instance.
 */
static inline void init_wdcap_merge_data(corsaro_wdcap_merger_t *tls,
		int threadid, corsaro_wdcap_global_t *glob) {

	tls->writer = NULL;
	tls->readers = calloc(glob->threads,
            sizeof(corsaro_wdcap_interim_reader_t));

	tls->glob = glob;
    tls->thread_num = threadid;
    tls->tid = 0;
	tls->waiting = NULL;
	tls->zmq_subsock = NULL;
}


/** Destroys the internal members of a processing thread's local state.
 *
 *  @param tls      The thread local state to be destroyed
 */
static inline void clear_wdcap_thread_data(corsaro_wdcap_local_t *tls) {

	if (tls->writer) {
		corsaro_destroy_fast_trace_writer(tls->glob->logger,
                tls->writer);
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

    tls->zmq_pushsock = zmq_socket(glob->zmq_ctxt, ZMQ_PUB);
    /* This option ensures that sockets don't linger after we close them */
	if (zmq_setsockopt(tls->zmq_pushsock, ZMQ_LINGER, &zero,
			sizeof(zero)) < 0) {
		corsaro_log(glob->logger,
				"error configuring push socket for wdcap processing thread: %s",
				strerror(errno));
		goto initfail;
	}

	if (zmq_connect(tls->zmq_pushsock, CORSARO_WDCAP_INTERNAL_QUEUE_BACK) < 0) {
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

    if (tls->ending) {
        return packet;
    }

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

        tls->current_interval.time = firsttv->tv_sec;
        tls->next_report = firsttv->tv_sec - (firsttv->tv_sec % glob->interval) + glob->interval;
    }

    ptv = trace_get_timeval(packet);

    while (corsaro_restart ||
            (tls->next_report && ptv.tv_sec >= tls->next_report)) {
        /* Tell merger that we've reached the end of the interval */
        mergemsg.threadid = trace_get_perpkt_thread_id(t);
        mergemsg.type = CORSARO_WDCAP_MSG_INTERVAL_DONE;
        mergemsg.timestamp = tls->current_interval.time;
        mergemsg.target_thread =
                (tls->current_interval.time / glob->interval) %
                glob->merge_threads;

        /* VERY IMPORTANT: do not close the fd for the interim file
         * here. close() is a blocking operation, even if the rest
         * of the I/O is asynchronous, so we run the risk of dropping
         * packets while we're waiting for those to complete.
         *
         * Instead, we're going to get the merging thread to do the
         * close for us, since it is a lot less time-sensitive than
         * the processing threads.
         */
        mergemsg.src_fd = -1;

        if (glob->writestats) {
            /* ask libtrace for stats about our processing thread and hand
             * them off to the merger.
             */
            trace_clear_statistics(&mergemsg.lt_stats);
            trace_get_thread_statistics(trace, t, &mergemsg.lt_stats);
        }

        /* Prepare to rotate our interim output file */
        if (tls->writer) {
            int srcfd;
            srcfd = corsaro_reset_fast_trace_writer(glob->logger, tls->writer);
            mergemsg.src_fd = srcfd;
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

        if (corsaro_restart) {
            tls->ending = 1;

            pthread_mutex_lock(&(tls->glob->globmutex));
            tls->glob->threads_ended ++;
            if (tls->glob->threads_ended >= tls->glob->threads) {
                corsaro_halted = 1;
            }
            pthread_mutex_unlock(&(tls->glob->globmutex));

            corsaro_log(glob->logger, "marked proc thread %d as ending",
                    trace_get_perpkt_thread_id(t));
            return packet;
        }
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

    if (glob->consterfframing >= 0 &&
            trace_config(glob->trace, TRACE_OPTION_CONSTANT_ERF_FRAMING,
            &(glob->consterfframing)) < 0) {
        libtrace_err_t err = trace_get_err(glob->trace);
        if (err.err_num != TRACE_ERR_OPTION_UNAVAIL) {
            corsaro_log(glob->logger, "error configuring trace object: %s",
                    err.problem);
            return -1;
        }
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

/** Parse command line arguments and read the configuration file for wdcap.
 *
 *  Performs any other one-off configuration or initialisation required by
 *  a corsarowdcap process.
 *
 *  @param argc     The number of items in the argv array
 *  @param argv     An array of strings containing the command line arguments
 *  @param glob     Global state variable for this corsarowdcap instance. Will
 *                  be allocated and initialised by this function.
 *
 *  @return 0 if successful, 1 if an error occurs
 */
static int init_wdcap_process(int argc, char *argv[],
        corsaro_wdcap_global_t **glob) {

    char *configfile = NULL;
    char *logmodestr = NULL;
	int logmode = GLOBAL_LOGMODE_STDERR;
	struct sigaction sigact;

    optind = 1;
	while (1) {
        int opti = 0;
        struct option long_options[] = {
            { "help", 0, 0, 'h' },
            { "config", 1, 0, 'c'},
            { "log", 1, 0, 'l'},
            { NULL, 0, 0, 0 }
        };

        int c = getopt_long(argc, argv, "l:c:h", long_options,
                &opti);
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
        fprintf(stderr,
                "corsarowdcap: no config file specified. Use -c to specify one.\n");
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

    /* Set up signal handling */
    sigact.sa_handler = child_signal;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGCHLD, &sigact, NULL);

    sigact.sa_handler = cleanup_signal;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);

    sigact.sa_handler = restart_signal;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGHUP, &sigact, NULL);

    signal(SIGPIPE, SIG_IGN);

    /* Create initial global state based on configuration file content */
	*glob = corsaro_wdcap_init_global(configfile, logmode);
	if (*glob == NULL) {
        return 1;
    }

    return 0;
}

/** Start the proxy thread that links the communication channels between
 *  the processing threads and the merging threads.
 *
 *  We need a proxy because this is a multiple-publisher to multiple-subscriber
 *  architecture, which won't work in zeromq any other way.
 */
static void *start_proxy_thread(void *data) {

    corsaro_wdcap_global_t *glob = (corsaro_wdcap_global_t *)data;
    void *xpub, *xsub;
    int zero = 0;

    xsub = zmq_socket(glob->zmq_ctxt, ZMQ_XSUB);
    xpub = zmq_socket(glob->zmq_ctxt, ZMQ_XPUB);

    if (zmq_setsockopt(xsub, ZMQ_LINGER, &zero, sizeof(zero)) < 0) {
        corsaro_log(glob->logger,
                "failed to set linger sockopt on xsub in proxy thread: %s",
                strerror(errno));
        goto endproxy;
    }

    if (zmq_setsockopt(xpub, ZMQ_LINGER, &zero, sizeof(zero)) < 0) {
        corsaro_log(glob->logger,
                "failed to set linger sockopt on xpub in proxy thread: %s",
                strerror(errno));
        goto endproxy;
    }

    if (zmq_bind(xsub, CORSARO_WDCAP_INTERNAL_QUEUE_BACK) < 0) {
        corsaro_log(glob->logger,
                "failed to bind xsub socket in proxy thread: %s",
                strerror(errno));
        goto endproxy;
    }

    if (zmq_bind(xpub, CORSARO_WDCAP_INTERNAL_QUEUE_FRONT) < 0) {
        corsaro_log(glob->logger,
                "failed to bind xpub socket in proxy thread: %s",
                strerror(errno));
        goto endproxy;
    }

    zmq_proxy(xsub, xpub, NULL);
endproxy:
    zmq_close(xsub);
    zmq_close(xpub);
    pthread_exit(NULL);
}

/** Starts a wdcap capture.
 *
 *  @param glob         The global state variable for this wdcap process
 *  @param argc         The number of elements in the argv array
 *  @param argv         The command line arguments provided to this process
 *
 *  @return 0 once the capture has been halted
 */
static int run_wdcap(corsaro_wdcap_global_t *glob, int argc, char *argv[]) {
    sigset_t sig_before, sig_block_all;
	int i, zero=0, mergestarted = 0;
    int forked = 0;
	pthread_t mergetid;
    corsaro_wdcap_message_t haltmsg;
    FILE *pidf = NULL;

    /* Create and initialise thread local state for the processing threads */
	glob->threaddata = calloc(glob->threads, sizeof(corsaro_wdcap_local_t));

    for (i = 0; i < glob->threads; i++) {
        init_wdcap_thread_data(&(glob->threaddata[i]), i, glob);
    }

    glob->mergedata = calloc(glob->merge_threads,
            sizeof(corsaro_wdcap_merger_t));
    for (i = 0; i < glob->merge_threads; i++) {
        init_wdcap_merge_data(&(glob->mergedata[i]), i, glob);
    }

    /* Write our pid to the pidfile, so that our parent thread is able to
     * signal us if we ever need to stop.
     */
    pidf = fopen(glob->pidfile, "w");
    if (!pidf) {
        corsaro_log(glob->logger,
                "error opening pidfile '%s' for corsarowdcap: %s",
                glob->pidfile, strerror(errno));
        goto endwdcap;
    }
    fprintf(pidf, "%u\n", getpid());
    fclose(pidf);

	glob->zmq_ctxt = zmq_ctx_new();

    pthread_create(&(glob->proxy_tid), NULL, start_proxy_thread, glob);

    /* Create a PUB socket that the main thread can use to send messages
     * to the merge thread. This is only really used to tell the merge
     * thread to stop running.
     */
	glob->zmq_pushsock = zmq_socket(glob->zmq_ctxt, ZMQ_PUB);
	if (zmq_setsockopt(glob->zmq_pushsock, ZMQ_LINGER, &zero,
			sizeof(zero)) < 0) {
		corsaro_log(glob->logger,
				"error configuring push socket for wdcap main thread: %s",
				strerror(errno));
        zmq_close(glob->zmq_pushsock);
        glob->zmq_pushsock = NULL;
		goto endwdcap;
	}

	if (zmq_connect(glob->zmq_pushsock, CORSARO_WDCAP_INTERNAL_QUEUE_BACK)
            < 0) {
		corsaro_log(glob->logger,
				"error connecting push socket for wdcap main thread: %s",
				strerror(errno));
        zmq_close(glob->zmq_pushsock);
        glob->zmq_pushsock = NULL;
		goto endwdcap;
	}


    /* Disable signals before starting threads -- this will help ensure that
     * any signals are received by the main thread (and its signal handlers)
     * only.
     */
	sigemptyset(&sig_block_all);
	if (pthread_sigmask(SIG_SETMASK, &sig_block_all, &sig_before) < 0) {
		corsaro_log(glob->logger, "unable to disable signals before starting threads.");
		goto endwdcap;
	}

    /* Start the merging thread */
    for (i = 0; i < glob->merge_threads; i++) {
    	pthread_create(&(glob->mergedata[i].tid), NULL, start_merging_thread,
                &(glob->mergedata[i]));
    }

    mergestarted = 1;

    /* Start reading packets from the trace, which will also start the
     * processing threads.
     */
	if (start_trace_input(glob) < 0) {
		corsaro_log(glob->logger, "failed to start packet source %s.",
				glob->inputuri);
		trace_destroy(glob->trace);
		glob->trace = NULL;
		goto endwdcap;
	}

    /* Re-enable signals */
	if (pthread_sigmask(SIG_SETMASK, &sig_before, NULL) < 0) {
		corsaro_log(glob->logger, "unable to re-enable signals after starting threads.");
		goto endwdcap;
	}

    /* Now we just wait until we get a signal that causes our signal handler
     * to set the halt flag.
     */
	while (!corsaro_halted) {
		usleep(100);
	}

    /* Stop reading packets and halt the processing threads */
	trace_pstop(glob->trace);
	trace_join(glob->trace);

	trace_destroy(glob->trace);
	glob->trace = NULL;

endwdcap:
    if (mergestarted) {
        /* Push a halt message to the merging thread and wait for it to end */
        if (glob->zmq_pushsock) {
            haltmsg.type = CORSARO_WDCAP_MSG_STOP;

            /* All merging threads subscribe to '255' */
            haltmsg.target_thread = 255;

            if (zmq_send(glob->zmq_pushsock, &haltmsg, sizeof(haltmsg),
                    0) < 0) {
                corsaro_log(glob->logger,
                        "error sending halt message to merge thread: %s",
                        strerror(errno));
            }
            zmq_close(glob->zmq_pushsock);
            glob->zmq_pushsock = NULL;
        }

        for (i = 0; i < glob->merge_threads; i++) {
            pthread_join(glob->mergedata[i].tid, NULL);
        }
        corsaro_log(glob->logger, "all threads have joined, exiting.");
    }

    /* Tidy up all our global state */
	for (i = 0; i < glob->threads; i++) {
		clear_wdcap_thread_data(&(glob->threaddata[i]));
	}

    free(glob->mergedata);
	free(glob->threaddata);

	zmq_ctx_destroy(glob->zmq_ctxt);
    pthread_join(glob->proxy_tid, NULL);
	corsaro_wdcap_free_global(glob);

	if (processing) {
		trace_destroy_callback_set(processing);
	}
	return 0;
}

static inline int get_running_pid(corsaro_wdcap_global_t *glob) {

    int runpid;
    FILE *f;

    f = fopen(glob->pidfile, "r");
    if (!f) {
        corsaro_log(glob->logger, "Failed to open file containing running corsarowdcap pid (%s): %s", glob->pidfile, strerror(errno));
        return 0;
    }
    if (fscanf(f, "%d", &runpid) != 1) {
        corsaro_log(glob->logger, "Failed to read file containing running corsarowdcap pid (%s): %s", glob->pidfile, strerror(errno));
        fclose(f);
        return 0;
    }
    fclose(f);
    return runpid;
}

int main(int argc, char *argv[]) {
    struct sigaction sigact;
    corsaro_wdcap_global_t *glob = NULL;
    int runpid = 0;
    int runerr = 0;
    int restart_triggered = 0;

    /* Disable threaded I/O in libwandio, in situations where wandio is
     * used -- we only do uncompressed output so the threading is just
     * extra overhead for us */
    if (setenv("LIBTRACEIO", "nothreads", 1) != 0) {
        fprintf(stderr, "corsarowdcap: unable to set libwandio environment\n");
        return -1;
    }

    corsaro_halted = 0;
    corsaro_restart = 0;

    if (init_wdcap_process(argc, argv, &glob)) {
        runerr = 1;
        goto endwdcap;
    }

    /* For compatibility with systemd, we need to have a parent process that
     * exists for the lifetime of the wdcap instance. This parent process
     * will do nothing other than wait for signals and forward them onto
     * the running capture process, which will be forked from the parent
     * process.
     */

    /* Initial fork -- parent remains the "monitor" process, child becomes
     * the first "capture" process.
     */
    if (fork() == 0) {
        /* this is the first child -- start capture process */
        if (run_wdcap(glob, argc, argv) == 0) {
            return 0;
        }
    }

    /* Everything from here on is the parent monitor process */
    while (!corsaro_halted) {

        if (corsaro_restart) {
            /* we got a HUP, forward it on to our running child */
            runpid = get_running_pid(glob);
            if (runpid == 0) {
                runerr = 1;
                break;
            }

            restart_triggered = 1;
            if (kill(runpid, SIGHUP) < 0) {
                corsaro_log(glob->logger, "Failed to send HUP to running corsarowdcap pid (%s): %s", glob->pidfile, strerror(errno));
                runerr = 1;
                break;
            }
            /* the running child will eventually exit on its own */

            /* re-read global config ourselves, just in case the pidfile
             * location is changed */
	        corsaro_wdcap_free_global(glob);
            glob = NULL;
            if (init_wdcap_process(argc, argv, &glob)) {
                goto endwdcap;
            }
            corsaro_restart = 0;

            if (fork() == 0) {
                /* this is the new child -- start capture process */
                if (run_wdcap(glob, argc, argv) == 0) {
                    return 0;
                }
            }

        }

        while (child_halted > 0) {
            if (!restart_triggered) {
                corsaro_log(glob->logger, "Child corsarowdcap process terminated unexpectedly?");
                runerr = 1;
                corsaro_halted = 1;
                break;
            }
            restart_triggered = 0;
            child_halted --;
        }

        usleep(100);
    }

endwdcap:
    if (!runerr) {
        /* we are halting, so send a TERM to the running child */
        runpid = get_running_pid(glob);
        if (runpid != 0) {
            if (kill(runpid, SIGTERM) < 0 && glob && glob->logger) {
                corsaro_log(glob->logger, "Failed to send TERM to running corsarowdcap pid (%d): %s", runpid, strerror(errno));
            }
        }
    }

	corsaro_wdcap_free_global(glob);
    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
