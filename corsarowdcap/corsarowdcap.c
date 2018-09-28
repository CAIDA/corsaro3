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

#define CORSARO_WDCAP_INTERNAL_QUEUE "inproc://wdcapinternal"

libtrace_callback_set_t *processing = NULL;
volatile int corsaro_halted = 0;

static void cleanup_signal(int sig) {
    (void)sig;
    corsaro_halted = 1;
}

void usage(char *prog) {
    printf("Usage: %s [ -l logmode ] -c configfile \n\n", prog);
    printf("Accepted logmodes:\n");
    printf("\tterminal\n\tfile\n\tsyslog\n\tdisabled\n");

}

static char *stradd(const char *str, char *bufp, char *buflim) {
    while(bufp < buflim && (*bufp = *str++) != '\0') {
        ++bufp;
    }
    return bufp;
}

static char *corsaro_wdcap_derive_output_name(corsaro_wdcap_local_t *tls,
        uint32_t timestamp, int threadid) {

    /* Adapted from libwdcap but slightly modified to fit corsaro
     * environment and templating format.
     */

    char scratch[9500];
    char outname[10000];
    char tsbuf[11];
    char *format, *ext;
    char *ptr, *w, *end;
    struct timeval tv;

    if (tls->glob->fileformat) {
        format = tls->glob->fileformat;
    } else {
        format = (char *)"pcapfile";
    }

    if (strcmp(format, "pcapfile") == 0) {
        ext = (char *)"pcap";
    } else {
        ext = format;
    }

    end = scratch + sizeof(scratch);
    ptr = tls->glob->template;

    /* Pre-pend the format */
    w = stradd(format, scratch, end);
    *w++ = ':';

    for (; *ptr; ++ptr) {
        if (*ptr == '%') {
            switch (*++ptr) {
                case '\0':
                    /* Reached end of naming scheme, stop */
                    --ptr;
                    break;
                case CORSARO_IO_MONITOR_PATTERN:
                    /* monitor name */
                    if (tls->glob->monitorid) {
                        w = stradd(tls->glob->monitorid, w, end);
                    }
                    continue;
                case CORSARO_IO_PLUGIN_PATTERN:
                    w = stradd("wdcap", w, end);
                    continue;
                case CORSARO_IO_TRACE_FORMAT_PATTERN:
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

    /* Attach a suitable file extension if the file is compressed */
    w = stradd(".gz", w, end);

    if (w >= end) {
        /* Not enough space for the full filename */
        return NULL;
    }

    if (threadid >= 0) {
        char thspace[1024];
        snprintf(thspace, 1024, "--%d", threadid);
        w = stradd(thspace, w, end);
    }

    if (w >= end) {
        /* Not enough space for the full filename */
        return NULL;
    }
    *w = '\0';

    tv.tv_sec = timestamp;
    strftime(outname, sizeof(outname), scratch, gmtime(&tv.tv_sec));
    return strdup(outname);
}


static inline void init_wdcap_thread_data(corsaro_wdcap_local_t *tls,
		int threadid, corsaro_wdcap_global_t *glob) {

	tls->writer = NULL;
	tls->interval_start_ts = 0;
	tls->interimfilename = NULL;
	tls->glob = glob;

	tls->lastmisscount = 0;
	tls->lastaccepted = 0;

	tls->last_ts = 0;
	tls->next_report = 0;
	tls->current_interval.time = 0;
}

static inline void clear_wdcap_thread_data(corsaro_wdcap_local_t *tls) {

	if (tls->writer) {
		trace_destroy_output(tls->writer);
	}
}

static void *init_trace_processing(libtrace_t *trace, libtrace_thread_t *t,
        void *global) {
    corsaro_wdcap_global_t *glob = (corsaro_wdcap_global_t *)global;
    corsaro_wdcap_local_t *tls;

    tls = &(glob->threaddata[trace_get_perpkt_thread_id(t)]);

    return tls;
}

static void process_tick(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *local, uint64_t tick) {

    corsaro_wdcap_global_t *glob = (corsaro_wdcap_global_t *)global;
    corsaro_wdcap_local_t *tls = (corsaro_wdcap_local_t *)local;
    libtrace_stat_t *stats;

    stats = trace_create_statistics();
    trace_get_thread_statistics(trace, t, stats);

    if (stats->missing > tls->lastmisscount) {
        corsaro_log(glob->logger,
                "thread %d dropped %lu packets in last minute (accepted %lu)",
                trace_get_perpkt_thread_id(t),
                stats->missing - tls->lastmisscount,
                stats->accepted - tls->lastaccepted);
        tls->lastmisscount = stats->missing;
    }
    tls->lastaccepted = stats->accepted;

    free(stats);
}

static libtrace_packet_t *per_packet(libtrace_t *trace, libtrace_thread_t *t,
        void *global, void *local, libtrace_packet_t *packet) {

    corsaro_wdcap_global_t *glob = (corsaro_wdcap_global_t *)global;
    corsaro_wdcap_local_t *tls = (corsaro_wdcap_local_t *)local;
    struct timeval ptv;

	if (tls->current_interval.time == 0) {
		const libtrace_packet_t *first;
		const struct timeval *firsttv;

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
        if (tls->writer) {
            corsaro_destroy_trace_writer(tls->writer);
            tls->writer = NULL;
        }

        /* tell merger that we've reached the end of the interval TODO */


		tls->current_interval.number ++;
		tls->current_interval.time = tls->next_report;
		tls->next_report += glob->interval;
    }

    if (tls->writer == NULL) {
        tls->interimfilename = corsaro_wdcap_derive_output_name(tls,
                tls->current_interval.time,
                trace_get_perpkt_thread_id(t));
        if (tls->interimfilename == NULL) {
            corsaro_log(glob->logger,
                    "unable to create suitable output file name for wdcap");
            corsaro_halted = 1;
            return packet;
        }

        tls->writer = corsaro_create_trace_writer(glob->logger,
                tls->interimfilename, 1, TRACE_OPTION_COMPRESSTYPE_NONE);
        if (tls->writer == NULL) {
            corsaro_log(glob->logger,
                    "unable to open output file for wdcap");
            corsaro_halted = 1;
            return packet;
        }
    }

	if (glob->stripvlans == CORSARO_WDCAP_STRIP_VLANS_ON) {
		packet = trace_strip_packet(packet);
	}

	tls->last_ts = ptv.tv_sec;
	if (corsaro_write_packet(glob->logger, tls->writer, packet) < 0) {
		corsaro_halted = 1;
	}

	return packet;
}

static int start_trace_input(corsaro_wdcap_global_t *glob) {

    glob->trace = trace_create(glob->inputuri);
    if (trace_is_err(glob->trace)) {
        libtrace_err_t err = trace_get_err(glob->trace);
        corsaro_log(glob->logger, "unable to create trace object: %s",
                err.problem);
        return -1;
    }

    trace_set_perpkt_threads(glob->trace, glob->threads);
    trace_set_tick_interval(glob->trace, 60 * 1000);

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

static void *start_merging_thread(void *data) {
	corsaro_wdcap_global_t *glob = (corsaro_wdcap_global_t *)data;
	corsaro_wdcap_merger_t mergestate;
	corsaro_wdcap_message_t msg;
	int zero = 0;

    mergestate.writer = NULL;
	mergestate.readers = calloc(glob->threads,
			sizeof(corsaro_wdcap_interim_reader_t));

	mergestate.zmq_pullsock = zmq_socket(glob->zmq_ctxt, ZMQ_PULL);
	if (zmq_setsockopt(mergestate.zmq_pullsock, ZMQ_LINGER, &zero,
			sizeof(zero)) < 0) {
		corsaro_log(glob->logger,
				"error configuring pull socket for wdcap merge thread: %s",
				strerror(errno));
		goto mergeover;
	}

	if (zmq_bind(mergestate.zmq_pullsock, CORSARO_WDCAP_INTERNAL_QUEUE) < 0) {
		corsaro_log(glob->logger,
				"error binding pull socket for wdcap merge thread: %s",
				strerror(errno));
		goto mergeover;
	}

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
            /* TODO */
        }
    }

mergeover:
	zmq_close(mergestate.zmq_pullsock);
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

	glob->zmq_pushsock = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
	if (zmq_setsockopt(glob->zmq_pushsock, ZMQ_LINGER, &zero,
			sizeof(zero)) < 0) {
		corsaro_log(glob->logger,
				"error configuring push socket for wdcap main thread: %s",
				strerror(errno));
        glob->zmq_pushsock = NULL;
		goto endwdcap;
	}

	if (zmq_connect(glob->zmq_pushsock, CORSARO_WDCAP_INTERNAL_QUEUE) < 0) {
		corsaro_log(glob->logger,
				"error connecting push socket for wdcap main thread: %s",
				strerror(errno));
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
    }

	for (i = 0; i < glob->threads; i++) {
		clear_wdcap_thread_data(&(glob->threaddata[i]));
	}

    zmq_close(glob->zmq_pushsock);
	zmq_ctx_destroy(glob->zmq_ctxt);

	free(glob->threaddata);
	pthread_join(mergetid, NULL);
	corsaro_log(glob->logger, "all threads have joined, exiting.");

	corsaro_wdcap_free_global(glob);


	if (processing) {
		trace_destroy_callback_set(processing);
	}
	return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
