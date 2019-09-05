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
#include <unistd.h>
#include <errno.h>
#include <zmq.h>
#include <assert.h>
#include <getopt.h>

#include "libcorsaro_log.h"
#include "libcorsaro_tagging.h"
#include "corsarofanner.h"

volatile int corsaro_halted = 0;

typedef struct corsaro_fanner_thread {
    int id;
    corsaro_fanner_global_t *glob;
    pthread_t pthreadid;
} corsaro_fanner_thread_t;

/** Signal handler for SIGINT and SIGTERM */
static void cleanup_signal(int sig) {
    (void)sig;
    corsaro_halted = 1;
}

static void usage(char *prog) {
    printf("Usage: %s [ -l logmode ] -c configfile \n\n", prog);
    printf("Accepted logmodes:\n");
    printf("\tterminal\n\tfile\n\tsyslog\n\tdisabled\n");
}

static inline void check_stat_timer(corsaro_fanner_global_t *glob,
        int threadid, uint32_t *nextstattime,
        corsaro_tagged_loss_tracker_t *tracker) {

    struct timeval tv;
    uint32_t statfreq = 60;     /* TODO make configurable? */
    FILE *f = NULL;
    char sfname[1024];

    if (glob->statfilename == NULL) {
        return;
    }

    gettimeofday(&tv, NULL);

    if (*nextstattime == 0) {
        *nextstattime = tv.tv_sec - (tv.tv_sec % statfreq) + statfreq;
    }

    if (tv.tv_sec >= *nextstattime) {
        snprintf(sfname, 1024, "%s-t%02d", glob->statfilename, threadid);
        f = fopen(sfname, "w");
        if (!f) {
            corsaro_log(glob->logger, "unable to open stats file %s: %s",
                    sfname, strerror(errno));
        }
    }

    while (tv.tv_sec >= *nextstattime) {
        if (f) {
            fprintf(f, "time=%u bytesreceived=%lu lostpackets=%lu lossinstances=%u\n",
                    (*nextstattime), tracker->bytesreceived,
                    tracker->lostpackets, tracker->lossinstances);
        }
        *nextstattime += statfreq;
        corsaro_reset_tagged_loss_tracker(tracker);
    }

    if (f) {
        fclose(f);
    }
}

static void *run_fanner(void *globalin) {

    corsaro_fanner_thread_t *local = (corsaro_fanner_thread_t *)globalin;
	void *insock, *outsock;
    corsaro_fanner_global_t *glob = local->glob;
	int inhwm = glob->inputhwm;
	int outhwm = glob->outputhwm;
	uint8_t *recvbuf = NULL;
	int processed, r, i, eagaincount, zero = 0;
    char fulloutsockname[256];
    uint32_t nextstattime = 0;
    corsaro_tagged_loss_tracker_t *losstracker = NULL;

	insock = zmq_socket(glob->zmq_ctxt, ZMQ_SUB);
	outsock = zmq_socket(glob->zmq_ctxt, ZMQ_PUB);

	recvbuf = malloc(TAGGER_MAX_MSGSIZE);

	if (zmq_setsockopt(insock, ZMQ_RCVHWM, &inhwm, sizeof(inhwm)) < 0) {
		corsaro_log(glob->logger,
				"unable to configure input socket for corsarofanner: %s",
				strerror(errno));
		goto endfanner;
	}

    for (i = 'A' + local->id; i <= 'z'; i += glob->threads) {
        char substr[5];

        if (i < 'a' && i > 'Z') {
            i = 'a';
        }
        snprintf(substr, 5, "%c", i);

        if (zmq_setsockopt(insock, ZMQ_SUBSCRIBE, substr, 1) < 0) {
            corsaro_log(glob->logger,
                    "unable to subscribe on input socket for corsarofanner: %s",
                    strerror(errno));
            goto endfanner;
        }
    }

	if (zmq_connect(insock, glob->inputsockname) != 0) {
		corsaro_log(glob->logger,
				"unable to connect input socket %s for corsarofanner: %s",
				glob->inputsockname, strerror(errno));
		goto endfanner;
	}

	if (zmq_setsockopt(outsock, ZMQ_LINGER, &zero, sizeof(zero)) < 0) {
		corsaro_log(glob->logger,
				"unable to configure output socket for corsarofanner: %s",
				strerror(errno));
		goto endfanner;
	}

	if (zmq_setsockopt(outsock, ZMQ_SNDHWM, &outhwm, sizeof(outhwm)) < 0) {
		corsaro_log(glob->logger,
				"unable to configure output socket for corsarofanner: %s",
				strerror(errno));
		goto endfanner;
	}

    snprintf(fulloutsockname, 256, "%s%02d", glob->outsockname, local->id);
    if (zmq_bind(outsock, fulloutsockname) < 0) {
        corsaro_log(glob->logger,
                "unable to bind output socket %s: %s", fulloutsockname,
                strerror(errno));
        goto endfanner;
    }

    losstracker = corsaro_create_tagged_loss_tracker(52);
    eagaincount = 0;
	while (!corsaro_halted) {
		r = zmq_recv(insock, recvbuf, TAGGER_MAX_MSGSIZE, ZMQ_DONTWAIT);
		if (r < 0) {
			if (errno == EAGAIN) {
				usleep(10);
                eagaincount ++;

                if (eagaincount >= 50000) {
                    check_stat_timer(glob, local->id, &nextstattime,
                            losstracker);
                    eagaincount = 0;
                }
				continue;
			}
			corsaro_log(glob->logger,
					"corsarofanner: error while reading tagged packet: %s",
					strerror(errno));
			goto endfanner;
		}
		if (r < sizeof(corsaro_tagged_packet_header_t)) {
			corsaro_log(glob->logger,
					"corsarofanner: tagged packet received is unexpectedly small?");
			goto endfanner;
		}

        check_stat_timer(glob, local->id, &nextstattime, losstracker);

        processed = 0;
        while (processed < r) {
            corsaro_tagged_packet_header_t *hdr;

            hdr = (corsaro_tagged_packet_header_t *)(recvbuf + processed);

            corsaro_update_tagged_loss_tracker(losstracker, hdr);
            processed += hdr->pktlen + sizeof(corsaro_tagged_packet_header_t);
        }

        eagaincount = 0;
		/* Republish the same packet(s) to the output queue */
		if (zmq_send(outsock, recvbuf, r, 0) != r) {
        }
	}

endfanner:
	if (outsock) {
		zmq_close(outsock);
	}
	if (insock) {
		zmq_close(insock);
	}
	if (recvbuf) {
		free(recvbuf);
	}
    if (losstracker) {
        corsaro_free_tagged_loss_tracker(losstracker);
    }
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    char *configfile = NULL;
    char *logmodestr = NULL;
    corsaro_fanner_global_t *glob = NULL;
    int logmode = GLOBAL_LOGMODE_STDERR;
    struct sigaction sigact;
    sigset_t sig_before, sig_block_all;
    corsaro_fanner_thread_t *tids;
    int i;
    corsaro_halted = 0;

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
                fprintf(stderr, "corsarofanner: unsupported option: %c\n", c);
                usage(argv[0]);
                return 1;
        }
    }

    if (configfile == NULL) {
        fprintf(stderr, "corsarofanner: no config file specified. Use -c to specify one.\n");
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
            fprintf(stderr, "corsarofanner: unexpected logmode: %s\n",
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

	glob = corsaro_fanner_init_global(configfile, logmode);
	if (glob == NULL) {
		return 1;
	}

    if (glob->inputsockname == NULL) {
        corsaro_log(glob->logger, "config file does not specify a suitable 'subqueuename' -- exiting");
        return 1;
    }

    tids = (corsaro_fanner_thread_t *)calloc(glob->threads,
            sizeof(corsaro_fanner_thread_t));
    if (tids == NULL) {
        corsaro_log(glob->logger, "failed to allocate memory for threads");
        return 1;
    }

    for (i = 0; i < glob->threads; i++) {
        tids[i].id = i;
        tids[i].glob = glob;
        pthread_create(&(tids[i].pthreadid), NULL, run_fanner, &(tids[i]));
    }
    for (i = 0; i < glob->threads; i++) {
        pthread_join(tids[i].pthreadid, NULL);
    }

	corsaro_fanner_free_global(glob);
    free(tids);
	return 0;
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
