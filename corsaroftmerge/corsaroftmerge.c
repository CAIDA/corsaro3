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

#include "libcorsaro_log.h"
#include "libcorsaro_avro.h"
#include "plugins/corsaro_flowtuple.h"
#include "pqueue.h"

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <Judy.h>
#include <zmq.h>

#define BASE_SOCKETNAME "inproc://ftmerger"

struct merger_ft {

    struct corsaro_flowtuple ft;
    int source;
    size_t pqueue_pos;
};

static size_t ft_get_pos(void *a) {
    struct merger_ft *ft = (struct merger_ft *)a;
    return ft->pqueue_pos;
}

static void ft_set_pos(void *a, size_t pos) {
    struct merger_ft *ft = (struct merger_ft *)a;
    ft->pqueue_pos = pos;
}

static int ft_same(struct merger_ft *a, struct merger_ft *b) {

    if (a == NULL || b == NULL) {
        return 0;
    }

    if (a->ft.interval_ts != b->ft.interval_ts) {
        return 0;
    }
    if (a->ft.protocol != b->ft.protocol) {
        return 0;
    }
    if (a->ft.ttl != b->ft.ttl) {
        return 0;
    }
    if (a->ft.tcp_flags != b->ft.tcp_flags) {
        return 0;
    }
    if (a->ft.src_ip != b->ft.src_ip) {
        return 0;
    }
    if (a->ft.dst_ip != b->ft.dst_ip) {
        return 0;
    }
    if (a->ft.src_port != b->ft.src_port) {
        return 0;
    }
    if (a->ft.dst_port != b->ft.dst_port) {
        return 0;
    }
    if (a->ft.ip_len != b->ft.ip_len) {
        return 0;
    }
    if (a->ft.tcp_synlen != b->ft.tcp_synlen) {
        return 0;
    }
    if (a->ft.tcp_synwinlen != b->ft.tcp_synwinlen) {
        return 0;
    }
    return 1;
}

static int ft_cmp_pri(void *next, void *curr) {

    struct merger_ft *nextft = (struct merger_ft *)next;
	struct merger_ft *currft = (struct merger_ft *)curr;

	if (currft->ft.interval_ts != nextft->ft.interval_ts) {
		return (currft->ft.interval_ts < nextft->ft.interval_ts);
	}

	if (currft->ft.protocol != nextft->ft.protocol) {
		return (currft->ft.protocol < nextft->ft.protocol);
	}

	if (currft->ft.ttl != nextft->ft.ttl) {
		return (currft->ft.ttl < nextft->ft.ttl);
	}

	if (currft->ft.tcp_flags != nextft->ft.tcp_flags) {
		return (currft->ft.tcp_flags < nextft->ft.tcp_flags);
	}

	if (currft->ft.src_ip != nextft->ft.src_ip) {
		return (currft->ft.src_ip < nextft->ft.src_ip);
	}

	if (currft->ft.dst_ip != nextft->ft.dst_ip) {
		return (currft->ft.dst_ip < nextft->ft.dst_ip);
	}

	if (currft->ft.src_port != nextft->ft.src_port) {
		return (currft->ft.src_port < nextft->ft.src_port);
	}

	if (currft->ft.dst_port != nextft->ft.dst_port) {
		return (currft->ft.dst_port < nextft->ft.dst_port);
	}

	if (currft->ft.ip_len != nextft->ft.ip_len) {
		return (currft->ft.ip_len < nextft->ft.ip_len);
	}

	if (currft->ft.tcp_synlen != nextft->ft.tcp_synlen) {
		return (currft->ft.tcp_synlen < nextft->ft.tcp_synlen);
	}

	if (currft->ft.tcp_synwinlen != nextft->ft.tcp_synwinlen) {
		return (currft->ft.tcp_synwinlen < nextft->ft.tcp_synwinlen);
	}

	return 1;
}


typedef struct avromerge_reader {
    pthread_t threadid;
    char *source;
    char *sockname;
    void *outsock;
    int readerid;
    corsaro_logger_t *logger;

} avromerge_reader_t;

volatile int halted = 0;

static void cleanup_signal(int sig) {
    (void)sig;
    halted = 1;
}

static inline void combine_flowtuple_records(struct merger_ft *prev,
        struct merger_ft *next) {

    next->ft.packet_cnt += prev->ft.packet_cnt;

}

static void *start_reader(void *arg) {
    avromerge_reader_t *rdata = (avromerge_reader_t *)arg;
    corsaro_avro_reader_t *avrdr = corsaro_create_avro_reader(rdata->logger,
            rdata->source);
    avro_value_t *record;

    int ret = 1, c = 0;
    struct merger_ft *tosend, **end;

    while (ret > 0) {
        ret = corsaro_read_next_avro_record(avrdr, &(record));

        if (ret <= 0) {
            break;
        }
        tosend = calloc(1, sizeof(struct merger_ft));
        tosend->source = rdata->readerid;
        tosend->pqueue_pos = 0;

        decode_flowtuple_from_avro(record, &(tosend->ft));

        if (zmq_send(rdata->outsock, &(tosend), sizeof(struct merger_ft **),
                0) != sizeof(struct merger_ft **)) {
            corsaro_log(rdata->logger, "Error sending message on push socket %s: %s",
                    rdata->sockname, strerror(errno));
            goto endreader;
        }
    }

    end = calloc(1, sizeof(struct merger_ft *));
    *end = NULL;
    if (zmq_send(rdata->outsock, end, sizeof(struct merger_ft **),
                0) != sizeof(struct merger_ft **)) {
        corsaro_log(rdata->logger, "Error sending final message on push socket %s: %s",
                rdata->sockname, strerror(errno));
        goto endreader;
    }


endreader:
	corsaro_destroy_avro_reader(avrdr);
    pthread_exit(NULL);
}

void run_merger(corsaro_logger_t *logger, corsaro_avro_writer_t *avwrt,
        void *zmq_ctxt, int tcount) {
    void **insocks;
    int inhwm = 100;
    int i, ret;
    char sockname[1024];
    char recvbuf[1024];
    struct merger_ft **recvd, *next, *prev;
	pqueue_t *pq;

    insocks = calloc(tcount, sizeof(void *));
	pq = pqueue_init(tcount, ft_cmp_pri, ft_get_pos, ft_set_pos);

    for (i = 0; i < tcount; i++) {
        insocks[i] = zmq_socket(zmq_ctxt, ZMQ_PULL);

        snprintf(sockname, 1024, "%s-%d", BASE_SOCKETNAME, i);

        if (zmq_setsockopt(insocks[i], ZMQ_RCVHWM, &inhwm, sizeof(inhwm)) < 0) {
            corsaro_log(logger, "unable to configure pull socket %s: %s",
                    sockname, strerror(errno));
            goto endmerger;
        }

        if (zmq_connect(insocks[i], sockname) != 0) {
            corsaro_log(logger, "failed to connect to pull socket %s: %s",
                    sockname, strerror(errno));
            goto endmerger;
        }

        ret = zmq_recv(insocks[i], recvbuf, 1024, 0);
        if (ret < 0) {
            corsaro_log(logger, "failed to read first flowtuple from pull socket %s: %s",
                    sockname, strerror(errno));
            goto endmerger;
        }

        recvd = (struct merger_ft **)recvbuf;
        if (*recvd != NULL) {
            pqueue_insert(pq, *recvd);
        }
    }

    prev = NULL;
    while (!halted && (next = (struct merger_ft *)(pqueue_pop(pq)))) {

        if (ft_same(prev, next)) {
        /*
            printf("%d %ld %d %d %d %ld %ld %d %d %d\n", next->source,
                    next->ft.interval_ts, next->ft.protocol, next->ft.ttl,
                    next->ft.tcp_flags, next->ft.src_ip, next->ft.dst_ip,
                    next->ft.src_port, next->ft.dst_port, next->ft.ip_len);
        */
            combine_flowtuple_records(prev, next);
            free(prev);
        } else if (prev) {
            encode_flowtuple_as_avro(&(prev->ft), avwrt, logger);
    		if (corsaro_append_avro_writer(avwrt, NULL) < 0) {
	    		corsaro_log(logger, "Error while writing merged avro record...");
		    }
            free(prev);
        }
        prev = next;
        ret = zmq_recv(insocks[next->source], recvbuf, 1024, 0);
        if (ret < 0) {
            corsaro_log(logger, "failed to read flowtuple from pull socket %s: %s",
                    sockname, strerror(errno));
            goto endmerger;
        }

        recvd = (struct merger_ft **)recvbuf;
        if (*recvd != NULL) {
            pqueue_insert(pq, *recvd);
        }
    }

    if (prev != NULL) {
        encode_flowtuple_as_avro(&(prev->ft), avwrt, logger);
        if (corsaro_append_avro_writer(avwrt, NULL) < 0) {
            corsaro_log(logger, "Error while writing merged avro record...");
        }
    }

endmerger:
    if (prev) {
        free(prev);
    }
	for (i = 0; i < tcount; i++) {
        if (insocks[i]) {
    		zmq_close(insocks[i]);
        }
	}
	free(insocks);
	pqueue_free(pq);
}

int main(int argc, char *argv[]) {
    char *outputpath = NULL;
    int input_c, i;
    struct sigaction sigact;
    sigset_t sig_before, sig_block_all;
    avromerge_reader_t *readers;
    void **push_sockets;
    corsaro_logger_t *logger;
    void *zmq_ctxt;
	corsaro_avro_writer_t *avwrt = NULL;
    int outhwm = 100;
	int logmode = GLOBAL_LOGMODE_STDERR;
	char *logmodestr = NULL;

    sigact.sa_handler = cleanup_signal;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = SA_RESTART;

    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    signal(SIGPIPE, SIG_IGN);

    zmq_ctxt = zmq_ctx_new();

    while (1) {
        int optind;
        struct option long_options[] = {
            { "outputfile", 1, 0, 'o'},
            { "log", 1, 0, 'l'},
            { NULL, 0, 0, 0 }
        };

        int c  = getopt_long(argc, argv, "o:l:", long_options, &optind);
        if (c == -1) {
            break;
        }

        switch(c) {
            case 'o':
                outputpath = optarg;
                break;
			case 'l':
				logmodestr = optarg;
				break;
        }

    }

	if (logmodestr != NULL) {
        if (strcmp(logmodestr, "stderr") == 0 ||
                    strcmp(logmodestr, "terminal") == 0) {
            logmode = GLOBAL_LOGMODE_STDERR;
        } else if (strcmp(logmodestr, "syslog") == 0) {
            logmode = GLOBAL_LOGMODE_SYSLOG;
        } else if (strcmp(logmodestr, "disabled") == 0 ||
                strcmp(logmodestr, "off") == 0 ||
                strcmp(logmodestr, "none") == 0) {
            logmode = GLOBAL_LOGMODE_DISABLED;
        } else {
            fprintf(stderr, "corsaroftmerge: unexpected logmode: %s\n",
                    logmodestr);
            return -1;
        }
    }

	if (logmode == GLOBAL_LOGMODE_STDERR) {
	    logger = init_corsaro_logger("corsaroftmerge", "");
	} else if (logmode == GLOBAL_LOGMODE_SYSLOG) {
	    logger = init_corsaro_logger("corsaroftmerge", NULL);
	} else {
		logger = NULL;
	}

    if (outputpath == NULL) {
        corsaro_log(logger, "Must specify an output file path with -o!");
        return -1;
    }

    if (optind >= argc) {
        corsaro_log(logger, "No inputs specified -- exiting");
        return 0;
    }

    input_c = argc - optind;
    readers = calloc(input_c, sizeof(avromerge_reader_t));
    push_sockets = calloc(input_c, sizeof(void *));

    sigemptyset(&sig_block_all);
    if (pthread_sigmask(SIG_SETMASK, &sig_block_all, &sig_before) < 0) {
        corsaro_log(logger, "Error in pthread_sigmask?: %s", strerror(errno));
        return 1;
    }

    for (i = 0; i < input_c; i++) {
        char sockname[1024];

        snprintf(sockname, 1024, "%s-%d", BASE_SOCKETNAME, i);
        push_sockets[i] = zmq_socket(zmq_ctxt, ZMQ_PUSH);

        if (zmq_setsockopt(push_sockets[i], ZMQ_SNDHWM, &outhwm,
                sizeof(outhwm)) < 0) {
            corsaro_log(logger, "Error configuring push socket %s: %s",
                    sockname, strerror(errno));
            return 1;
        }

        if (zmq_bind(push_sockets[i], sockname) < 0) {
            corsaro_log(logger, "Unable to bind push socket %s: %s",
                    sockname, strerror(errno));
            return 1;
        }

        readers[i].readerid = i;
        readers[i].sockname = strdup(sockname);
        readers[i].source = argv[optind+i];
        readers[i].logger = logger;
        readers[i].outsock = push_sockets[i];
        pthread_create(&(readers[i].threadid), NULL, start_reader, &(readers[i]));
    }

    if (pthread_sigmask(SIG_SETMASK, &sig_before, NULL) < 0) {
        corsaro_log(logger, "Error in pthread_sigmask?: %s", strerror(errno));
        return 1;
    }

	avwrt = corsaro_create_avro_writer(logger, FLOWTUPLE_RESULT_SCHEMA);
	if (avwrt == NULL) {
		return 1;
	}

	if (corsaro_start_avro_writer(avwrt, outputpath, 0) < 0) {
		return 1;
	}

    run_merger(logger, avwrt, zmq_ctxt, input_c);

	corsaro_destroy_avro_writer(avwrt);
    for (i = 0; i < input_c; i++) {
        pthread_join(readers[i].threadid, NULL);
        zmq_close(push_sockets[i]);
    }
    free(readers);
    free(push_sockets);
    zmq_ctx_destroy(zmq_ctxt);
    return 0;

}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
