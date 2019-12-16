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
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,  * EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED
 * HEREUNDER IS ON AN “AS IS” BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO
 * OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <zmq.h>
#include <assert.h>

#include "libcorsaro_log.h"
#include "libcorsaro_tagging.h"
#include "libcorsaro_common.h"
#include "corsarotagger.h"
#include "pqueue.h"


/** Get Position function for a tagged packet priority queue */
static size_t pkt_get_pos(void *a) {
    corsaro_tagger_packet_t *pkt = (corsaro_tagger_packet_t *)a;
    return pkt->pqueue_pos;
}

/** Set Position function for a tagged packet priority queue */
static void pkt_set_pos(void *a, size_t pos) {
    corsaro_tagger_packet_t *pkt = (corsaro_tagger_packet_t *)a;
    pkt->pqueue_pos = pos;
}


/** Comparison function for two tagged packets.
 *
 *  @param next     A tagged packet being added to a priority queue
 *  @param curr     A tagged packet already in the priority queue
 *  @return 1 if curr has a high priority than next, 0 if next should
 *          be exported ahead of curr.
 */
static int pkt_cmp_pri(void *next, void *curr) {
    corsaro_tagger_packet_t *nextpkt = (corsaro_tagger_packet_t *)next;
    corsaro_tagger_packet_t *currpkt = (corsaro_tagger_packet_t *)curr;

    if (nextpkt->hdr.ts_sec > currpkt->hdr.ts_sec) {
        return 1;
    }

    if (nextpkt->hdr.ts_sec < currpkt->hdr.ts_sec) {
        return 0;
    }

    if (nextpkt->hdr.ts_usec < currpkt->hdr.ts_usec) {
        return 0;
    }

    return 1;
}

/** Main loop for the proxy thread that publishes tagged packets produced
 *  by the tagging threads.
 *
 *  @param data         The tagger proxy state for this proxy thread.
 */
void *start_zmq_output_thread(void *data) {
    corsaro_tagger_proxy_data_t *proxy = (corsaro_tagger_proxy_data_t *)data;
    corsaro_tagger_global_t *glob = proxy->glob;
    corsaro_tagger_packet_t *packet;
    uint32_t taggerid = 0;
    uint64_t *nextseq = NULL;
    FILE *f;
    int seqindex;
    uint64_t totalseen = 0;

    pqueue_t *pq;
    int i, r, zero = 0, hwm = 250;
    int onesec = 1000;

    void **proxy_recv = calloc(glob->tag_threads, sizeof(void *));
    void *proxy_fwd = zmq_socket(glob->zmq_ctxt, proxy->pushtype);

    uint8_t **recvbufs = calloc(glob->tag_threads, sizeof(uint8_t *));
    uint32_t *recvbufsizes = calloc(glob->tag_threads, sizeof(uint32_t));

    uint8_t **sendbufs = calloc(glob->output_hashbins, sizeof(uint8_t *));
    uint32_t *sendbufsizes = calloc(glob->output_hashbins, sizeof(uint32_t));

    hwm = glob->outputhwm;
    nextseq = (uint64_t *)calloc(glob->output_hashbins, sizeof(uint64_t));

    /* Assign ourselves a "random" tagger ID number so that clients can
     * tell if the tagger is restarted (and therefore its sequence space
     * will be reset).
     * Try using /dev/urandom but fall back to current Unix time if that
     * fails for some reason.
     */
    f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        corsaro_log(glob->logger,
                "unable to open /dev/urandom to generate tagger ID: %s",
                strerror(errno));
        taggerid = (uint32_t) time(NULL);
    }

    while (taggerid == 0) {
        if (fread(&taggerid, sizeof(taggerid), 1, f) < 1) {
            corsaro_log(glob->logger,
                    "unable to read /dev/urandom to generate tagger ID: %s",
                    strerror(errno));
            taggerid = (uint32_t) time(NULL);
        }
    }

    if (f) {
        fclose(f);
    }

    /** Our output needs to be in chronological order, so we'll use a
     *  priority queue to make sure we're publishing the oldest packet
     *  available.
     */
    pq = pqueue_init(glob->tag_threads, pkt_cmp_pri, pkt_get_pos, pkt_set_pos);

    if (zmq_setsockopt(proxy_fwd, ZMQ_LINGER, &zero, sizeof(zero)) < 0) {
        corsaro_log(glob->logger,
                "unable to configure tagger output forwarding socket %s: %s",
                proxy->outsockname, strerror(errno));
        goto proxyexit;
    }

    if (zmq_setsockopt(proxy_fwd, ZMQ_SNDHWM, &hwm, sizeof(hwm)) != 0) {
        corsaro_log(glob->logger,
                "error while setting HWM for output forwarding socket %s: %s",
                proxy->outsockname, strerror(errno));
        goto proxyexit;
    }

    if (zmq_bind(proxy_fwd, proxy->outsockname) < 0) {
        corsaro_log(glob->logger,
                "unable to create tagger output forwarding socket %s: %s",
                proxy->outsockname, strerror(errno));
        goto proxyexit;
    }

    for (i = 0; i < glob->output_hashbins; i++) {
        sendbufs[i] = malloc(TAGGER_MAX_MSGSIZE);
    }

    /* Set up our receiving sockets from each of the tagger threads and
     * read a packet from each to populate the priority queue.
     */
    for (i = 0; i < glob->tag_threads; i++) {
        char sockname[1024];

        snprintf(sockname, 1024, "%s-%d", proxy->insockname, i);

        recvbufs[i] = malloc(TAGGER_BUFFER_SIZE);

        proxy_recv[i] = zmq_socket(glob->zmq_ctxt, ZMQ_PULL);
        if (zmq_setsockopt(proxy_recv[i], ZMQ_LINGER, &zero, sizeof(zero)) < 0) {
            corsaro_log(glob->logger,
                    "unable to configure tagger output recv socket: %s",
                    strerror(errno));
            goto proxyexit;
        }

        /* Only block for a max of one second when reading published packets */
        if (zmq_setsockopt(proxy_recv[i], ZMQ_RCVTIMEO, &onesec, sizeof(onesec)) < 0) {
            corsaro_log(glob->logger,
                    "unable to configure tagger output recv socket %s: %s",
                    sockname,strerror(errno));
            goto proxyexit;
        }

        if (zmq_setsockopt(proxy_recv[i], ZMQ_RCVHWM, &zero, sizeof(zero)) < 0) {
            corsaro_log(glob->logger,
                    "unable to configure tagger output recv socket %s: %s",
                    sockname,strerror(errno));
            goto proxyexit;
        }

        if (zmq_connect(proxy_recv[i], sockname) < 0) {
            corsaro_log(glob->logger,
                    "unable to create tagger output recv socket %s: %s",
                    sockname, strerror(errno));
            goto proxyexit;
        }

        /* Read the first packet produced by each tagger thread */
        while (1) {
            r = zmq_recv(proxy_recv[i], recvbufs[i], TAGGER_BUFFER_SIZE, 0);
            if (r < 0) {
                if (errno == EAGAIN) {
                    continue;
                }
                corsaro_log(glob->logger,
                        "error while reading first packet from tagger thread %d: %s",
                        i, strerror(errno));
                goto proxyexit;
            }
            if (r < sizeof(corsaro_tagger_packet_t)) {
                corsaro_log(glob->logger,
                        "first packet from tagger thread %d is too small?", i);
                goto proxyexit;
            }
            break;
        }
        packet = (corsaro_tagger_packet_t *)recvbufs[i];
        recvbufsizes[i] = r;
        pqueue_insert(pq, recvbufs[i]);
    }

    while (!corsaro_halted) {
        uint8_t *nextpkt;
        uint8_t workind = 0;

        /* Grab the oldest packet from the priority queue */
        nextpkt = (uint8_t *)(pqueue_pop(pq));
        if (nextpkt == NULL) {
            usleep(10);
            continue;
        }
        packet = (corsaro_tagger_packet_t *)nextpkt;
        workind = packet->taggedby;

        if (glob->sample_rate == 1 || ((totalseen % glob->sample_rate) == 0)) {

            if (packet->hdr.hashbin <= 'Z') {
                seqindex = packet->hdr.hashbin - 'A';
            } else {
                seqindex = packet->hdr.hashbin - 'a';
            }

            packet->hdr.tagger_id = htonl(taggerid);
            if (nextseq[seqindex] == 0) {
                nextseq[seqindex] = 1;
            }
            packet->hdr.seqno = bswap_host_to_be64(nextseq[seqindex]);
            nextseq[seqindex] ++;

            if (glob->sample_rate <= 10) {
                if (TAGGER_MAX_MSGSIZE - sendbufsizes[seqindex] <
                        sizeof(packet->hdr) + packet->hdr.pktlen) {

                    zmq_send(proxy_fwd, sendbufs[seqindex],
                            sendbufsizes[seqindex], 0);
                    sendbufsizes[seqindex] = 0;
                }
            }

            memcpy(sendbufs[seqindex] + sendbufsizes[seqindex], &(packet->hdr),
                    sizeof(packet->hdr) + packet->hdr.pktlen);
            sendbufsizes[seqindex] += sizeof(packet->hdr) + packet->hdr.pktlen;
            if (glob->sample_rate > 10) {
                    zmq_send(proxy_fwd, sendbufs[seqindex],
                            sendbufsizes[seqindex], 0);
                    sendbufsizes[seqindex] = 0;
            }
        }

        totalseen ++;

        /* Read the next packet from the worker that provided us with
         * the packet we just published.
         */
        while (!corsaro_halted) {
            r = zmq_recv(proxy_recv[workind], recvbufs[workind],
                    TAGGER_BUFFER_SIZE, ZMQ_DONTWAIT);

            if (r < 0) {
                if (errno == EAGAIN) {
                    usleep(10);
                    continue;
                }
                corsaro_log(glob->logger,
                        "error while reading subsequent packet from tagger thread %d: %s",
                        workind, strerror(errno));
                goto proxyexit;
            }
            if (r < sizeof(corsaro_tagger_packet_t)) {
                corsaro_log(glob->logger,
                        "first packet from tagger thread %d is too small?",
                        workind);
                goto proxyexit;
            }
            break;
        }

        recvbufsizes[workind] = r;
        pqueue_insert(pq, recvbufs[workind]);
    }

proxyexit:
    pqueue_free(pq);
    free(nextseq);
    for (i = 0; i < glob->output_hashbins; i++) {
        if (sendbufsizes[i] > 0) {
            zmq_send(proxy_fwd, sendbufs[i], sendbufsizes[i], 0);
        }
        free(sendbufs[i]);
    }

    for (i = 0; i < glob->tag_threads; i++) {
        if (proxy_recv[i]) {
            zmq_close(proxy_recv[i]);
        }
        free(recvbufs[i]);
    }
    free(proxy_recv);
    free(recvbufs);
    free(recvbufsizes);
    free(sendbufs);
    free(sendbufsizes);
    zmq_close(proxy_fwd);
    pthread_exit(NULL);
}

/** Main loop for the proxy thread that links our packet processing
 *  threads with our tagging worker threads.
 *
 *  @param proxy_recv       A zeromq socket for receiving from the packet
 *                          processing threads.
 *  @param proxy_fwd        A zeromq socket for sending to the tagger threads.
 */
static inline void run_simple_proxy(void *proxy_recv, void *proxy_fwd) {
    int tosend = 0;
    uint8_t recvbuf[TAGGER_BUFFER_SIZE];

    while (!corsaro_halted) {
        int r;

        if (tosend == 0) {
            /* Try read a tagged packet buffer from one of our packet threads */
            if ((r = zmq_recv(proxy_recv, recvbuf, TAGGER_BUFFER_SIZE, 0)) < 0)             {
                if (errno == EAGAIN) {
                    /* Nothing available for now, check if we need to halt
                     * then try again.
                     */
                    continue;
                }
                break;
            }

            tosend = r;
            if (corsaro_halted) {
                break;
            }
            assert(r == sizeof(corsaro_tagger_internal_msg_t));
        }

        /* Got something, publish it to our workers */
        r = zmq_send(proxy_fwd, recvbuf, tosend, ZMQ_DONTWAIT);

        if (r < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            break;
        }
        tosend = 0;
    }
}

/** Starts the thread which manages the proxy that bridges our zeromq
 *  publishing sockets to the clients that are subscribing to them.
 *
 *  The reason for the proxy is to support our multiple-publisher,
 *  multiple-subscriber architecture without either side having to
 *  know how many sockets exist on the other side of the proxy.
 *
 *  @param data         The tagger proxy state for this proxy thread.
 *  @return NULL when the proxy thread has halted.
 */
void *start_zmq_proxy_thread(void *data) {
	corsaro_tagger_proxy_data_t *proxy = (corsaro_tagger_proxy_data_t *)data;
	corsaro_tagger_global_t *glob = proxy->glob;

	void *proxy_recv = zmq_socket(glob->zmq_ctxt, proxy->recvtype);
	void *proxy_fwd = zmq_socket(glob->zmq_ctxt, proxy->pushtype);
	int zero = 0, hwm=1000;
	int onesec = 1000;

	if (zmq_setsockopt(proxy_recv, ZMQ_LINGER, &zero, sizeof(zero)) < 0) {
		corsaro_log(glob->logger,
				"unable to configure tagger proxy recv socket: %s",
				strerror(errno));
		goto proxyexit;
	}

	/* Only block for a max of one second when reading published packets */
	if (zmq_setsockopt(proxy_recv, ZMQ_RCVTIMEO, &onesec, sizeof(onesec)) < 0) {
		corsaro_log(glob->logger,
				"unable to configure tagger proxy recv socket %s: %s",
				proxy->insockname,strerror(errno));
		goto proxyexit;
	}

    if (zmq_setsockopt(proxy_recv, ZMQ_RCVHWM, &hwm, sizeof(hwm)) < 0) {
		corsaro_log(glob->logger,
				"unable to configure tagger proxy recv socket %s: %s",
				proxy->insockname,strerror(errno));
		goto proxyexit;
	}

	if (zmq_bind(proxy_recv, proxy->insockname) < 0) {
		corsaro_log(glob->logger,
				"unable to create tagger proxy recv socket %s: %s",
				proxy->insockname, strerror(errno));
		goto proxyexit;
	}

	if (proxy->recvtype == ZMQ_SUB) {
		/* Subscribe to ALL streams */
		if (zmq_setsockopt(proxy_recv, ZMQ_SUBSCRIBE, "", 0) < 0) {
			corsaro_log(glob->logger,
					"unable to configure tagger proxy recv socket %s: %s",
					proxy->insockname, strerror(errno));
			goto proxyexit;
		}
	}

	if (zmq_setsockopt(proxy_fwd, ZMQ_LINGER, &zero, sizeof(zero)) < 0) {
		corsaro_log(glob->logger,
				"unable to configure tagger proxy forwarding socket %s: %s",
				proxy->outsockname, strerror(errno));
		goto proxyexit;
	}

	/* Allow the forwarding socket to buffer as many messages as it
	 * wants -- NOTE: this means you will run out of memory if you
	 * have a slow client!
	 */
	if (zmq_setsockopt(proxy_fwd, ZMQ_SNDHWM, &hwm, sizeof(hwm)) != 0) {
		corsaro_log(glob->logger,
				"error while setting HWM for proxy forwarding socket %s: %s",
				proxy->outsockname, strerror(errno));
		goto proxyexit;
	}

	if (zmq_bind(proxy_fwd, proxy->outsockname) < 0) {
		corsaro_log(glob->logger,
				"unable to create tagger proxy forwarding socket %s: %s",
				proxy->outsockname, strerror(errno));
		goto proxyexit;
	}

	run_simple_proxy(proxy_recv, proxy_fwd);

proxyexit:
	zmq_close(proxy_recv);
	zmq_close(proxy_fwd);
	pthread_exit(NULL);
}



// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
