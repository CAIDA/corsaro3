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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <zmq.h>

#include "libcorsaro_log.h"
#include "libcorsaro_tagging.h"
#include "corsarotagger.h"

#define ASSIGN_HASH_BIN(hash_val, hash_bins, result) { \
    int hmod; \
    hmod = hash_val % hash_bins; \
    if (hmod < 26) {result = 'A' + hmod;} \
    else {result = 'a' + (hmod - 26); } \
}

/** Initialises the local data for a tagging thread.
 *
 *  @param tls          The thread-local data to be initialised
 *  @param threadid     A numeric identifier for the thread that this data
 *                      is going to be attached to
 *  @param glob         The global data for this corsarotagger instance.
 *
 */
void init_tagger_thread_data(corsaro_tagger_local_t *tls,
        int threadid, corsaro_tagger_global_t *glob) {
    int hwm = 0;
    int one = 1;
    char sockname[1024];

    tls->ptid = 0;
    tls->glob = glob;
    tls->stopped = 0;
    tls->tagger = corsaro_create_packet_tagger(glob->logger,
            glob->ipmeta_state);
    tls->errorcount = 0;
    tls->threadid = threadid;

    if (tls->tagger == NULL) {
        corsaro_log(glob->logger,
                "out of memory while creating packet tagger.");
        tls->stopped = 1;
        return;
    }

    /* create zmq socket for publishing */
    tls->pubsock = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
    if (zmq_setsockopt(tls->pubsock, ZMQ_SNDHWM, &hwm, sizeof(hwm)) != 0) {
        corsaro_log(glob->logger,
                "error while setting HWM for zeromq publisher socket in tagger thread %d:%s",
                threadid, strerror(errno));
        tls->stopped = 1;
    }

    /* Don't queue messages for incomplete connections */
    if (zmq_setsockopt(tls->pubsock, ZMQ_IMMEDIATE, &one, sizeof(one)) != 0) {
        corsaro_log(glob->logger,
                "error while setting immediate for zeromq publisher socket in tagger thread %d:%s",
                threadid, strerror(errno));
        tls->stopped = 1;
    }

    snprintf(sockname, 1024, "%s-%d", TAGGER_PUB_QUEUE, threadid);
    if (zmq_bind(tls->pubsock, sockname) != 0) {
        corsaro_log(glob->logger,
                "error while connecting zeromq publisher socket in tagger thread %d:%s",
                threadid, strerror(errno));
        tls->stopped = 1;
    }

    tls->pullsock = zmq_socket(glob->zmq_ctxt, ZMQ_PULL);
    if (zmq_connect(tls->pullsock, TAGGER_SUB_QUEUE) != 0) {
        corsaro_log(glob->logger,
                "error while binding zeromq publisher socket in tagger thread %d:%s",
                threadid, strerror(errno));
        tls->stopped = 1;
    }

    tls->controlsock = zmq_socket(glob->zmq_ctxt, ZMQ_PAIR);
    snprintf(sockname, 1024, "%s-%d", TAGGER_CONTROL_SOCKET, threadid);
    if (zmq_connect(tls->controlsock, sockname) != 0) {
        corsaro_log(glob->logger,
                "error while connecting zeromq control socket in tagger thread %d:%s",
                threadid, strerror(errno));
        tls->stopped = 1;
    }

}

/** Destroys the thread local state for a tagging thread.
 *
 *  @param glob         The global state for this corsarotagger instance
 *  @param tls          The thread-local state to be destroyed
 *  @param threadid     The identifier for the thread that owned this state
 */
void destroy_local_tagger_state(corsaro_tagger_global_t *glob,
        corsaro_tagger_local_t *tls, int threadid) {
    int linger = 1000;

    if (tls->tagger) {
        corsaro_destroy_packet_tagger(tls->tagger);
    }

    if (tls->controlsock) {
        zmq_setsockopt(tls->controlsock, ZMQ_LINGER, &linger, sizeof(linger));
        zmq_close(tls->controlsock);
    }

    if (tls->pubsock) {
        zmq_setsockopt(tls->pubsock, ZMQ_LINGER, &linger, sizeof(linger));
        zmq_close(tls->pubsock);
    }

    if (tls->pullsock) {
        zmq_setsockopt(tls->pullsock, ZMQ_LINGER, &linger, sizeof(linger));
        zmq_close(tls->pullsock);
    }

}


/** Receives and processes a buffer of untagged packets for a tagger thread,
 *  tagging each packet contained within that buffer appropriately and
 *  publishing it to the external proxy thread.
 *
 *  @param tls      The thread-local state for this tagging thread.
 *  @return 1 if the buffer was received and processed successfully, -1
 *          if an error occurs, 0 if there is an EOF on receive.
 */
static int tagger_thread_process_buffer(corsaro_tagger_local_t *tls) {
    uint8_t recvbuf[TAGGER_BUFFER_SIZE];
    int r;
    uint32_t processed;
    corsaro_tagger_buffer_t *buf = NULL;
    corsaro_tagger_internal_msg_t *recvd = NULL;

    memset(recvbuf, 0, TAGGER_BUFFER_SIZE);
    r = zmq_recv(tls->pullsock, recvbuf, TAGGER_BUFFER_SIZE, 0);
    if (r < 0) {
        corsaro_log(tls->glob->logger,
                "error while receiving from pull socket in tagger thread %d: %s",
                tls->threadid, strerror(errno));
        return -1;
    }

    if (r == 0) {
        return 0;
    }

    assert(r == sizeof(corsaro_tagger_internal_msg_t));
    recvd = (corsaro_tagger_internal_msg_t *)recvbuf;
    buf = recvd->content.buf;
    processed = 0;

    /* The buffer probably contains multiple untagged packets, so keep
     * looping until we've tagged them all */
    while (processed < buf->used) {
        corsaro_tagger_packet_t *packet;
        libtrace_ip_t *ip;
        void *l2, *next;
        uint32_t rem;
        uint16_t ethertype;

        packet = (corsaro_tagger_packet_t *)(buf->space + processed);

        if (buf->used - processed < sizeof(corsaro_tagger_packet_t)) {
            corsaro_log(tls->glob->logger,
                    "error: not enough buffer content for a complete header...");
            exit(2);
        }
        processed += sizeof(corsaro_tagger_packet_t);
        if (buf->used - processed < packet->hdr.pktlen) {
            corsaro_log(tls->glob->logger,
                    "error: missing packet contents in tagger thread...");
            exit(2);
        }

        /* Find the IP header in the packet contents.
         * The packet should start with an Ethernet header */
        l2 = buf->space + processed;
        rem = packet->hdr.pktlen;

        next = trace_get_payload_from_layer2(l2, TRACE_TYPE_ETH,
                &ethertype, &rem);
        while (next != NULL && rem > 0) {
            switch(ethertype) {
                case TRACE_ETHERTYPE_8021Q:
                    next = trace_get_payload_from_vlan(next, &ethertype, &rem);
                    continue;
                case TRACE_ETHERTYPE_MPLS:
                    next = trace_get_payload_from_mpls(next, &ethertype, &rem);
                    continue;
                case TRACE_ETHERTYPE_PPP_SES:
                    next = trace_get_payload_from_pppoe(next, &ethertype, &rem);
                    continue;
                default:
                    break;
            }
            break;
        }

        if (rem == 0) {
            next = NULL;
        }

        ip = (libtrace_ip_t *)next;

        /* Actually do the tagging */
        if (corsaro_tag_ippayload(tls->tagger, &(packet->hdr.tags),
                    ip, rem) < 0) {
            corsaro_log(tls->glob->logger,
                    "error while tagging IP payload in tagger thread.");
            tls->errorcount ++;
        }

        /* Using the results of the flowtuple hash tag, assign this packet
         * to one of our output hash bins, so clients will be able to
         * receive the tagged packets in parallel if they desire.
         */
        ASSIGN_HASH_BIN(packet->hdr.tags.ft_hash,
                tls->glob->output_hashbins, packet->hdr.hashbin);
        packet->hdr.filterbits = htons(packet->hdr.tags.highlevelfilterbits);
        packet->taggedby = tls->threadid;
        processed += packet->hdr.pktlen;

        /* Send the packet on to the external proxy for publishing. Don't
         * block -- if the proxy closes its pull socket (i.e. during
         * pre-exit cleanup), we can end up blocking forever.
         */
        while (!corsaro_halted) {
            r = zmq_send(tls->pubsock, packet, sizeof(corsaro_tagger_packet_t)
                    + packet->hdr.pktlen, ZMQ_DONTWAIT);
            if (r < 0) {
                if (errno == EAGAIN) {
                    usleep(10);
                    continue;
                }
                corsaro_log(tls->glob->logger,
                        "error publishing packet from tagger thread %d: %s",
                        tls->threadid, strerror(errno));
                return -1;
            }
            break;
        }

    }
    free_tls_buffer(buf);
    return 1;
}

/** Main loop for a tagger thread. */
void *start_tagger_thread(void *data) {
    corsaro_tagger_local_t *tls = (corsaro_tagger_local_t *)data;
    zmq_pollitem_t items[2];

    /* We have two sockets that we care about -- the pull socket, which
     * we receive untagged packets from, and the control socket, which
     * we receive updated IPmeta state on.
     */

    while (!corsaro_halted) {
        corsaro_tagger_internal_msg_t *recvd = NULL;
        corsaro_tagger_buffer_t *buf = NULL;

        items[0].socket = tls->pullsock;
        items[0].events = ZMQ_POLLIN;
        items[1].socket = tls->controlsock;
        items[1].events = ZMQ_POLLIN;

        if (zmq_poll(items, 2, 100) < 0) {
            corsaro_log(tls->glob->logger,
                    "error while polling in tagger thread %d: %s",
                    tls->threadid, strerror(errno));
            break;
        }

        if (items[1].revents & ZMQ_POLLIN) {
            /* New IPmeta state, replace what we've got */
            char recvbuf[12];
            corsaro_ipmeta_state_t **replace;

            if (zmq_recv(tls->controlsock, recvbuf, 12, 0) < 0) {
                corsaro_log(tls->glob->logger,
                        "error while receiving new IPmeta state in tagger thread %d: %s",
                        tls->threadid, strerror(errno));
                break;
            }

            replace = (corsaro_ipmeta_state_t **)recvbuf;
            corsaro_replace_tagger_ipmeta(tls->tagger, *replace);
        }

        if (items[0].revents & ZMQ_POLLIN) {
            /* Got some untagged packets to process */
            if (tagger_thread_process_buffer(tls) <= 0) {
                break;
            }
        }
    }

    pthread_exit(NULL);
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
