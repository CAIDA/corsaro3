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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <zmq.h>

#include "libcorsaro_common.h"
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
        int threadid, corsaro_tagger_global_t *glob, uint16_t mcast_port) {
    int hwm = glob->outputhwm / 2;
    int one = 1;
    char sockname[1024];

    tls->ptid = 0;
    tls->glob = glob;
    tls->stopped = 0;
    tls->tagger = corsaro_create_packet_tagger(glob->logger,
            glob->ipmeta_state);
    tls->errorcount = 0;
    tls->threadid = threadid;
    tls->mcast_port = mcast_port;
    tls->next_seq = 1;

    if (tls->tagger == NULL) {
        corsaro_log(glob->logger,
                "out of memory while creating packet tagger.");
        tls->stopped = 1;
        return;
    }

    tls->mcast_sock = ndag_create_multicaster_socket(mcast_port,
            glob->ndag_mcastgroup, glob->ndag_sourceaddr, &(tls->mcast_target),
            glob->ndag_ttl);
    if (tls->mcast_sock == -1) {
        corsaro_log(glob->logger,
                "error while creating multicast socket in tagger thread %d",
                threadid);
        tls->stopped = 1;
    }

    ndag_init_encap(&(tls->ndag_params), tls->mcast_sock, tls->mcast_target,
            glob->ndag_monitorid, (uint16_t)threadid, glob->starttime,
            glob->ndag_mtu, NDAG_PKT_CORSAROTAG, 0);

#if 0
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
#endif

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
/*
    if (tls->pubsock) {
        zmq_setsockopt(tls->pubsock, ZMQ_LINGER, &linger, sizeof(linger));
        zmq_close(tls->pubsock);
    }
*/
    if (tls->pullsock) {
        zmq_setsockopt(tls->pullsock, ZMQ_LINGER, &linger, sizeof(linger));
        zmq_close(tls->pullsock);
    }

    ndag_destroy_encap(&(tls->ndag_params));
    ndag_close_multicaster_socket(tls->mcast_sock, tls->mcast_target);

}

static inline int push_message_to_ndag(ndag_encap_params_t *params,
        uint8_t *msgstart, uint16_t msgused, uint16_t reccount,
        uint16_t *savedtosend, corsaro_logger_t *logger, uint8_t force_send) {

    struct iovec iov;

    iov.iov_base = msgstart;
    iov.iov_len = msgused;

    if (ndag_push_encap_iovecs(params, &iov, 1, reccount, *savedtosend) == 0) {
        corsaro_log(logger,
                "error: unable to push tagged packets onto ndag buffer");
        return -1;
    }

    (*savedtosend) = (*savedtosend) + 1;

    if (*savedtosend >= NDAG_BATCH_SIZE || force_send) {

        if (ndag_send_encap_records(params, *savedtosend) == 0) {
            corsaro_log(logger,
                    "error: unable to send tagged packets via ndag");
            return -1;
        }
        ndag_reset_encap_state(params);
        *savedtosend = 0;
    }

    return 0;
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
    int r, ret;
    uint32_t processed;
    corsaro_tagger_buffer_t *buf = NULL;
    corsaro_tagger_internal_msg_t *recvd = NULL;
    uint16_t maxmsg = tls->glob->ndag_mtu - sizeof(ndag_common_t) -
            sizeof(ndag_encap_t);
    uint16_t msgused = 0;
    uint16_t reccount = 0;
    uint8_t *msgstart = NULL;;
    uint16_t savedtosend = 0;

    ret = 1;
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
    msgstart = buf->space;

    ndag_reset_encap_state(&(tls->ndag_params));

    /* The buffer probably contains multiple untagged packets, so keep
     * looping until we've tagged them all */
    while (processed < buf->used) {
        corsaro_tagged_packet_header_t *packet;
        libtrace_ip_t *ip;
        void *l2, *next;
        uint32_t rem;
        uint16_t ethertype, filtbits;

        packet = (corsaro_tagged_packet_header_t *)(buf->space + processed);

        if (buf->used - processed < sizeof(corsaro_tagged_packet_header_t)) {
            corsaro_log(tls->glob->logger,
                    "error: not enough buffer content for a complete header...");
            ret = -1;
            break;
        }
        processed += sizeof(corsaro_tagged_packet_header_t);
        if (buf->used - processed < packet->pktlen) {
            corsaro_log(tls->glob->logger,
                    "error: missing packet contents in tagger thread...");
            ret = -1;
            break;
        }

        /* Find the IP header in the packet contents.
         * The packet should start with an Ethernet header */
        l2 = buf->space + processed;
        rem = packet->pktlen;

        if (rem + sizeof(corsaro_tagged_packet_header_t) > maxmsg - msgused) {
            if (push_message_to_ndag(&(tls->ndag_params), msgstart, msgused,
                    reccount, &savedtosend, tls->glob->logger, 0) < 0) {
                ret = -1;
                break;
            }

            msgstart = buf->space + processed -
                    sizeof(corsaro_tagged_packet_header_t);
            reccount = 0;
            msgused = 0;
        }

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
        if (corsaro_tag_ippayload(tls->tagger, &(packet->tags),
                    ip, rem) < 0) {
            corsaro_log(tls->glob->logger,
                    "error while tagging IP payload in tagger thread.");
            tls->errorcount ++;
        }

        /* Using the results of the flowtuple hash tag, assign this packet
         * to one of our output hash bins, so clients will be able to
         * receive the tagged packets in parallel if they desire.
         */
        ASSIGN_HASH_BIN(packet->tags.ft_hash,
                tls->glob->output_hashbins, packet->hashbin);

        filtbits = 0;
        filtbits = (uint16_t)(packet->tags.filterbits & 0x0f);

        packet->filterbits = htons(filtbits);
        processed += packet->pktlen;

        msgused += packet->pktlen + sizeof(corsaro_tagged_packet_header_t);
        reccount += 1;

        packet->pktlen = htons(packet->pktlen);
        packet->wirelen = htons(packet->wirelen);
        packet->ts_sec = htonl(packet->ts_sec);
        packet->ts_usec = htonl(packet->ts_usec);
        packet->tagger_id = htonl(tls->glob->instance_id);
        packet->seqno = bswap_host_to_be64(tls->next_seq);

        /* Send the packet on to the external proxy for publishing. Don't
         * block -- if the proxy closes its pull socket (i.e. during
         * pre-exit cleanup), we can end up blocking forever.
         */
        #if 0
        while (!corsaro_halted) {
            r = zmq_send(tls->pubsock, packet, sizeof(corsaro_tagged_packet_header_t)
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
        #endif

        tls->next_seq ++;
        if (tls->next_seq == 0) {
            tls->next_seq = 1;
        }

    }

    if (msgused > 0) {
        if (push_message_to_ndag(&(tls->ndag_params), msgstart, msgused,
                reccount, &savedtosend, tls->glob->logger, 1) < 0) {
            ret = -1;
        }
    }
    free_tls_buffer(buf);
    return ret;
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
