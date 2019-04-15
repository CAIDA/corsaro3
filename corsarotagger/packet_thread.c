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
#include <libtrace.h>
#include <libtrace_parallel.h>
#include <zmq.h>
#include <assert.h>

#include "libcorsaro_log.h"
#include "libcorsaro_tagging.h"
#include "corsarotagger.h"

/** Initialises thread-local state for a packet processing thread.
 *
 *  @param tls          The thread local state for this thread
 *  @param threadid     The id number of the thread
 *  @param glob         The global state for the corsaro tagger
 */
void init_packet_thread_data(corsaro_packet_local_t *tls,
        int threadid, corsaro_tagger_global_t *glob) {

    int hwm = 0;
    int one = 1;
    tls->stopped = 0;
    tls->lastmisscount = 0;
    tls->lastaccepted = 0;
    tls->tickcounter = 0;

    tls->buf = create_tls_buffer();

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

    if (zmq_connect(tls->pubsock, PACKET_PUB_QUEUE) != 0) {
        corsaro_log(glob->logger,
                "error while connecting zeromq publisher socket in tagger thread %d:%s",
                threadid, strerror(errno));
        tls->stopped = 1;
    }
}

/** Destroys the thread local state for a packet processing thread.
 *
 *  @param glob         The global state for this corsarotagger instance
 *  @param tls          The thread-local state to be destroyed
 *  @param threadid     The identifier for the thread that owned this state
 */
void destroy_local_packet_state(corsaro_tagger_global_t *glob,
        corsaro_packet_local_t *tls, int threadid) {
    int linger = 1000;

    if (tls->pubsock) {
        zmq_setsockopt(tls->pubsock, ZMQ_LINGER, &linger, sizeof(linger));
    }
    zmq_close(tls->pubsock);

    if (tls->buf) {
        free_tls_buffer(tls->buf);
    }

}

/** Create a tagged packet message and publishes it to the tagger proxy
 *  queue.
 *
 *  @param glob         The global state for this corsarotagger instance.
 *  @param tls          The thread-local state for this processing thread.
 *  @param packet       The packet to be published.
 */
int corsaro_publish_tags(corsaro_tagger_global_t *glob,
        corsaro_packet_local_t *tls, libtrace_packet_t *packet) {

    struct timeval tv;
    void *pktcontents;
    uint32_t rem;
    libtrace_linktype_t linktype;
    corsaro_tagger_packet_t *tpkt;
    size_t bufsize;

    pktcontents = trace_get_layer2(packet, &linktype, &rem);
    if (rem == 0 || pktcontents == NULL) {
        return 0;
    }

    if (linktype != TRACE_TYPE_ETH) {
        return 0;
    }
    tv = trace_get_timeval(packet);

    bufsize = sizeof(corsaro_tagger_packet_t) + rem;

    assert(tls->buf->used <= tls->buf->size);
    if (tls->buf->size - tls->buf->used < bufsize) {
		if (tls->buf) {
			corsaro_tagger_internal_msg_t msg;
			msg.type = CORSARO_TAGGER_MSG_TOTAG;
			msg.content.buf = tls->buf;
			zmq_send(tls->pubsock, &msg, sizeof(msg), 0);
		}
        tls->buf = create_tls_buffer();
        if (tls->buf == NULL) {
            corsaro_log(glob->logger, "OOM while tagging packets");
            return -1;
        }
    }

    tpkt = (corsaro_tagger_packet_t *)
            (tls->buf->space + tls->buf->used);

    tpkt->taggedby = 255;
    tpkt->pqueue_pos = 0;
    tpkt->hdr.filterbits = 0;
    tpkt->hdr.ts_sec = tv.tv_sec;
    tpkt->hdr.ts_usec = tv.tv_usec;
    tpkt->hdr.pktlen = rem;
    memset(&(tpkt->hdr.tags), 0, sizeof(corsaro_packet_tags_t));

    tls->buf->used += sizeof(corsaro_tagger_packet_t);
    /* Put the packet itself in the buffer (minus the capture and
     * meta-data headers -- we don't need them).
     */
    memcpy(tls->buf->space + tls->buf->used, pktcontents, rem);
    tls->buf->used += rem;

    return 0;
}



// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

