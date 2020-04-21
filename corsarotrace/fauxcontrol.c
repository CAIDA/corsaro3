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

#include <zmq.h>
#include "libcorsaro_log.h"
#include "corsarotrace.h"

static inline char *send_ipmeta_labels(Pvoid_t labelmap, char *buffer,
        char *rptr, int bufsize, void *sock, uint8_t labeltype) {

    corsaro_tagger_label_hdr_t *hdr;
    Word_t index;
    PWord_t pval;

    index = 0;
    JLF(pval, labelmap, index);
    while (pval) {
        char *label = (char *)(*pval);
        uint32_t subjid = (uint32_t) index;
        int labellen = strlen(label);

        int needed = labellen + sizeof(corsaro_tagger_label_hdr_t);

        if (bufsize - (rptr - buffer) < needed) {
            /* send what we've got */
            if (zmq_send(sock, buffer, rptr-buffer, ZMQ_SNDMORE) < 0) {
                /* TODO log an error? */

            }
            rptr = buffer;
        }

        hdr = (corsaro_tagger_label_hdr_t *)rptr;
        hdr->subject_type = labeltype;
        hdr->subject_id = ntohl(subjid);
        hdr->label_len = ntohs((uint16_t)labellen);

        rptr += sizeof(corsaro_tagger_label_hdr_t);
        memcpy(rptr, label, labellen);
        rptr += labellen;

        JLN(pval, labelmap, index);
    }

    return rptr;
}

static char *send_new_ipmeta_labels(corsaro_ipmeta_state_t *state,
        char *buffer, char *rptr, int bufsize, void *sock) {

    rptr = send_ipmeta_labels(state->recently_added_country_labels, buffer,
            rptr, bufsize, sock, TAGGER_LABEL_COUNTRY);
    rptr = send_ipmeta_labels(state->recently_added_region_labels, buffer,
            rptr, bufsize, sock, TAGGER_LABEL_REGION);
    rptr = send_ipmeta_labels(state->recently_added_polygon_labels, buffer,
            rptr, bufsize, sock, TAGGER_LABEL_POLYGON);

    return rptr;

}

static char *send_all_ipmeta_labels(corsaro_ipmeta_state_t *state,
        char *buffer, char *rptr, int bufsize, void *sock) {

    rptr = send_ipmeta_labels(state->country_labels, buffer, rptr, bufsize,
            sock, TAGGER_LABEL_COUNTRY);
    rptr = send_ipmeta_labels(state->region_labels, buffer, rptr, bufsize,
            sock, TAGGER_LABEL_REGION);
    rptr = send_ipmeta_labels(state->polygon_labels, buffer, rptr, bufsize,
            sock, TAGGER_LABEL_POLYGON);

    return rptr;
}


void *start_faux_control_thread(void *data) {

    corsaro_trace_global_t *glob = (corsaro_trace_global_t *)data;
    void *zmq_control;
    corsaro_tagger_control_request_t req;
    corsaro_tagger_control_reply_t *reply;
    char reply_buffer[10000];
    char *rptr = reply_buffer;
    Word_t rc_word;
    int ending = 0;

    zmq_control = zmq_socket(glob->zmq_ctxt, ZMQ_REP);

    if (zmq_bind(zmq_control, INTERNAL_ZMQ_CONTROL_URI) < 0) {
        corsaro_log(glob->logger, "error while binding faux control socket: %s",
                strerror(errno));
        goto endthread;
    }

    while (!ending) {
        if (zmq_recv(zmq_control, &req, sizeof(req), 0) < 0) {
            if (errno == EINTR) {
                continue;
            }
            corsaro_log(glob->logger, "error while reading message on faux control socket: %s", strerror(errno));
            break;
        }

        switch(req.request_type) {
            case TAGGER_REQUEST_HELLO:
                /* shouldn't get one of these, but be nice anyway */
                reply = (corsaro_tagger_control_reply_t *)reply_buffer;
                reply->hashbins = 4;
                reply->ipmeta_version = 1;
                reply->label_count = 0;
                rptr = reply_buffer + sizeof(corsaro_tagger_control_reply_t);
                break;
            case TAGGER_REQUEST_HALT_FAUX:
                ending = 1;
                break;
            case TAGGER_REQUEST_IPMETA_UPDATE:
                reply = (corsaro_tagger_control_reply_t *)reply_buffer;
                reply->hashbins = 4;
                reply->ipmeta_version = 1;
                reply->label_count = 0;

                rptr = reply_buffer + sizeof(corsaro_tagger_control_reply_t);

                if (glob->ipmeta_state == NULL) {
                    reply->label_count = 0;
                } else if (req.data.last_version == 0) {
                    JLC(rc_word, glob->ipmeta_state->country_labels, 0, -1);
                    reply->label_count += (uint32_t)rc_word;
                    JLC(rc_word, glob->ipmeta_state->region_labels, 0, -1);
                    reply->label_count += (uint32_t)rc_word;
                    reply->label_count = htonl(reply->label_count);

                    rptr = send_all_ipmeta_labels(glob->ipmeta_state,
                            reply_buffer, rptr, 10000, zmq_control);
                } else {
                    JLC(rc_word,
                            glob->ipmeta_state->recently_added_country_labels,
                            0, -1);
                    reply->label_count += (uint32_t)rc_word;
                    JLC(rc_word,
                            glob->ipmeta_state->recently_added_region_labels,
                            0, -1);
                    reply->label_count += (uint32_t)rc_word;
                    reply->label_count = htonl(reply->label_count);
                    rptr = send_new_ipmeta_labels(glob->ipmeta_state,
                            reply_buffer, rptr, 10000, zmq_control);
                }
                break;
        }

        while (rptr - reply_buffer > 0) {
            if (zmq_send(zmq_control, reply_buffer, rptr - reply_buffer,
                        0) < 0) {
                if (errno == EINTR) {
                    continue;
                }
                corsaro_log(glob->logger, "error while sending control message: %s", strerror(errno));
                /* carry on, don't die because of a bad client */
            }
            break;
        }
    }

endthread:
    zmq_close(zmq_control);
    pthread_exit(NULL);
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
