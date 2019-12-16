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

#include "corsaro_report.h"
#include "report_internal.h"

/** Macro that will check if there are more parts remaining in a zeromq
 *  multipart message -- assumes "int more" and "size_t moresize" are in
 *  scope, as well as a corsaro_report_iptracker_t * instance called 'track'.
 */
#define ZEROMQ_CHECK_MORE \
    moresize = sizeof(moresize); \
    if (zmq_getsockopt(track->incoming, ZMQ_RCVMORE, &more, &moresize) < 0) { \
        corsaro_log(track->logger, "error checking if there are more parts to a received ip tracker message: %s", strerror(errno)); \
        goto trackerover; \
    }

/** Updates the tallies for a single observed IP + metric combination.
 *
 *  @param track        The state for this IP tracker thread
 *  @param tagptr       The individual tag for the metric being updated
 *  @param issrc        Set to 1 if the IP was seen as a source IP, 0 if
 *                      the IP was seen as a destination IP.
 *  @param metrictally  The hash map containing the metric tallies to be
 *                      updated.
 *  @param ipaddr       The IP address that participated in this metric
 *  @param asn          The source ASN that participated in this metric
 */

static void update_knownip_metric(corsaro_report_iptracker_t *track,
        corsaro_report_msg_tag_t *tagptr, uint8_t issrc,
        Pvoid_t *metrictally, uint32_t ipaddr, uint32_t asn) {

    corsaro_metric_ip_hash_t *m;
    uint64_t metricid = tagptr->tagid;
    int ret;
    PWord_t pval;

    JLG(pval, *metrictally, (Word_t)metricid);
    if (pval != NULL) {
        m = (corsaro_metric_ip_hash_t *)(*pval);
    } else {
        m = (corsaro_metric_ip_hash_t *)calloc(1,
                sizeof(corsaro_metric_ip_hash_t));

        JLI(pval, *metrictally, (Word_t)metricid);
        m->metricid = metricid;
        m->srcips = NULL;
        m->destips = NULL;
        m->srcasns = NULL;
        m->packets = 0;
        m->bytes = 0;
        *pval = (Word_t)(m);
    }

    /* Only increment byte and packet counts for the source IP half of
     * this metric tag, otherwise we will double-count them */
    if (issrc) {
        m->packets += tagptr->packets;
        m->bytes += tagptr->bytes;

        J1S(ret, m->srcips, (Word_t)ipaddr);
        if (asn != 0) {
            J1S(ret, m->srcasns, (Word_t)asn);
        }
    } else {
        J1S(ret, m->destips, (Word_t)ipaddr);
    }
}

/** Frees an entire metric tally hash map.
 *
 *  @param track        The state for this IP tracker thread
 *  @param methash      The hash map to be destroyed
 */
static void free_metrichash(corsaro_report_iptracker_t *track,
        Pvoid_t methash) {
    corsaro_metric_ip_hash_t *ipiter;
    Word_t index = 0, ret;
    PWord_t pval;

    JLF(pval, methash, index);
    while (pval) {
        ipiter = (corsaro_metric_ip_hash_t *)(*pval);
        J1FA(ret, ipiter->srcips);
        J1FA(ret, ipiter->destips);
        J1FA(ret, ipiter->srcasns);
        free(ipiter);
        JLN(pval, methash, index);
    }
    JLFA(ret, methash);

}

/** Frees an entire IP hash map.
 *
 *  @param track        The state for this IP tracker thread
 *  @param knownips     The IP hash map to be destroyed
 */
static void free_knownips(corsaro_report_iptracker_t *track,
        Pvoid_t knownips) {
    corsaro_ip_hash_t *ipiter;
    Word_t index = 0, ret;
    PWord_t pval;

    JLF(pval, knownips, index);
    while (pval) {
        ipiter = (corsaro_ip_hash_t *)(*pval);
        JLFA(ret, ipiter->metricsseen);
        free(ipiter);

        JLN(pval, knownips, index);
    }
    JLFA(ret, knownips);
}

/** Checks if a packet processing thread has already sent us an interval end
 *  message for the current interval.
 *
 *  If so, any observed metric tags and IPs need to be applied to the *next*
 *  interval instead.
 *
 *  @param outl     The list of incomplete intervals for this IP tracker.
 *  @param sender   The thread ID of the packet processing thread.
 *
 *  @return 1 if the processing thread has ended the interval, 0 if it has not.
 */
static inline int sender_in_outstanding(libtrace_list_t *outl, uint8_t sender) {

    libtrace_list_node_t *n;
    corsaro_report_out_interval_t *o;

    n = outl->head;
    while (n) {
        o = (corsaro_report_out_interval_t *)(n->data);
        n = n->next;

        if (o->reports_recvd[sender]) {
            return 1;
        }
    }
    return 0;
}

/** Updates an IP tracker thread's list of processing threads that have
 *  ended an interval, following receipt of an interval end from a packet
 *  processing thread.
 *
 *  @param outl         The list of incomplete intervals for this IP tracker.
 *  @param ts           The timestamp of the interval to update.
 *  @param limit        The total number of packet processing threads.
 *  @param sender       The thread ID of the packet processing thread that
 *                      has just sent us an interval message.
 *  @return the timestamp of the interval if this was the last thread that
 *          we were waiting on, 0 otherwise.
 */
static uint32_t update_outstanding(libtrace_list_t *outl, uint32_t ts,
        uint8_t limit, uint8_t sender) {

    libtrace_list_node_t *n;
    corsaro_report_out_interval_t *o, newentry;
    uint32_t toret = 0;

    assert(outl);
    n = outl->head;

    while (n) {
        o = (corsaro_report_out_interval_t *)(n->data);
        if (o->interval_ts == ts) {
            if (o->reports_recvd[sender] == 0) {
                o->reports_recvd[sender] = 1;
                o->reports_total ++;
            }
            if (o->reports_total == limit) {
                /* All threads have ended for this interval */
                toret = ts;
                break;
            } else {
                return 0;
            }
        }
        n = n->next;
    }

    if (toret > 0) {
        /* An interval has completed */

        /* Intervals *should* complete in order, but I'm still going
         * to prune any incomplete preceding incomplete intervals just to
         * be safe -- we're unlikely to ever get the missing messages that
         * we're waiting for now anyway.
         */
        corsaro_report_out_interval_t popped;
        while (libtrace_list_pop_front(outl, (void *)((&popped))) > 0) {
            if (popped.interval_ts == toret) {
                break;
            }
        }
        return toret;
    }

    /* This is a new interval, add it to our list */
    if (outl->tail) {
        /* sanity check that our intervals are ending in order */
        o = (corsaro_report_out_interval_t *)(outl->tail->data);
        assert(o->interval_ts < ts);
    }

    /* Only one processing thread, no need to wait */
    if (limit == 1) {
        return ts;
    }

    memset(&(newentry.reports_recvd), 0, sizeof(newentry.reports_recvd));
    newentry.reports_recvd[sender] = 1;
    newentry.reports_total = 1;
    newentry.interval_ts = ts;
    libtrace_list_push_back(outl, (void *)(&newentry));
    return 0;

}


/** Processes and acts upon an "Interval" or "Reset" message received
 *  by an IP tracker thread.
 *
 *  @param track        The IP tracker thread that received the message
 *  @param msg          The message that was received.
 */
static void process_interval_reset_message(corsaro_report_iptracker_t *track,
        corsaro_report_ipmsg_header_t *msg) {

    uint32_t complete;
    uint64_t totallost = 0;
    int i;
	int more;
    size_t moresize;

	ZEROMQ_CHECK_MORE
	if (more != 0) {
		corsaro_log(track->logger, "Interval end messages are not expected to be multi-part");
		/* XXX should try to do more than just return if this happens */
		return;
	}

    pthread_mutex_lock(&(track->mutex));
    if (msg->timestamp == 0) {
        pthread_mutex_unlock(&(track->mutex));
        return;
    }

    if (msg->timestamp <= track->lastresultts) {
        pthread_mutex_unlock(&(track->mutex));
        return;
    }

    /* update our record of which processing threads have
     * completed intervals. */
    complete = update_outstanding(track->outstanding, msg->timestamp,
            track->sourcethreads, msg->sender);
    if (complete == 0) {
        /* still waiting on at least one more thread */
        pthread_mutex_unlock(&(track->mutex));
        return;
    }

 	pthread_mutex_unlock(&(track->mutex));

    /* End of interval, take final tally and update lastresults */

    /* First, make sure that the merging thread has finished with the
     * previous result we gave it...
     */
    do {
        pthread_mutex_lock(&(track->mutex));
        if (track->lastresult == NULL) {
            break;
        }
        pthread_mutex_unlock(&(track->mutex));
        /* TODO use a proper condition variable here */
        sleep(1);
    } while (1);

    if (msg->msgtype == CORSARO_IP_MESSAGE_INTERVAL) {
        track->lastresult = track->currentresult;
        track->lastresultts = complete;
    } else {
        free_metrichash(track, (track->currentresult));
    }

    if (track->haltphase == 1) {
        track->haltphase = 2;
    }
    pthread_mutex_unlock(&(track->mutex));

    for (i = 0; i < track->sourcethreads; i++) {
        totallost += track->sourcetrack[i].lost;
        track->sourcetrack[i].lost = 0;
    }

    if (totallost > 0) {
        corsaro_log(track->logger, "IP tracker thread missed %lu messages from incoming queue", totallost);
    }

    /* Reset IP and metric tally hash maps -- don't forget we may
     * already have some valid info in the "next" interval maps.
     */
    free_knownips(track, track->knownips);
    track->knownips = track->knownips_next;
    track->currentresult = track->nextresult;
    track->knownips_next = NULL;
    track->nextresult = NULL;
trackerover:
	return;
}

#define METRIC_ALLOWED(met, allowflag) \
    if (track->allowedmetricclasses == 0 && (met != CORSARO_METRIC_CLASS_FILTER_CRITERIA)) { \
        allowflag = 1; \
    } else if (track->allowedmetricclasses & (1UL << met)) { \
        allowflag = 1; \
    } else { \
        allowflag = 0; \
    }

/** Processes and acts upon an update message that has been received
 *  by an IP tracker thread.
 *
 *  @param track        The IP tracker thread that received the message
 *  @param msg          The message that was received.
 */
static int process_iptracker_update_message(corsaro_report_iptracker_t *track,
        corsaro_report_ipmsg_header_t *msg, Pvoid_t *knownip,
		Pvoid_t *knowniptally) {


	char *buf, *ptr;
	int more, i, j;
    size_t moresize;
	uint32_t toalloc = 0;
    uint32_t tagsdone = 0;
    uint64_t metricid;
    uint8_t allowed;

	buf = NULL;

	ZEROMQ_CHECK_MORE
	if (more == 0) {
		corsaro_log(track->logger, "IP tracker update message has no body?");
		goto trackerover;
	}

	toalloc = (msg->tagcount * sizeof(corsaro_report_msg_tag_t)) +
			(msg->bodycount * sizeof(corsaro_report_single_ip_header_t));

	buf = calloc(toalloc, 1);
	if (!buf) {
		corsaro_log(track->logger, "Unable to allocate %u bytes for reading an IP tracker update message", toalloc);
		goto trackerover;
	}

	while (track->haltphase != 2) {
		if (zmq_recv(track->incoming, buf, toalloc, 0) < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			corsaro_log(track->logger,
                        "error receiving trailer on tracker pull socket: %s",
                        strerror(errno));
			goto trackerover;
		}
		break;
	}

	ZEROMQ_CHECK_MORE
	if (more == 1) {
		corsaro_log(track->logger, "IP tracker update message has too many parts?");
		goto trackerover;
	}

	ptr = buf;
	for (i = 0; i < msg->bodycount; i++) {
		corsaro_report_single_ip_header_t *iphdr;
		corsaro_report_msg_tag_t *tag;

		iphdr = (corsaro_report_single_ip_header_t *)ptr;

		ptr += sizeof(corsaro_report_single_ip_header_t);

		for (j = 0; j < iphdr->numtags; j++) {
			tag = (corsaro_report_msg_tag_t *)ptr;
            metricid = tag->tagid;

            METRIC_ALLOWED((metricid >> 32), allowed);
            if (allowed) {
			    update_knownip_metric(track, tag, iphdr->issrc,
				        knowniptally, iphdr->ipaddr, iphdr->sourceasn);
            }
			ptr += sizeof(corsaro_report_msg_tag_t);
            tagsdone ++;
		}

		if (ptr - buf >= toalloc && i < msg->bodycount - 1) {
			corsaro_log(track->logger, "warning: IP tracker has walked past the end of a receive buffer!");
            corsaro_log(track->logger, "up to IP %d, total tags done: %u",
                    i, tagsdone);
			break;
		}
	}

	if (buf) free(buf);
	return 0;

trackerover:
	if (buf) free(buf);
	return -1;
}


/** Routine for the IP tracker threads
 *
 * @param tdata     The state for this IP tracker thread (initialised).
 * @return NULL via pthread_exit()
 */
void *start_iptracker(void *tdata) {
    corsaro_report_iptracker_t *track;
    corsaro_report_ipmsg_header_t msg;
    corsaro_report_iptracker_source_t *src;
	Pvoid_t *knownip;
	Pvoid_t *knowniptally;

    track = (corsaro_report_iptracker_t *)tdata;

    /* haltphases:
     * 0 = running
     * 1 = seen halt message, waiting for outstanding intervals to complete
     * 2 = seen halt message, no more outstanding intervals so can exit
     */

    while (track->haltphase != 2) {
        if (zmq_recv(track->incoming, &msg, sizeof(msg), 0) < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }
            corsaro_log(track->logger,
                    "error receiving message on tracker pull socket: %s",
                    strerror(errno));
            pthread_mutex_lock(&(track->mutex));
            track->haltphase = 2;
            pthread_mutex_unlock(&(track->mutex));
            break;
        }

        if (msg.sender >= track->sourcethreads) {
            corsaro_log(track->logger,
                    "invalid sender %u in message received by IP tracker, skipping",
                    msg.sender);
            continue;
        }

        if (msg.msgtype == CORSARO_IP_MESSAGE_HALT) {
            pthread_mutex_lock(&(track->mutex));
            track->haltphase = 2;
            pthread_mutex_unlock(&(track->mutex));
            break;
        }

        /* Check if this message has the expected sequence number. If not,
         * figure out how many have gone missing */
        src = &(track->sourcetrack[msg.sender]);

        if (src->expected != msg.seqno) {
            src->lost += (msg.seqno - src->expected);
        }
        src->expected = msg.seqno + 1;

        if (msg.msgtype == CORSARO_IP_MESSAGE_INTERVAL ||
                msg.msgtype == CORSARO_IP_MESSAGE_RESET) {

            process_interval_reset_message(track, &msg);
            continue;
        }

		/* figure out if our sender has finished the interval already; if
		 * so, we need to update the next interval not the current one.
		 */
		if (libtrace_list_get_size(track->outstanding) == 0) {
			knownip = &(track->knownips);
			knowniptally = &(track->currentresult);
		} else if (sender_in_outstanding(track->outstanding, msg.sender)) {
			knownip = &(track->knownips_next);
			knowniptally = &(track->nextresult);
		} else {
			knownip = &(track->knownips);
			knowniptally = &(track->currentresult);
		}


        if (process_iptracker_update_message(track, &msg, knownip,
				knowniptally) < 0) {
            pthread_mutex_lock(&(track->mutex));
            track->haltphase = 2;
            pthread_mutex_unlock(&(track->mutex));
            break;
        }
    }

trackerover:
    /* Thread is ending, tidy up everything */
    free_metrichash(track, (track->currentresult));
    free_metrichash(track, (track->nextresult));
    free_knownips(track, track->knownips);
    free_knownips(track, track->knownips_next);
    pthread_exit(NULL);
}






// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

