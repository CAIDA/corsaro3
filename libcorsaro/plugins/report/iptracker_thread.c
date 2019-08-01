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

/** Finds the entry for a given IP address in an IP tracker hash map. If
 *  the IP is not present in the map, creates and inserts a new entry which
 *  is then returned.
 *
 *  @param track        The state for the IP tracker thread.
 *  @param knownips     The hash map to search.
 *  @param ipaddr       The IP address to search the hash map for.
 *  @return a pointer to an IP hash entry corresponding to the given IP
 *          address.
 */
static corsaro_ip_hash_t *update_iphash(corsaro_report_iptracker_t *track,
        Pvoid_t *knownips, uint32_t ipaddr) {

    corsaro_ip_hash_t *iphash;
    PWord_t pval;

    JLG(pval, *knownips, (Word_t)ipaddr);
    if (pval == NULL) {
        /* New IP, so create a new entry in our map */
        iphash = calloc(1, sizeof(corsaro_ip_hash_t));
        JLI(pval, *knownips, (Word_t)ipaddr);
        iphash->ipaddr = ipaddr;
        iphash->metricsseen = NULL;
        iphash->metriccount = 0;
        *pval = (Word_t)(iphash);
    } else {
        /* IP exists in the map, return the existing entry */
        iphash = (corsaro_ip_hash_t *)(*pval);
    }

    return iphash;
}

/** Searches and updates the map of metrics associated with a single IP
 *  address. If the metric has not been associated with the IP previously,
 *  a new entry is created for that metric.
 *
 *  Also update the unique source or dest IP tally for the metric if this
 *  is the first time that IP has been seen in that context.
 *
 *  @param iphash       The IP hash entry to be updated.
 *  @param metricid     The ID of the metric.
 *  @param issrc        Set to 1 if the IP was seen as a source IP, 0 if
 *                      the IP was seen as a destination IP.
 *  @param m            The current tallies for the given metric.
 */
static inline void update_metric_map(corsaro_ip_hash_t *iphash,
        uint64_t metricid, uint8_t issrc, corsaro_metric_ip_hash_t *m) {

    uint8_t metval;
    PWord_t pval;

    JLG(pval, iphash->metricsseen, (Word_t)metricid);
    if (pval == NULL) {
        /* metricid was not in the metric hash for this IP */
        JLI(pval, iphash->metricsseen, (Word_t)metricid);
        *pval = 0;
        iphash->metriccount ++;
    }

    /* metval is a simple bitmask that indicates whether we've seen this
     * IP + metric combination before, either as a source IP, destination IP
     * or both.
     * bit 1 (0b0000001) = seen as source
     * bit 2 (0b0000010) = seen as dest
     *
     * If we set a bit for the first time, we can also increment our combined
     * tally of source or dest IPs for this metric.
     */
    metval = (uint8_t) (*pval);
    if (issrc && !(metval & 0x01)) {
        metval |= 0x01;
        *pval = metval;
        m->srcips ++;
    } else if (!issrc && !(metval & 0x02)) {
        metval |= 0x02;
        *pval = metval;
        m->destips ++;
    }
}

/** Updates the tallies for a single observed IP + metric combination.
 *
 *  @param track        The state for this IP tracker thread
 *  @param metricid     The ID of the metric that was observed
 *  @param iphash       The IP hash map entry for the observed IP
 *  @param issrc        Set to 1 if the IP was seen as a source IP, 0 if
 *                      the IP was seen as a destination IP.
 *  @param iplen        The number of IP-layer bytes to add to the tally.
 *  @param metrictally  The hash map containing the metric tallies to be
 *                      updated.
 */

static void update_knownip_metric(corsaro_report_iptracker_t *track,
        corsaro_report_msg_tag_t *tagptr, corsaro_ip_hash_t *iphash,
        uint8_t issrc, Pvoid_t *metrictally) {

    corsaro_metric_ip_hash_t *m;
    uint64_t metricid = tagptr->tagid;

    PWord_t pval;

    JLG(pval, *metrictally, (Word_t)metricid);
    if (pval != NULL) {
        m = (corsaro_metric_ip_hash_t *)(*pval);
    } else {
        m = (corsaro_metric_ip_hash_t *)calloc(1,
                sizeof(corsaro_metric_ip_hash_t));

        JLI(pval, *metrictally, (Word_t)metricid);
        m->metricid = metricid;
        m->srcips = 0;
        m->destips = 0;
        m->packets = 0;
        m->bytes = 0;
        *pval = (Word_t)(m);
    }

    /* An IP length of zero == the packet has already been tallied for
     * this metric, just update IP tallies only. */
    if (issrc) {
        m->packets += tagptr->packets;
        m->bytes += tagptr->bytes;
    }

    update_metric_map(iphash, metricid, issrc, m);
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
	corsaro_ip_hash_t *thisip = NULL;
    uint32_t tagsdone = 0;

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
		thisip = update_iphash(track, knownip, iphdr->ipaddr);

		ptr += sizeof(corsaro_report_single_ip_header_t);

		for (j = 0; j < iphdr->numtags; j++) {
			tag = (corsaro_report_msg_tag_t *)ptr;
			update_knownip_metric(track, tag, thisip, iphdr->issrc,
				knowniptally);
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

