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

#include <libcorsaro_filtering.h>
#include <math.h>

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

static inline corsaro_report_iptracker_maps_t *create_new_map_set() {

    corsaro_report_iptracker_maps_t *maps;

    maps = calloc(1, sizeof(corsaro_report_iptracker_maps_t));
    return maps;
}

static inline bool should_count_address(uint32_t ipaddr, uint32_t *tocount,
        corsaro_report_ipcount_conf_t *ipconf, uint32_t sample_index) {

    uint32_t swapped, mask;
    if (ipconf->method == REPORT_IPCOUNT_METHOD_ALL) {
        *tocount = ipaddr;
        return true;
    }

    swapped = ntohl(ipaddr);
    if (ipconf->method == REPORT_IPCOUNT_METHOD_PREFIXAGG) {
        mask = (0xFFFFFFFF << (32 - ipconf->pfxbits));
        *tocount = (swapped & mask);
        return true;
    }

    if (ipconf->method == REPORT_IPCOUNT_METHOD_SAMPLE) {
        mask = (0xFFFFFFFF << (32 - ipconf->pfxbits));

        if (swapped - mask == sample_index) {
            *tocount = swapped;
            return true;
        }
    }

    *tocount = 0;
    return false;

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
        corsaro_report_iptracker_maps_t *maps, uint32_t ipaddr, uint32_t asn) {

    corsaro_metric_ip_hash_t *m;
    uint64_t metricid = tagptr->tagid;
    uint64_t metricclass = (metricid >> 32);
    uint32_t tocount = 0;
    int ret;
    PWord_t pval;

    if (metricclass == CORSARO_METRIC_CLASS_COMBINED) {
        m = &(maps->combined);
    } else if (metricclass == CORSARO_METRIC_CLASS_IP_PROTOCOL) {
        uint64_t ipproto = (metricid & 0xFFFFFFFF);
        if (maps->ipprotocols == NULL) {
            maps->ipprotocols = calloc(256, sizeof(corsaro_metric_ip_hash_t));
        }

        assert(ipproto < 256);
        m = &(maps->ipprotocols[ipproto]);

    } else if (metricclass == CORSARO_METRIC_CLASS_FILTER_CRITERIA) {
        uint64_t filterid = (metricid & 0xFFFFFFFF);
        if (maps->filters == NULL) {
            maps->filters = calloc(CORSARO_FILTERID_MAX, sizeof(corsaro_metric_ip_hash_t));
        }
        assert(filterid < CORSARO_FILTERID_MAX);
        m = &(maps->filters[filterid]);
    } else if (metricclass == CORSARO_METRIC_CLASS_NETACQ_CONTINENT ||
            metricclass == CORSARO_METRIC_CLASS_NETACQ_COUNTRY ||
            metricclass == CORSARO_METRIC_CLASS_NETACQ_REGION ||
            metricclass == CORSARO_METRIC_CLASS_NETACQ_POLYGON) {

        if (track->netacq_saved.next_saved == MAX_ASSOCIATED_METRICS) {
            /* Ignore hierarchies that exceed our maximum array size */
            return;
        }

        if (metricclass == CORSARO_METRIC_CLASS_NETACQ_POLYGON &&
                (metricid & 0xFFFFFF) == 0) {
            return;
        }

        track->netacq_saved.associated_metricids[
                track->netacq_saved.next_saved] = metricid;
        track->netacq_saved.next_saved ++;

        if (track->netacq_saved.next_saved > 1) {
            /* Don't count packets etc multiple times for each associated
             * metric.
             */
            return;
        }

        if (issrc) {
            track->netacq_saved.srcip = ipaddr;
            track->netacq_saved.srcasn = asn;
            track->netacq_saved.packets = tagptr->packets;
            track->netacq_saved.bytes = tagptr->bytes;
        } else {
            track->netacq_saved.destip = ipaddr;
        }

        return;
    } else {
        JLG(pval, maps->general, (Word_t)metricid);

        if (pval != NULL) {
            m = (corsaro_metric_ip_hash_t *)(*pval);
        } else {
            m = (corsaro_metric_ip_hash_t *)calloc(1,
                    sizeof(corsaro_metric_ip_hash_t));

            JLI(pval, maps->general, (Word_t)metricid);
            m->metricid = metricid;
            m->srcips = NULL;
            m->destips = NULL;
            m->srcasns = NULL;
            m->packets = 0;
            m->bytes = 0;
            *pval = (Word_t)(m);
        }
    }

    /* Only increment byte and packet counts for the source IP half of
     * this metric tag, otherwise we will double-count them */
    if (issrc) {
        m->packets += tagptr->packets;
        m->bytes += tagptr->bytes;

        if (should_count_address(ipaddr, &tocount,
                &(track->conf->src_ipcount_conf), track->srcip_sample_index)) {

            J1S(ret, m->srcips, (Word_t)tocount);
            if (asn != 0 && ret == 1) {
                J1S(ret, m->srcasns, (Word_t)asn);
            }
        }
    } else {
        if (should_count_address(ipaddr, &tocount,
                &(track->conf->dst_ipcount_conf), track->dstip_sample_index)) {
            J1S(ret, m->destips, (Word_t)ipaddr);
        }
    }
}

static void update_knownip_metric_saved(corsaro_report_iptracker_t *track,
        corsaro_report_savedtags_t *saved, corsaro_report_iptracker_maps_t *maps)
{

    uint64_t metricid;
    corsaro_metric_ip_hash_t *m;
    int ret;
    PWord_t pval;

    assert(saved->next_saved > 0);
    metricid = saved->associated_metricids[saved->next_saved - 1];

    JLG(pval, maps->general, (Word_t)metricid);
    if (pval != NULL) {
        m = (corsaro_metric_ip_hash_t *)(*pval);
    } else {
        m = (corsaro_metric_ip_hash_t *)calloc(1,
                    sizeof(corsaro_metric_ip_hash_t));
        JLI(pval, maps->general, (Word_t)metricid);
        m->metricid = metricid;
        memcpy(m->associated_metricids, saved->associated_metricids,
                MAX_ASSOCIATED_METRICS * sizeof(uint64_t));

        m->srcips = NULL;
        m->destips = NULL;
        m->srcasns = NULL;
        m->packets = 0;
        m->bytes = 0;
        *pval = (Word_t)(m);
    }

    m->packets += saved->packets;
    m->bytes += saved->bytes;

    if (saved->destip != 0) {
        J1S(ret, m->destips, (Word_t)saved->destip);
    } else {
        J1S(ret, m->srcips, (Word_t)saved->srcip);
        if (saved->srcasn != 0) {
            J1S(ret, m->srcasns, (Word_t)saved->srcasn);
        }
    }

}

/** Frees an entire metric tally hash map.
 *
 *  @param methash      The hash map to be destroyed
 */
static inline void free_metrichash(corsaro_metric_ip_hash_t *ipiter) {
    int ret;
    J1FA(ret, ipiter->srcips);
    J1FA(ret, ipiter->destips);
    J1FA(ret, ipiter->srcasns);
}

static void free_map_set(corsaro_report_iptracker_maps_t *maps) {
    int i;

    if (maps == NULL) {
        return;
    }

    if (maps->general) {
        corsaro_metric_ip_hash_t *ipiter;
        Word_t index = 0, ret;
        PWord_t pval;

        JLF(pval, maps->general, index);
        while (pval) {
            ipiter = (corsaro_metric_ip_hash_t *)(*pval);
            free_metrichash(ipiter);
            free(ipiter);
            JLN(pval, maps->general, index);
        }
        JLFA(ret, maps->general);
    }

    if (maps->ipprotocols) {
        for (i = 0; i < 256; i++) {
            free_metrichash(&(maps->ipprotocols[i]));
        }
        free(maps->ipprotocols);
    }

    if (maps->filters) {
        for (i = 0; i < CORSARO_FILTERID_MAX; i++) {
            free_metrichash(&(maps->filters[i]));
        }
        free(maps->filters);
    }

    free_metrichash(&(maps->combined));
    free(maps);
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
        if (track->prev_maps == NULL) {
            break;
        }
        pthread_mutex_unlock(&(track->mutex));
        /* TODO use a proper condition variable here */
        sleep(1);
    } while (1);

    if (msg->msgtype == CORSARO_IP_MESSAGE_INTERVAL) {
        track->prev_maps = track->curr_maps;
        track->lastresultts = complete;
        track->srcip_sample_index ++;

        if (track->srcip_sample_index >=
                    pow(2, track->conf->src_ipcount_conf.pfxbits)) {
            track->srcip_sample_index = 0;
        }

        track->dstip_sample_index ++;
        if (track->dstip_sample_index >=
                    pow(2, track->conf->dst_ipcount_conf.pfxbits)) {
            track->dstip_sample_index = 0;
        }
    } else {
        free_map_set(track->curr_maps);
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
    track->curr_maps = track->next_maps;
    track->next_maps = create_new_map_set();
trackerover:
	return;
}

#define METRIC_ALLOWED(met, allowflag) \
    if (track->allowedmetricclasses == 0 && (met == CORSARO_METRIC_CLASS_FILTER_CRITERIA)) { \
        allowflag = 0; \
    } else { \
        allowflag = 1; \
    }

/** Processes and acts upon an update message that has been received
 *  by an IP tracker thread.
 *
 *  @param track        The IP tracker thread that received the message
 *  @param msg          The message that was received.
 */
static int process_iptracker_update_message(corsaro_report_iptracker_t *track,
        corsaro_report_ipmsg_header_t *msg,
        corsaro_report_iptracker_maps_t *maps) {


	uint8_t *ptr;
	int more, i, j;
    size_t moresize;
	uint32_t toalloc = 0;
    uint32_t tagsdone = 0;
    uint64_t metricid;
    uint8_t allowed;

	ZEROMQ_CHECK_MORE
	if (more == 0) {
		corsaro_log(track->logger, "IP tracker update message has no body?");
		goto trackerover;
	}

	toalloc = (msg->tagcount * sizeof(corsaro_report_msg_tag_t)) +
			(msg->bodycount * sizeof(corsaro_report_single_ip_header_t));

    if (track->inbuf == NULL || track->inbuflen < toalloc) {
        track->inbuf = realloc(track->inbuf, toalloc + 256);
        track->inbuflen = toalloc + 256;
    }

	if (!track->inbuf) {
		corsaro_log(track->logger, "Unable to allocate %u bytes for reading an IP tracker update message", toalloc + 256);
		goto trackerover;
	}

	while (track->haltphase != 2) {
		if (zmq_recv(track->incoming, track->inbuf, toalloc, 0) < 0) {
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

	ptr = track->inbuf;
	for (i = 0; i < msg->bodycount; i++) {
		corsaro_report_single_ip_header_t *iphdr;
		corsaro_report_msg_tag_t *tag;

		iphdr = (corsaro_report_single_ip_header_t *)ptr;

		ptr += sizeof(corsaro_report_single_ip_header_t);

        memset(&(track->netacq_saved), 0, sizeof(corsaro_report_savedtags_t));

		for (j = 0; j < iphdr->numtags; j++) {
			tag = (corsaro_report_msg_tag_t *)ptr;
            metricid = tag->tagid;

            METRIC_ALLOWED((metricid >> 32), allowed);
            if (allowed) {
			    update_knownip_metric(track, tag, iphdr->issrc,
				        maps, iphdr->ipaddr, iphdr->sourceasn);
            }
			ptr += sizeof(corsaro_report_msg_tag_t);
            tagsdone ++;
		}

        if (track->netacq_saved.next_saved != 0) {
            update_knownip_metric_saved(track, &(track->netacq_saved),
                    maps);
        }

		if (ptr - track->inbuf >= toalloc && i < msg->bodycount - 1) {
			corsaro_log(track->logger, "warning: IP tracker has walked past the end of a receive buffer!");
            corsaro_log(track->logger, "up to IP %d, total tags done: %u",
                    i, tagsdone);
			break;
		}
	}

	return 0;

trackerover:
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
    corsaro_report_iptracker_maps_t *maps;

    track = (corsaro_report_iptracker_t *)tdata;

    track->curr_maps = create_new_map_set();
    track->next_maps = create_new_map_set();

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
            track->haltsseen ++;
            if (track->haltsseen >= track->sourcethreads) {
                track->haltphase = 2;
            }
            pthread_mutex_unlock(&(track->mutex));
            continue;
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
            maps = track->curr_maps;
		} else if (sender_in_outstanding(track->outstanding, msg.sender)) {
            maps = track->next_maps;
		} else {
            maps = track->curr_maps;
		}


        if (process_iptracker_update_message(track, &msg, maps) < 0) {
            pthread_mutex_lock(&(track->mutex));
            track->haltphase = 2;
            pthread_mutex_unlock(&(track->mutex));
            break;
        }
    }

trackerover:
    /* Thread is ending, tidy up everything */
    free_map_set(track->curr_maps);
    free_map_set(track->next_maps);
    pthread_exit(NULL);
}






// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

