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

#include "config.h"
#include "corsarowdcap.h"
#include "libcorsaro_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <zmq.h>

#include "utils.h"

#define MERGE_FIELD(field)                      \
    if (from->field##_valid) {                  \
        to->field##_valid = 1;                  \
        to->field += from->field;               \
    }

static inline void merge_ltstats(libtrace_stat_t *to, libtrace_stat_t *from) {
    /* if a field is valid in 'from' it is then set to valid in 'to' */
    MERGE_FIELD(accepted);
    MERGE_FIELD(filtered);
    MERGE_FIELD(received);
    MERGE_FIELD(dropped);
    MERGE_FIELD(captured);
    MERGE_FIELD(missing);
    MERGE_FIELD(errors);
}

#define LOG_FIELD(field)                                        \
    fprintf(f, "thread:%d "STR(field)"_pkts:%"PRIi64"\n",       \
            threadid, s->field##_valid ? s->field : -1);

static void log_ltstats(FILE *f, libtrace_stat_t *s, int threadid) {
    LOG_FIELD(accepted);
    LOG_FIELD(filtered);
    LOG_FIELD(received);
    LOG_FIELD(dropped);
    LOG_FIELD(captured);
    LOG_FIELD(missing);
    LOG_FIELD(errors);
}

/** Determines which of the available packets in the interim files should
 *  be added to the merged output file next.
 *
 *  Merged output file order is chronological, so the packet with the
 *  lowest timestamp will always be chosen.
 *
 *  @param mergestate       The state for the merging thread.
 *  @param inpcount         The number of interim files that are being
 *                          combined to create the merged output.
 *  @param logger           A corsaro logger instance for writing error logs.
 *
 *  @return the index of the interim file reader that the next packet should
 *          be drawn from, or -1 if all readers have run out of packets.
 */
static int choose_next_merge_packet(corsaro_wdcap_merger_t *mergestate,
        int inpcount, corsaro_logger_t *logger) {

    int i, candind = -1;

    /* XXX naive method -- if performance is an issue, consider maintaining
     * a sorted list/map of packet timestamps instead which will reduce
     * the number of comparisons we do (on average)
     */

    for (i = 0; i < inpcount; i++) {
        if (mergestate->readers[i].status == CORSARO_WDCAP_INTERIM_EOF) {
            continue;
        }

        if (mergestate->readers[i].status == CORSARO_WDCAP_INTERIM_NOPACKET) {
            /* We've used the most recent packet for this reader, so read
             * the next one.
             */
            int ret = corsaro_read_next_packet(logger,
                    mergestate->readers[i].source,
                    mergestate->readers[i].nextp);
            if (ret <= 0) {
                /* No more packets in this interim file, flag it as done. */
                mergestate->readers[i].status = CORSARO_WDCAP_INTERIM_EOF;
                continue;
            }
            mergestate->readers[i].nextp_ts = trace_get_erf_timestamp(
                    mergestate->readers[i].nextp);
            mergestate->readers[i].status = CORSARO_WDCAP_INTERIM_PACKET;
        }

        if (candind == -1) {
            /* This is the first valid packet seen this round, so start
             * with this reader as having the "earliest" packet.
             */
            candind = i;
            continue;
        }
        if (mergestate->readers[i].nextp_ts <
                mergestate->readers[candind].nextp_ts) {
            /* This reader's next packet is earlier than our current
             * earliest packet.
             */
            candind = i;
        }
    }

    return candind;
}


/** Merges all interim files for a given interval into a single output file.
 *
 *  @param glob         The global state for this instance of corsarowdcap.
 *  @param mergestate   The state for the merging thread.
 *  @param interval     The state for the interval that is being merged.
 *
 *  @return -1 if an error occurs, 0 if merging is successful.
 */
static int write_merged_output(corsaro_wdcap_global_t *glob,
        corsaro_wdcap_merger_t *mergestate,
        corsaro_wdcap_interval_t *interval) {

    int candind, i, ret = 0;
    char *outname = NULL;
    int success = 0;
    uint64_t start_time;
    libtrace_stat_t overall_stats;

    if (glob->writestats) {
        memset(&overall_stats, 0, sizeof(overall_stats));
        /* time the merge process */
        start_time = epoch_msec();
    }

    /* Create read handlers for each of the interim files */
    for (i = 0; i < glob->threads; i++) {
        mergestate->readers[i].uri = corsaro_wdcap_derive_output_name(glob,
                interval->timestamp, i, 1, 0);
        mergestate->readers[i].source = corsaro_create_trace_reader(
                glob->logger, mergestate->readers[i].uri);
        if (mergestate->readers[i].source == NULL) {
            mergestate->readers[i].nextp = NULL;
            mergestate->readers[i].nextp_ts = (uint64_t)-1;
            mergestate->readers[i].status = CORSARO_WDCAP_INTERIM_EOF;
        } else {
            mergestate->readers[i].nextp = trace_create_packet();
            mergestate->readers[i].nextp_ts = (uint64_t)-1;
            mergestate->readers[i].status = CORSARO_WDCAP_INTERIM_NOPACKET;

            if (mergestate->readers[i].nextp == NULL) {
                ret = -1;
                goto fail;
            }
        }
    }

    /* Create the output file handle for the merged result */
    outname = corsaro_wdcap_derive_output_name(glob, interval->timestamp,
                                               -1, 1, 0);
    mergestate->writer = corsaro_create_trace_writer(glob->logger,
            outname, glob->compress_level, glob->compress_method);
    if (mergestate->writer == NULL) {
        ret = -1;
        goto fail;
    }


    /* Look at the next available packet from each reader, choose the
     * one with the earliest timestamp, write it to the output file.
     */
    do {
        candind = choose_next_merge_packet(mergestate, glob->threads,
                glob->logger);
        if (candind == -1) {
            /* No more packets available for merging in any of the
             * interim files. */
            break;
        }
        if (corsaro_write_packet(glob->logger, mergestate->writer,
                mergestate->readers[candind].nextp) < 0) {
            ret = -1;
            goto fail;
        }
        /* Setting this will tell the reader that it needs to read the next
         * packet from the interim trace file. */
        mergestate->readers[candind].status = CORSARO_WDCAP_INTERIM_NOPACKET;
    } while (candind != -1);

    success = 1;

fail:
    if (mergestate->writer) {
        corsaro_destroy_trace_writer(mergestate->writer);
        mergestate->writer = NULL;
    }

    if (glob->writestats) {
        char *statfilename;
        FILE *f;

        statfilename =
            corsaro_wdcap_derive_output_name(glob, interval->timestamp,
                                             -1, 0, 2);
        if ((f = fopen(statfilename, "w")) == NULL) {
            corsaro_log(glob->logger, "error while creating stats file '%s'",
                        statfilename);
        } else {
            fprintf(f, "time:%"PRIu32"\n", interval->timestamp);
            /* per-thread stats and update overall stats */
            for (i=0; i < glob->threads; i++) {
                log_ltstats(f, &interval->thread_stats[i],
                            interval->thread_ids[i]);
                merge_ltstats(&overall_stats, &interval->thread_stats[i]);
            }
            /* overall stats */
            log_ltstats(f, &overall_stats, -1);

            /* output merge duration */
            fprintf(f, "merge_duration_msec:%"PRIu64"\n",
                     epoch_msec() - start_time);
            fclose(f);
        }
    }

    if (success) {
        /* All packets have been written to the merged file, now create a
         * special ".done" file so that our archiving scripts can tell that
         * the file is complete. */
        char *donefilename;
        FILE *f;

        donefilename = corsaro_wdcap_derive_output_name(glob,
                    interval->timestamp, -1, 0, 1);
        f = fopen(donefilename, "w");
        /* File can be empty, just has to exist */
        fclose(f);
    }

    /* Clean up all of the reader handlers */
    for (i = 0; i < glob->threads; i++) {
        if (mergestate->readers[i].nextp) {
            trace_destroy_packet(mergestate->readers[i].nextp);
        }
        if (mergestate->readers[i].source) {
            char *tok, *uri;
            corsaro_destroy_trace_reader(mergestate->readers[i].source);

            /* Delete the interim file */
            uri = mergestate->readers[i].uri;

            tok = strchr(uri, ':');
            if (tok == NULL) {
                tok = uri;
            } else {
                tok ++;
            }
            remove(tok);
        }
        free(mergestate->readers[i].uri);
    }

    if (outname) {
        free(outname);
    }

    corsaro_log(glob->logger, "done merging output files for %"PRIu32,
                interval->timestamp);

    return ret;
}

static int merge_finished_interval(corsaro_wdcap_global_t *glob,
    corsaro_wdcap_merger_t *mergestate, uint8_t threadid,
    uint32_t timestamp, libtrace_stat_t *lt_stats) {

    corsaro_wdcap_interval_t *fin = mergestate->waiting;
    corsaro_wdcap_interval_t *prev = NULL;

    /* Find this interval in our list of incomplete intervals. Ideally,
     * there should only be at most one entry in this list at any given time.
     */
    while (fin != NULL) {
        if (fin->timestamp == timestamp) {
            break;
        }
        prev = fin;
        fin = fin->next;
    }

    if (fin == NULL) {
        /* First time we've seen this interval; add it to the list */
        fin = (corsaro_wdcap_interval_t *)malloc(
                sizeof(corsaro_wdcap_interval_t));
        fin->timestamp = timestamp;
        fin->threads_done = 1;
        fin->thread_ids = malloc(glob->threads);
        fin->thread_stats = malloc(sizeof(libtrace_stat_t) * glob->threads);
        fin->thread_ids[0] = threadid;
        memcpy(&fin->thread_stats[0], lt_stats, sizeof(libtrace_stat_t));
        fin->next = NULL;

        if (prev) {
            prev->next = fin;
        } else {
            mergestate->waiting = fin;
        }
    } else {
        /* Update "finished thread" information */
        fin->thread_ids[fin->threads_done] = threadid;
        memcpy(&fin->thread_stats[fin->threads_done], lt_stats,
               sizeof(libtrace_stat_t));
        /* XXX we assume that each processing thread will only send us ONE
         * interval over message per interval...
         */
        fin->threads_done ++;
    }

    if (fin->threads_done == glob->threads) {
        int ret = 0;
        if (fin != mergestate->waiting) {
            corsaro_log(glob->logger, "Warning: corsarowdcap has completed an interval out of order (missing %u, got %u)",
                        mergestate->waiting->timestamp, timestamp);
        }
        corsaro_log(glob->logger,
                "merging thread %u has started merging interim files for %u",
                mergestate->thread_num, fin->timestamp);
        if (write_merged_output(glob, mergestate, fin) < 0) {
            corsaro_log(glob->logger, "Failed to merge interim output files for interval %u", timestamp);
            ret = -1;
        } else {
            ret = 1;
        }
        mergestate->waiting = fin->next;
        free(fin->thread_ids);
        free(fin->thread_stats);
        free(fin);
        return ret;
    }

    return 0;

}

/** Main loop for the corsarowdcap merging thread.
 *
 *  @param data     The global state for this corsarowdcap instance.
 *
 *  @return NULL once the thread is halted.
 */
void *start_merging_thread(void *data) {
    corsaro_wdcap_merger_t *mergestate = (corsaro_wdcap_merger_t *)data;
    corsaro_wdcap_global_t *glob = mergestate->glob;
    corsaro_wdcap_message_t msg;
    int badmessages = 0;
    uint8_t subval;

	mergestate->zmq_subsock = zmq_socket(glob->zmq_ctxt, ZMQ_SUB);

    subval = 255;
    if (zmq_setsockopt(mergestate->zmq_subsock, ZMQ_SUBSCRIBE, &subval,
            sizeof(subval)) < 0) {
        corsaro_log(glob->logger,
                "merge thread %u failed to sub to main thread messages: %s",
                mergestate->thread_num, strerror(errno));
        goto endmerge;
    }

    subval = mergestate->thread_num;
    if (zmq_setsockopt(mergestate->zmq_subsock, ZMQ_SUBSCRIBE, &subval,
            sizeof(subval)) < 0) {
        corsaro_log(glob->logger,
                "merge thread %u failed to sub to specific thread messages: %s",
                mergestate->thread_num, strerror(errno));
        goto endmerge;
    }

    if (zmq_connect(mergestate->zmq_subsock, CORSARO_WDCAP_INTERNAL_QUEUE_FRONT)
            < 0) {
        corsaro_log(glob->logger,
                "error binding sub socket for wdcap merging thread %u: %s",
                mergestate->thread_num, strerror(errno));
        goto endmerge;
    }

    while (1) {
        /* Wait for a message on our zeromq socket */
        if (zmq_recv(mergestate->zmq_subsock, &msg, sizeof(msg), 0) < 0) {
            corsaro_log(glob->logger,
                "error receiving message on wdcap merge socket: %s",
                strerror(errno));
            break;
        }

        if (msg.type == CORSARO_WDCAP_MSG_STOP) {
            /* Main thread has told us to halt */
            break;
        } else if (msg.type == CORSARO_WDCAP_MSG_INTERVAL_DONE) {
            /* An interval is complete, see if we are ready to do a merge. */

            /* Close the file descriptor that was used to write the interim
             * file -- we do this here to avoid blocking in the processing
             * thread while we wait for any remaining async I/O to complete.
             * We can afford to wait here, but we can't in the processing
             * threads.
             */
            if (msg.src_fd != -1) {
                close(msg.src_fd);
            }
            merge_finished_interval(glob, mergestate, msg.threadid,
                                    msg.timestamp, &msg.lt_stats);
        } else {
            corsaro_log(glob->logger,
                    "received unexpected message (type %u) in merging thread %u.",
                    msg.type, mergestate->thread_num);
            badmessages ++;
            if (badmessages >= 100) {
                corsaro_log(glob->logger,
                        "too many bad messages in merging thread %u-- exiting.",
                        mergestate->thread_num);
                break;
            }
        }
    }

endmerge:
    /* Tidy up any remaining local thread state */
    while (mergestate->waiting) {
        corsaro_wdcap_interval_t *fin = mergestate->waiting;
        mergestate->waiting = fin->next;
        free(fin->thread_ids);
        free(fin->thread_stats);
        free(fin);
    }

    zmq_close(mergestate->zmq_subsock);
    free(mergestate->readers);
    pthread_exit(NULL);
}



// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
