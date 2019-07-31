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

#include "libcorsaro.h"
#include "libcorsaro_plugin.h"
#include "libcorsaro_common.h"
#include "libcorsaro_avro.h"
#include "corsaro_report.h"
#include "utils.h"
#include "report_internal.h"

/** Broad overview of this whole plugin, since it is a *bit* complicated.
 *
 *  Our goal is to count the number of packets, bytes, source IPs and
 *  dest IPs observed per minute for each supported metric.
 *
 *  The IP counting is the challenging part, as we need to keep track of
 *  which IPs we've seen already so as not to count them twice, but we also
 *  need to account for the possibility that an IP can appear on multiple
 *  processing threads.
 *  Also, on the telescope we can end up seeing a LOT of unique IPs even in
 *  the space of a minute so we have to be careful about both memory usage and
 *  CPU time efficiency.
 *
 *  Here's how it all works out:
 *  We start with N packet processing threads, as with any other plugin.
 *  We use parallel libtrace to funnel packets to each thread using our
 *  standard hashing approach.
 *
 *  We also create a set of IP tracker threads (4 by default). Each of
 *  the IP tracker threads has a queue associated with it and the queues
 *  are available to the packet processing threads.
 *
 *  For each packet received by a packet processing thread, we...
 *    - grab the source IP address
 *    - map that IP address to one of the IP tracker threads using a
 *      consistent deterministic function.
 *    - update an internal map (keyed by the IP address) that keeps track
 *      of each tag observed for that address and increment the number of
 *      packets and bytes seen for each IP + tag combination that applies
 *      to this packet. There is one map per tracker thread.
 *    - repeat for the destination address, but do NOT increment packets
 *      or bytes for each metric (otherwise we count the packet twice).
 *    - when we have either a decent number of IP addresses in a map, or
 *      a single IP address accumulates a large number of tags, create a
 *      message to send to the corresponding IP tracker containing all of
 *      the IPs, their tags and the packet/byte counts for each tag. Send
 *      the message and reset the map for that tracker thread.
 *
 *  At the end of the interval, our packet processing thread pushes on an
 *  "interval" message to each IP tracker thread to signal that it has sent
 *  all of the packets for that interval.
 *
 *  At the same time, an IP tracker thread continuously reads messages from
 *  its queue. Update messages are used to update the thread's internal
 *  record of all observed IPs, the metrics that apply to each IP and the
 *  byte, IP and packet tallies for each metric. When an interval message
 *  has been received from all processing threads, the final tally for the
 *  tracker thread is confirmed and the "last" interval timestamp is updated
 *  to signify that the tally is complete.
 *
 *  Finally, the merge thread waits for an interval end trigger from the
 *  processing loop. Once received, it will poll until all of the tracker
 *  threads have signalled that their tally for that interval is complete.
 *  As tallies become available, the merge thread simply adds them together
 *  since there should be no tallies containing overlapping IPs (because of
 *  the hash of IP address to IP tracker thread). Once all tallies have been
 *  received, the combined tally is turned into Avro records and written to
 *  the results file.
 */



/** The magic number for this plugin - "REPT" */
#define CORSARO_REPORT_MAGIC 0x52455054

/** The name for this plugin */
#define PLUGIN_NAME "report"

/** Common plugin information and function callbacks */
static corsaro_plugin_t corsaro_report_plugin = {
    PLUGIN_NAME,
    CORSARO_PLUGIN_ID_REPORT,
    CORSARO_REPORT_MAGIC,
    CORSARO_PLUGIN_GENERATE_BASE_PTRS(corsaro_report),
    CORSARO_PLUGIN_GENERATE_TRACE_PTRS(corsaro_report),
    CORSARO_PLUGIN_GENERATE_MERGE_PTRS(corsaro_report),
    CORSARO_PLUGIN_GENERATE_TAIL
};

/** Allows external access to the report plugin definition and callbacks */
corsaro_plugin_t *corsaro_report_alloc(void) {
    return &(corsaro_report_plugin);
}

/** Parses the YAML configuration specific to the report plugin
 *
 *  @param p        A pointer to an instance of the report plugin.
 *  @param doc      A reference to the YAML document being parsed.
 *  @param options  A reference to the report plugin config section from the
 *                  YAML document.
 *  @return 0 if the report plugin config was parsed without problems, -1 if
 *            an error occurred.
 */
int corsaro_report_parse_config(corsaro_plugin_t *p, yaml_document_t *doc,
        yaml_node_t *options) {

    corsaro_report_config_t *conf;
    yaml_node_t *key, *value;
    yaml_node_pair_t *pair;

    conf = (corsaro_report_config_t *)malloc(sizeof(corsaro_report_config_t));
    if (conf == NULL) {
        corsaro_log(p->logger,
                "unable to allocate memory to store report plugin config.");
        return -1;
    }

    CORSARO_INIT_PLUGIN_PROC_OPTS(conf->basic);
    conf->outlabel = NULL;
    conf->outformat = CORSARO_OUTPUT_AVRO;
    conf->tracker_count = 4;
    conf->query_tagger_labels = 1;
    conf->internalhwm = 30;

    if (options->type != YAML_MAPPING_NODE) {
        corsaro_log(p->logger,
                "report plugin config should be a map.");
        free(conf);
        return -1;
    }

    for (pair = options->data.mapping.pairs.start;
            pair < options->data.mapping.pairs.top; pair ++) {

        char *val;
        key = yaml_document_get_node(doc, pair->key);
        value = yaml_document_get_node(doc, pair->value);
        val = (char *)value->data.scalar.value;

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value,
                    "output_row_label") == 0) {
            if (conf->outlabel) {
                corsaro_log(p->logger,
                        "duplicate definition of 'output_row_label' in report config -- using latter.");
                free(conf->outlabel);
            }
            conf->outlabel = strdup(val);
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                    && strcmp((char *)key->data.scalar.value,
                    "iptracker_threads") == 0) {

            conf->tracker_count = strtol((char *)value->data.scalar.value,
                    NULL, 0);
            if (conf->tracker_count < 1) {
                conf->tracker_count = 1;
            }
            if (conf->tracker_count > CORSARO_REPORT_MAX_IPTRACKERS) {
                corsaro_log(p->logger, "report plugin: iptracker thread count is currently capped at %d", CORSARO_REPORT_MAX_IPTRACKERS);
                conf->tracker_count = CORSARO_REPORT_MAX_IPTRACKERS;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                    && strcmp((char *)key->data.scalar.value,
                    "internalhwm") == 0) {
            uint64_t optval;

            optval = strtoul((char *)value->data.scalar.value, NULL, 0);
            if (optval > 65535) {
                conf->internalhwm = 0;
            } else {
                conf->internalhwm = optval;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                    && strcmp((char *)key->data.scalar.value,
                    "querytaggerlabels") == 0) {

            if (parse_onoff_option(p->logger, (char *)value->data.scalar.value,
                    &(conf->query_tagger_labels), "query_tagger_labels") < 0) {
                corsaro_log(p->logger, "setting query_tagger_labels to disabled");
                conf->query_tagger_labels = 0;
            }
        }

        if (key->type == YAML_SCALAR_NODE && value->type == YAML_SCALAR_NODE
                && strcmp((char *)key->data.scalar.value,
                    "output_format") == 0) {
           if (strcmp((char *)value->data.scalar.value, "avro") == 0) {
                conf->outformat = CORSARO_OUTPUT_AVRO;
           } else if (strcmp((char *)value->data.scalar.value,
                    "libtimeseries") == 0) {
                conf->outformat = CORSARO_OUTPUT_LIBTIMESERIES;
           } else {
                corsaro_log(p->logger, "output format '%s' is not supported by the report plugin.",
                        (char *)value->data.scalar.value);
                corsaro_log(p->logger, "falling back to avro output.");
                conf->outformat = CORSARO_OUTPUT_AVRO;
           }
        }
    }

    p->config = conf;

    return 0;
}

/** Complete configuration for the report plugin and assign default values
 *  to any unconfigured options.
 *
 *  This function also initialises and starts the IP tracker threads, so that
 *  they are up and running as soon as we start processing packets.
 *
 *  @param p        A reference to the running instance of the report plugin
 *  @param stdopts  The set of global-level options that are common to every
 *                  plugin
 *  @param zmq_ctxt A ZeroMQ contect for the entire process that can be
 *                  used to create new messaging sockets
 *  @return 0 if successful, -1 if an error occurred.
 */
int corsaro_report_finalise_config(corsaro_plugin_t *p,
        corsaro_plugin_proc_options_t *stdopts, void *zmq_ctxt) {

    corsaro_report_config_t *conf;
    int i, j, ret = 0, rto=10, hwm=30;
    char sockname[40];

    conf = (corsaro_report_config_t *)(p->config);
    conf->basic.template = stdopts->template;
    conf->basic.monitorid = stdopts->monitorid;
    conf->basic.procthreads = stdopts->procthreads;
    conf->basic.libtsascii = stdopts->libtsascii;
    conf->basic.libtskafka = stdopts->libtskafka;
    conf->basic.libtsdbats = stdopts->libtsdbats;

    if (conf->outlabel == NULL) {
        conf->outlabel = strdup("unlabeled");
    }

    corsaro_log(p->logger,
            "report plugin: labeling all output rows with '%s'",
            conf->outlabel);

    if (conf->outformat == CORSARO_OUTPUT_AVRO) {
        corsaro_log(p->logger,
                "report plugin: writing output to avro files");
    } else if (conf->outformat == CORSARO_OUTPUT_LIBTIMESERIES) {
        corsaro_log(p->logger,
                "report plugin: writing output using libtimeseries");
        display_libts_ascii_options(p->logger, conf->basic.libtsascii,
                "report plugin");
        display_libts_kafka_options(p->logger, conf->basic.libtskafka,
                "report plugin");
        display_libts_dbats_options(p->logger, conf->basic.libtsdbats,
                "report plugin");
    } else {
        corsaro_log(p->logger,
                "report plugin: invalid value for output format (?)");
    }

    corsaro_log(p->logger,
            "report plugin: starting %d IP tracker threads",
            conf->tracker_count);
    if (conf->query_tagger_labels == 0) {
        corsaro_log(p->logger,
                "report plugin: NOT querying the tagger for FQ geo-location labels");
    }

    hwm = conf->internalhwm;
    corsaro_log(p->logger, "report plugin: using internal queue HWM of %u",
            conf->internalhwm);

    /* Create and start the IP tracker threads.
     *
     * We include the tracker thread references in the config, because
     * that is easily available in both the packet processing and
     * merging threads.
     */
    conf->iptrackers = (corsaro_report_iptracker_t *)calloc(
            conf->tracker_count, sizeof(corsaro_report_iptracker_t));
    conf->tracker_queues = calloc(conf->tracker_count * conf->basic.procthreads,
		sizeof(void *));

    for (i = 0; i < conf->tracker_count; i++) {

        pthread_mutex_init(&(conf->iptrackers[i].mutex), NULL);
        conf->iptrackers[i].lastresultts = 0;

        conf->iptrackers[i].knownips = NULL;
        conf->iptrackers[i].knownips_next = NULL;
        conf->iptrackers[i].lastresult = NULL;
        conf->iptrackers[i].currentresult = NULL;
        conf->iptrackers[i].nextresult = NULL;
        conf->iptrackers[i].logger = p->logger;
        conf->iptrackers[i].sourcethreads = stdopts->procthreads;
        conf->iptrackers[i].haltphase = 0;
        conf->iptrackers[i].outstanding = libtrace_list_init(
               sizeof(corsaro_report_out_interval_t));

        conf->iptrackers[i].sourcetrack = calloc(stdopts->procthreads,
                sizeof(corsaro_report_iptracker_source_t));

        snprintf(sockname, 40, "inproc://reporttracker%d", i);

        conf->iptrackers[i].incoming = zmq_socket(zmq_ctxt, ZMQ_PULL);
        if (zmq_setsockopt(conf->iptrackers[i].incoming, ZMQ_RCVTIMEO, &rto,
                    sizeof(rto)) < 0) {
            corsaro_log(p->logger,
                    "error while configuring ip tracker %d pull socket: %s", i,
                    strerror(errno));
            ret = -1;
        }

        if (zmq_setsockopt(conf->iptrackers[i].incoming, ZMQ_RCVHWM, &hwm,
                    sizeof(hwm)) < 0) {
            corsaro_log(p->logger,
                    "error while configuring ip tracker %d pull socket: %s", i,
                    strerror(errno));
            ret = -1;
        }

        if (zmq_bind(conf->iptrackers[i].incoming, sockname) < 0) {
            corsaro_log(p->logger,
                    "error while binding ip tracker %d pull socket: %s", i,
                    strerror(errno));
            ret = -1;
        }

        /* Each processing thread needs a queue for it to send messages to
         * each of the IP tracking threads, so we need m * n queues (where
         * m = num proc threads and n = num tracker threads).
         *
         * Lay them out in such a way that the proc threads can easily
         * identify "their" queues.
         */
        for (j = 0; j < conf->basic.procthreads; j++) {
            int tq_id = i * conf->basic.procthreads + j;
            conf->tracker_queues[tq_id] = zmq_socket(zmq_ctxt, ZMQ_PUSH);
            if (zmq_setsockopt(conf->tracker_queues[tq_id], ZMQ_SNDHWM, &hwm,
                        sizeof(hwm)) < 0) {
                corsaro_log(p->logger,
                        "error while configuring ip tracker %d push socket: %s", tq_id,
                        strerror(errno));
                ret = -1;
            }

            if (zmq_connect(conf->tracker_queues[tq_id], sockname) < 0) {
                corsaro_log(p->logger,
                        "error while connecting ip tracker %d-%d push socket: %s",
                        i, j, strerror(errno));
                ret = -1;
            }
        }


        pthread_create(&(conf->iptrackers[i].tid), NULL,
                start_iptracker, &(conf->iptrackers[i]));
    }

    return ret;
}

/** Tidies up all memory allocated by this instance of the report plugin.
 *
 *  @param p    A reference to the running instance of the report plugin
 */
void corsaro_report_destroy_self(corsaro_plugin_t *p) {
    int i, j;
    if (p->config) {
        corsaro_report_config_t *conf;
        conf = (corsaro_report_config_t *)(p->config);
        if (conf->outlabel) {
            free(conf->outlabel);
        }

        /* Hopefully the tracker threads have joined by this point... */
        if (conf->iptrackers) {
            for (i = 0; i < conf->tracker_count; i++) {
                pthread_mutex_destroy(&(conf->iptrackers[i].mutex));

                zmq_close(conf->iptrackers[i].incoming);
                for (j = 0; j < conf->basic.procthreads; j++) {
                    zmq_close(conf->tracker_queues[
                            i * conf->basic.procthreads + j]);
                }
                free(conf->iptrackers[i].sourcetrack);
                libtrace_list_deinit(conf->iptrackers[i].outstanding);
            }
            free(conf->iptrackers);
            free(conf->tracker_queues);
        }

        free(p->config);
    }
    p->config = NULL;

}
/** Given a timestamp and processing thread ID, generate an appropriate
 *  Avro output filename using the pre-configured output file template.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param local        The packet processing thread state for this plugin.
 *  @param timestamp    The timestamp of the first interval covered by this
 *                      output file.
 *  @param threadid     The processing thread that is creating this file. Set
 *                      to -1 if the merge thread is calling this function.
 *  @return A malloc'd string containing the filename that should be used
 *          when creating an output file. Returns NULL if an error occurs.
 *
 *  @note It is the caller's responsibility to free the returned string when
 *        they are finished with opening the file.
 */
char *corsaro_report_derive_output_name(corsaro_plugin_t *p,
        void *local, uint32_t timestamp, int threadid) {

    corsaro_report_config_t *conf;
    char *outname = NULL;

    conf = (corsaro_report_config_t *)(p->config);

    outname = corsaro_generate_avro_file_name(conf->basic.template, p->name,
            conf->basic.monitorid, timestamp, threadid);
    if (outname == NULL) {
        corsaro_log(p->logger,
                "failed to generate suitable filename for report output");
        return NULL;
    }

    return outname;
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
