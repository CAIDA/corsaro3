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

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <yaml.h>
#include <libipmeta.h>
#include <libtrace/message_queue.h>
#include <errno.h>
#include <math.h>

#ifdef __linux__
#include <sys/epoll.h>
#else
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#endif

#include <uthash.h>
#include "khash.h"
#include "libcorsaro3.h"
#include "libcorsaro3_memhandler.h"
#include "libcorsaro3_plugin.h"
#include "libcorsaro3_avro.h"
#include "corsaro_report.h"
#include "utils.h"

#define CORSARO_REPORT_MAGIC 0x52455054
#define PLUGIN_NAME "report"

#define METRIC_MAXMIND_2CHAR_MAX (65536)
#define METRIC_PORT_MAX (65536)
#define METRIC_ICMP_MAX (256)
#define METRIC_IPPROTOS_MAX (256)

static corsaro_plugin_t corsaro_report_plugin = {
    PLUGIN_NAME,
    CORSARO_PLUGIN_ID_REPORT,
    CORSARO_REPORT_MAGIC,
    CORSARO_PLUGIN_GENERATE_BASE_PTRS(corsaro_report),
    CORSARO_PLUGIN_GENERATE_TRACE_PTRS(corsaro_report),
    CORSARO_PLUGIN_GENERATE_MERGE_PTRS(corsaro_report),
    CORSARO_PLUGIN_GENERATE_TAIL
};

typedef enum {
    CORSARO_METRIC_CLASS_COMBINED,
    CORSARO_METRIC_CLASS_MAXMIND_CONTINENT,
    CORSARO_METRIC_CLASS_MAXMIND_COUNTRY,
    CORSARO_METRIC_CLASS_NETACQ_CONTINENT,
    CORSARO_METRIC_CLASS_NETACQ_COUNTRY,
    CORSARO_METRIC_CLASS_PREFIX_ASN,
    CORSARO_METRIC_CLASS_TCP_SOURCE_PORT,
    CORSARO_METRIC_CLASS_TCP_DEST_PORT,
    CORSARO_METRIC_CLASS_UDP_SOURCE_PORT,
    CORSARO_METRIC_CLASS_UDP_DEST_PORT,
    CORSARO_METRIC_CLASS_IP_PROTOCOL,
    CORSARO_METRIC_CLASS_ICMP_CODE,
    CORSARO_METRIC_CLASS_ICMP_TYPE,
} corsaro_report_metric_class_t;

enum {
    CORSARO_IP_MESSAGE_UPDATE,
    CORSARO_IP_MESSAGE_HALT,
    CORSARO_IP_MESSAGE_INTERVAL
};

KHASH_MAP_INIT_INT64(mset, uint8_t);

typedef struct corsaro_standalone_metric {
    uint64_t metricid;
    uint8_t metval;
} PACKED corsaro_standalone_metric_t;

#define METRIC_ARRAY_SIZE 20

typedef struct corsaro_ip_hash {

    UT_hash_handle hh;
    uint32_t ipaddr;
    uint8_t issrc;
    corsaro_memsource_t *memsrc;
    corsaro_standalone_metric_t firstmetrics[METRIC_ARRAY_SIZE];
    uint32_t metriccount;
    kh_mset_t *metricsseen;
} PACKED corsaro_ip_hash_t;

typedef struct corsaro_metric_ip_hash_t {
    UT_hash_handle hh;
    uint64_t metricid;
    uint32_t srcips;
    uint32_t destips;
    uint32_t packets;
    uint64_t bytes;
    corsaro_memsource_t *memsrc;
} PACKED corsaro_metric_ip_hash_t;

typedef struct corsaro_report_outstanding_interval {
    uint32_t interval_ts;
    uint8_t reports_recvd[256];
    uint8_t reports_total;
} corsaro_report_out_interval_t;


typedef struct corsaro_report_iptracker {
    libtrace_message_queue_t incoming;

    uint32_t lastresultts;
    uint8_t sourcethreads;
    uint8_t haltphase;
    pthread_t tid;
    pthread_mutex_t mutex;
    corsaro_ip_hash_t *knownips;
    corsaro_ip_hash_t *knownips_next;
    corsaro_memhandler_t *ip_handler;
    corsaro_memhandler_t *metric_handler;

    corsaro_metric_ip_hash_t *lastresult;
    corsaro_metric_ip_hash_t *currentresult;
    corsaro_metric_ip_hash_t *nextresult;
    corsaro_logger_t *logger;
    libtrace_list_t *outstanding;

} corsaro_report_iptracker_t;

typedef struct corsaro_report_config {
    /** Standard options, e.g. template */
    corsaro_plugin_proc_options_t basic;
    /** Additional labelling to attach to every avro record -- useful for
     *  distinguishing between different inputs, for instance */
    char *outlabel;

    int tracker_count;
    corsaro_report_iptracker_t *iptrackers;
} corsaro_report_config_t;

typedef struct corsaro_report_tag {
    uint64_t metid;
    uint16_t size;
} corsaro_report_tag_t;

typedef struct corsaro_report_msg_body {
    uint32_t ipaddr;
    uint8_t issrc;
    uint8_t numtags;
    corsaro_report_tag_t tags[CORSARO_MAX_SUPPORTED_TAGS];
} corsaro_report_msg_body_t;

#define REPORT_BATCH_SIZE (500)

typedef struct corsaro_report_ip_message {
    uint8_t msgtype;
    uint8_t sender;
    uint32_t timestamp;
    uint16_t bodycount;
    corsaro_memsource_t *memsrc;
    corsaro_memhandler_t *handler;
    corsaro_report_msg_body_t *update;
} PACKED corsaro_report_ip_message_t;

typedef struct corsaro_report_state {

    corsaro_memhandler_t *msgbody_handler;
    corsaro_report_ip_message_t *nextmsg;
    int threadid;
    uint32_t current_interval;

    int queueblocks;
} corsaro_report_state_t;

typedef struct corsaro_report_merge_state {
    corsaro_avro_writer_t *writer;
    corsaro_memhandler_t *res_handler;
} corsaro_report_merge_state_t;

typedef struct corsaro_report_interim {
    corsaro_report_config_t *baseconf;
} corsaro_report_interim_t;


typedef struct corsaro_report_result {
    uint64_t metricid;
    uint64_t pkt_cnt;
    uint64_t bytes;
    uint32_t uniq_src_ips;
    uint32_t uniq_dst_ips;
    uint32_t attimestamp;

    char *label;
    char *metrictype;
    char *metricval;
    corsaro_memsource_t *memsrc;
    UT_hash_handle hh;
} PACKED corsaro_report_result_t;

static const char REPORT_RESULT_SCHEMA[] =
"{\"type\": \"record\",\
  \"namespace\": \"org.caida.corsaro\",\
  \"name\": \"report\",\
  \"doc\":  \"A Corsaro report result containing statistics describing the \
              range of traffic that was assigned to each supported tag by \
              corsarotrace.\",\
  \"fields\": [\
        {\"name\": \"bin_timestamp\", \"type\": \"long\"}, \
        {\"name\": \"source_label\", \"type\": \"string\"}, \
        {\"name\": \"metric_name\", \"type\": \"string\"}, \
        {\"name\": \"metric_value\", \"type\": \"string\"}, \
        {\"name\": \"src_ip_cnt\", \"type\": \"long\"}, \
        {\"name\": \"dest_ip_cnt\", \"type\": \"long\"}, \
        {\"name\": \"pkt_cnt\", \"type\": \"long\"}, \
        {\"name\": \"byte_cnt\", \"type\": \"long\"} \
        ]}";

corsaro_plugin_t *corsaro_report_alloc(void) {
    return &(corsaro_report_plugin);
}

static inline int report_result_to_avro(corsaro_logger_t *logger,
        avro_value_t *av, void *repres) {

    avro_value_t field;
    corsaro_report_result_t *res = (corsaro_report_result_t *)repres;

    CORSARO_AVRO_SET_FIELD(long, av, field, 0, "bin_timestamp", "report",
            res->attimestamp);
    CORSARO_AVRO_SET_FIELD(string, av, field, 1, "source_label", "report",
            res->label);
    CORSARO_AVRO_SET_FIELD(string, av, field, 2, "metric_name", "report",
            res->metrictype);
    CORSARO_AVRO_SET_FIELD(string, av, field, 3, "metric_value", "report",
            res->metricval);
    CORSARO_AVRO_SET_FIELD(long, av, field, 4, "src_ip_cnt", "report",
            res->uniq_src_ips);
    CORSARO_AVRO_SET_FIELD(long, av, field, 5, "dest_ip_cnt", "report",
            res->uniq_dst_ips);
    CORSARO_AVRO_SET_FIELD(long, av, field, 6, "pkt_cnt", "report",
            res->pkt_cnt);
    CORSARO_AVRO_SET_FIELD(long, av, field, 7, "byte_cnt", "report",
            res->bytes);
    return 0;
}

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
    }

    p->config = conf;

    return 0;
}

static corsaro_ip_hash_t *update_iphash(corsaro_report_iptracker_t *track,
        corsaro_ip_hash_t **knownips, uint32_t ipaddr) {

    corsaro_ip_hash_t *iphash;
    corsaro_memsource_t *memsrc;

    HASH_FIND(hh, *knownips, &(ipaddr), sizeof(ipaddr), iphash);
    if (!iphash) {
        iphash = (corsaro_ip_hash_t *)get_corsaro_memhandler_item(
                track->ip_handler, &memsrc);
        iphash->ipaddr = ipaddr;
        iphash->issrc = 0;
        iphash->memsrc = memsrc;
        memset(iphash->firstmetrics, 0, sizeof(corsaro_standalone_metric_t) *
                METRIC_ARRAY_SIZE);
        iphash->metriccount = 0;
        iphash->metricsseen = kh_init(mset);

        HASH_ADD_KEYPTR(hh, *knownips, &(iphash->ipaddr),
                sizeof(iphash->ipaddr), iphash);
    }
    return iphash;

}

static inline void update_metric_map(corsaro_ip_hash_t *iphash,
        uint64_t metricid, uint8_t issrc, corsaro_metric_ip_hash_t *m) {

    int khret;
    khiter_t khiter;
    uint8_t metval;

    khiter = kh_put(mset, iphash->metricsseen, metricid, &khret);
    if (khret == 1) {
        kh_value(iphash->metricsseen, khiter) = 0;
        iphash->metriccount ++;
    }

    metval = kh_value(iphash->metricsseen, khiter);
    if (issrc && !(metval & 0x01)) {
        kh_value(iphash->metricsseen, khiter) |= 0x01;
        m->srcips ++;
    } else if (!issrc && !(metval & 0x02)) {
        kh_value(iphash->metricsseen, khiter) |= 0x02;
        m->destips ++;
    }
}

static inline void update_metric_array(corsaro_ip_hash_t *iphash,
        uint64_t metricid, uint8_t issrc, corsaro_metric_ip_hash_t *m) {

    corsaro_standalone_metric_t *found = NULL;
    int khret;
    khiter_t khiter;
    int i;

    for (i = 0; i < iphash->metriccount; i++) {
        if (iphash->firstmetrics[i].metricid == metricid) {
            found = &(iphash->firstmetrics[i]);
            break;
        }
    }

    if (!found && iphash->metriccount == METRIC_ARRAY_SIZE) {
        /* convert to hash map */
        for (i = 0; i < iphash->metriccount; i++) {
            khiter = kh_put(mset, iphash->metricsseen,
                    iphash->firstmetrics[i].metricid, &khret);
            kh_value(iphash->metricsseen, khiter) =
                    iphash->firstmetrics[i].metval;
        }

        update_metric_map(iphash, metricid, issrc, m);
        return;
    }

    if (!found) {
        found = &(iphash->firstmetrics[iphash->metriccount]);
        found->metricid = metricid;
        found->metval = 0;
        iphash->metriccount ++;
    }

    if (issrc && !(found->metval & 0x01)) {
        found->metval |= 0x01;
        m->srcips ++;
    } else if (!issrc && !(found->metval & 0x02)) {
        found->metval |= 0x02;
        m->destips ++;
    }
}

static void update_knownip_metric(corsaro_report_iptracker_t *track,
        uint64_t metricid, corsaro_ip_hash_t *iphash, uint8_t issrc,
        uint16_t iplen, uint8_t *newip, corsaro_metric_ip_hash_t **metrictally) {

    corsaro_memsource_t *memsrc;
    corsaro_metric_ip_hash_t *m;
    if (issrc && !(iphash->issrc & 0x01)) {
        iphash->issrc |= 0x01;
        *newip = 1;
    } else if (!issrc && !(iphash->issrc & 0x02)) {
        iphash->issrc |= 0x02;
        *newip = 1;
    }

    HASH_FIND(hh, *metrictally, &metricid, sizeof(metricid), m);
    if (!m) {
        m = (corsaro_metric_ip_hash_t *)get_corsaro_memhandler_item(
                track->metric_handler, &memsrc);
        m->metricid = metricid;
        m->srcips = 0;
        m->destips = 0;
        m->memsrc = memsrc;
        m->packets = 0;
        m->bytes = 0;

        HASH_ADD_KEYPTR(hh, *metrictally, &(m->metricid), sizeof(m->metricid),
                m);
    }

    if (iplen > 0) {
        m->packets += 1;
        m->bytes += iplen;
    }

    if (iphash->metriccount <= METRIC_ARRAY_SIZE) {
        update_metric_array(iphash, metricid, issrc, m);
    } else {
        update_metric_map(iphash, metricid, issrc, m);
    }

}

static void free_metrichash(corsaro_report_iptracker_t *track,
        corsaro_metric_ip_hash_t **methash) {
    corsaro_metric_ip_hash_t *ipiter, *tmp;

    HASH_ITER(hh, *methash, ipiter, tmp) {
        HASH_DELETE(hh, *methash, ipiter);
        release_corsaro_memhandler_item(track->metric_handler, ipiter->memsrc);
    }
}

static void free_knownips(corsaro_report_iptracker_t *track,
        corsaro_ip_hash_t **knownips) {
    corsaro_ip_hash_t *ipiter, *tmp;

    HASH_ITER(hh, *knownips, ipiter, tmp) {
        kh_destroy(mset, ipiter->metricsseen);
        HASH_DELETE(hh, *knownips, ipiter);
        release_corsaro_memhandler_item(track->ip_handler, ipiter->memsrc);
    }
}

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

static void process_msg_body(corsaro_report_iptracker_t *track, uint8_t sender,
        corsaro_report_msg_body_t *body) {

    uint8_t newip = 0;
    int i;
    corsaro_ip_hash_t **knownip = NULL;
    corsaro_metric_ip_hash_t **knowniptally = NULL;
    corsaro_ip_hash_t *thisip = NULL;

    /* figure out if our sender has finished the interval already; if
     * so, we need to update the next interval not the current one.
     */
    if (libtrace_list_get_size(track->outstanding) == 0) {
        knownip = &track->knownips;
        knowniptally = &track->currentresult;
    } else if (sender_in_outstanding(track->outstanding, sender)) {
        knownip = &track->knownips_next;
        knowniptally = &track->nextresult;
    } else {
        knownip = &track->knownips;
        knowniptally = &track->currentresult;
    }

    for (i = 0; i < body->numtags; i++) {
        /* Combined should always be the first tag we see, so we'll always
         * know if this is a new IP before we do any "stable" metric
         * updates.
         */

        if (i == 0) {
            assert(body->tags[i].metid == 0);
        }

        if (!thisip) {
            thisip = update_iphash(track, knownip, body->ipaddr);
        }
        update_knownip_metric(track, body->tags[i].metid, thisip,
                body->issrc, body->tags[i].size, &newip, knowniptally);
    }

}

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
                toret = ts;
                break;
            } else {
                return 0;
            }
        }
        n = n->next;
    }

    if (toret > 0) {
        corsaro_report_out_interval_t popped;
        while (libtrace_list_pop_front(outl, (void *)((&popped))) > 0) {
            if (popped.interval_ts == toret) {
                break;
            }
        }
        return toret;
    }

    if (outl->tail) {
        o = (corsaro_report_out_interval_t *)(outl->tail->data);
        assert(o->interval_ts < ts);
    }

    memset(&(newentry.reports_recvd), 0, sizeof(newentry.reports_recvd));
    newentry.reports_recvd[sender] = 1;
    newentry.reports_total = 1;
    newentry.interval_ts = ts;
    libtrace_list_push_back(outl, (void *)(&newentry));
    return 0;

}

static void *start_iptracker(void *tdata) {
    corsaro_report_iptracker_t *track;
    corsaro_report_ip_message_t msg;
    int i;

    track = (corsaro_report_iptracker_t *)tdata;

    while (track->haltphase != 2) {
        if (libtrace_message_queue_try_get(&(track->incoming), &msg)
                == LIBTRACE_MQ_FAILED) {
            usleep(10);
            continue;
        }

        if (msg.msgtype == CORSARO_IP_MESSAGE_HALT) {
            pthread_mutex_lock(&(track->mutex));
            if (libtrace_list_get_size(track->outstanding) == 0) {
                corsaro_log(track->logger, "tracker thread has been halted");
                track->haltphase = 2;
            } else {
                track->haltphase = 1;
            }
            pthread_mutex_unlock(&(track->mutex));
            continue;
        }

        if (msg.msgtype == CORSARO_IP_MESSAGE_INTERVAL) {
            uint32_t complete;

            pthread_mutex_lock(&(track->mutex));
            if (msg.timestamp == 0) {
                pthread_mutex_unlock(&(track->mutex));
                continue;
            }

            if (msg.timestamp <= track->lastresultts) {
                pthread_mutex_unlock(&(track->mutex));
                continue;
            }

            complete = update_outstanding(track->outstanding, msg.timestamp,
                    track->sourcethreads, msg.sender);
            if (complete == 0) {
                pthread_mutex_unlock(&(track->mutex));
                continue;
            }

            pthread_mutex_unlock(&(track->mutex));
            corsaro_log(track->logger,
                    "%p tracker thread has started tally for %u IPs\n", track, HASH_CNT(hh, track->knownips));

            /* End of interval, tally up results and update lastresults */
            if (track->lastresult != NULL) {
                corsaro_log(track->logger,
                        "error, ended report interval before we had dealt with the results from the previous one!");
                assert(0);
            }

            pthread_mutex_lock(&(track->mutex));
            track->lastresult = track->currentresult;
            track->lastresultts = complete;
            corsaro_log(track->logger,
                    "%p tracker thread has finished tally for %u", track, track->lastresultts);
            if (track->haltphase == 1) {
                track->haltphase = 2;
            }
            pthread_mutex_unlock(&(track->mutex));

            free_knownips(track, &(track->knownips));

            track->knownips = track->knownips_next;
            track->currentresult = track->nextresult;
            track->knownips_next = NULL;
            track->nextresult = NULL;
            continue;

        }

        for (i = 0; i < msg.bodycount; i++) {
            process_msg_body(track, msg.sender, &(msg.update[i]));
        }
        release_corsaro_memhandler_item(msg.handler, msg.memsrc);


    }

    free_metrichash(track, &(track->currentresult));
    free_metrichash(track, &(track->nextresult));
    free_knownips(track, &(track->knownips));
    free_knownips(track, &(track->knownips_next));
    corsaro_log(track->logger, "exiting tracker thread...");
    pthread_exit(NULL);
}

int corsaro_report_finalise_config(corsaro_plugin_t *p,
        corsaro_plugin_proc_options_t *stdopts) {

    corsaro_report_config_t *conf;
    int i;

    conf = (corsaro_report_config_t *)(p->config);
    conf->basic.template = stdopts->template;
    conf->basic.monitorid = stdopts->monitorid;
    conf->basic.procthreads = stdopts->procthreads;

    if (conf->outlabel == NULL) {
        conf->outlabel = strdup("unlabeled");
    }

    corsaro_log(p->logger,
            "report plugin: labeling all output rows with '%s'",
            conf->outlabel);

    /* TODO add config option for this */
    conf->tracker_count = 4;

    corsaro_log(p->logger,
            "report plugin: starting %d IP tracker threads",
            conf->tracker_count);

    conf->iptrackers = (corsaro_report_iptracker_t *)calloc(
            conf->tracker_count, sizeof(corsaro_report_iptracker_t));
    for (i = 0; i < conf->tracker_count; i++) {
        libtrace_message_queue_init(&(conf->iptrackers[i].incoming),
                sizeof(corsaro_report_ip_message_t));
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

        conf->iptrackers[i].ip_handler = (corsaro_memhandler_t *)malloc(
                sizeof(corsaro_memhandler_t));
        init_corsaro_memhandler(p->logger, conf->iptrackers[i].ip_handler,
                sizeof(corsaro_ip_hash_t), 10000);
        conf->iptrackers[i].metric_handler = (corsaro_memhandler_t *)malloc(
                sizeof(corsaro_memhandler_t));
        init_corsaro_memhandler(p->logger, conf->iptrackers[i].metric_handler,
                sizeof(corsaro_metric_ip_hash_t), 10000);

        pthread_create(&(conf->iptrackers[i].tid), NULL,
                start_iptracker, &(conf->iptrackers[i]));
    }

    return 0;
}

void corsaro_report_destroy_self(corsaro_plugin_t *p) {
    int i;
    if (p->config) {
        corsaro_report_config_t *conf;
        conf = (corsaro_report_config_t *)(p->config);
        if (conf->outlabel) {
            free(conf->outlabel);
        }
        if (conf->iptrackers) {
            for (i = 0; i < conf->tracker_count; i++) {
                destroy_corsaro_memhandler(conf->iptrackers[i].metric_handler);
                destroy_corsaro_memhandler(conf->iptrackers[i].ip_handler);
                pthread_mutex_destroy(&(conf->iptrackers[i].mutex));
                libtrace_message_queue_destroy(&(conf->iptrackers[i].incoming));
                libtrace_list_deinit(conf->iptrackers[i].outstanding);
            }
            free(conf->iptrackers);
        }

        free(p->config);
    }
    p->config = NULL;

}

void *corsaro_report_init_processing(corsaro_plugin_t *p, int threadid) {

    corsaro_report_state_t *state;
    corsaro_report_config_t *conf;
    corsaro_memsource_t *memsrc;
    int i;

    conf = (corsaro_report_config_t *)(p->config);
    state = (corsaro_report_state_t *)malloc(sizeof(corsaro_report_state_t));

    state->current_interval = 0;
    state->threadid = threadid;
    state->queueblocks = 0;

    state->msgbody_handler = (corsaro_memhandler_t *)malloc(
            sizeof(corsaro_memhandler_t));
    init_corsaro_memhandler(p->logger, state->msgbody_handler,
            sizeof(corsaro_report_msg_body_t) * REPORT_BATCH_SIZE,
            10000);

    state->nextmsg = (corsaro_report_ip_message_t *)calloc(
            conf->tracker_count, sizeof(corsaro_report_ip_message_t));

    for (i = 0; i < conf->tracker_count; i++) {
        state->nextmsg[i].update = (corsaro_report_msg_body_t *)
            get_corsaro_memhandler_item(state->msgbody_handler, &memsrc);
        state->nextmsg[i].handler = state->msgbody_handler;
        state->nextmsg[i].memsrc = memsrc;
        state->nextmsg[i].sender = state->threadid;
    }

    return state;
}

int corsaro_report_halt_processing(corsaro_plugin_t *p, void *local) {

    corsaro_report_state_t *state;
    corsaro_report_ip_message_t msg;
    corsaro_report_config_t *conf;
    corsaro_memsource_t *memsrc;
    int i;

    conf = (corsaro_report_config_t *)(p->config);
    state = (corsaro_report_state_t *)local;

    if (state == NULL) {
        return 0;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msgtype = CORSARO_IP_MESSAGE_HALT;
    msg.sender = state->threadid;

    for (i = 0; i < conf->tracker_count; i++) {
        if (state->nextmsg[i].bodycount > 0) {
            libtrace_message_queue_put(&(conf->iptrackers[i].incoming),
                    (void *)(&(state->nextmsg[i])));

            state->nextmsg[i].bodycount = 0;
            state->nextmsg[i].update = (corsaro_report_msg_body_t *)
                get_corsaro_memhandler_item(state->msgbody_handler, &memsrc);
            state->nextmsg[i].handler = state->msgbody_handler;
            state->nextmsg[i].memsrc = memsrc;
        }
        libtrace_message_queue_put(&(conf->iptrackers[i].incoming), (void *)(&msg));
    }

    for (i = 0; i < conf->tracker_count; i++) {
        pthread_join(conf->iptrackers[i].tid, NULL);
    }

    destroy_corsaro_memhandler(state->msgbody_handler);
    free(state);

    return 0;
}

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

int corsaro_report_start_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_start) {

    corsaro_report_state_t *state;

    state = (corsaro_report_state_t *)local;
    if (state != NULL) {
        state->current_interval = int_start->time;
    }
    return 0;
}

void *corsaro_report_end_interval(corsaro_plugin_t *p, void *local,
        corsaro_interval_t *int_end) {

    corsaro_report_config_t *conf;
    corsaro_report_state_t *state;
    corsaro_report_interim_t *interim;
    corsaro_report_ip_message_t msg;
    corsaro_memsource_t *memsrc;
    int i;

    conf = (corsaro_report_config_t *)(p->config);
    state = (corsaro_report_state_t *)local;

    if (state == NULL) {
        corsaro_log(p->logger,
                "corsaro_report_end_interval: report thread-local state is NULL!");
        return NULL;
    }

    interim = (corsaro_report_interim_t *)malloc(
            sizeof(corsaro_report_interim_t));
    interim->baseconf = conf;

    memset(&msg, 0, sizeof(msg));
    msg.msgtype = CORSARO_IP_MESSAGE_INTERVAL;
    msg.timestamp = state->current_interval;
    msg.sender = state->threadid;

    for (i = 0; i < conf->tracker_count; i++) {
        if (state->nextmsg[i].bodycount > 0) {
            libtrace_message_queue_put(&(conf->iptrackers[i].incoming),
                    (void *)(&(state->nextmsg[i])));
            state->nextmsg[i].bodycount = 0;
            state->nextmsg[i].update = (corsaro_report_msg_body_t *)
                get_corsaro_memhandler_item(state->msgbody_handler, &memsrc);
            state->nextmsg[i].handler = state->msgbody_handler;
            state->nextmsg[i].memsrc = memsrc;
        }
        libtrace_message_queue_put(&(conf->iptrackers[i].incoming), (void *)(&msg));
    }

    state->queueblocks = 0;

    return (void *)interim;
}

static inline int extract_addresses(libtrace_packet_t *packet,
        uint32_t *srcaddr, uint32_t *dstaddr, uint16_t *iplen) {

    libtrace_ip_t *ip;
    void *l3;
    uint16_t ethertype;
    uint32_t rem;

    l3 = trace_get_layer3(packet, &ethertype, &rem);

    if (l3 == NULL || rem == 0) {
        return -1;
    }

    if (ethertype != TRACE_ETHERTYPE_IP) {
        return -1;
    }

    if (rem < sizeof(libtrace_ip_t)) {
        return -1;
    }
    ip = (libtrace_ip_t *)l3;

    *srcaddr = ip->ip_src.s_addr;
    *dstaddr = ip->ip_dst.s_addr;
    *iplen = ntohs(ip->ip_len);
    return 0;
}

static inline int basic_tagged(corsaro_packet_tags_t *tags) {
    if (tags->providers_used & 0x01) {
        return 1;
    }
    return 0;
}

static inline int maxmind_tagged(corsaro_packet_tags_t *tags) {
    if (tags->providers_used & (1 << IPMETA_PROVIDER_MAXMIND)) {
        return 1;
    }
    return 0;
}

static inline int netacq_tagged(corsaro_packet_tags_t *tags) {
    if (tags->providers_used & (1 << IPMETA_PROVIDER_NETACQ_EDGE)) {
        return 1;
    }
    return 0;
}

static inline int pfx2as_tagged(corsaro_packet_tags_t *tags) {
    if (tags->providers_used & (1 << IPMETA_PROVIDER_PFX2AS)) {
        return 1;
    }
    return 0;
}

static char *metclasstostr(corsaro_report_metric_class_t class) {

    switch(class) {
        case CORSARO_METRIC_CLASS_COMBINED:
            return "combined";
        case CORSARO_METRIC_CLASS_IP_PROTOCOL:
            return "IP protocol";
        case CORSARO_METRIC_CLASS_ICMP_TYPE:
            return "ICMP type";
        case CORSARO_METRIC_CLASS_ICMP_CODE:
            return "ICMP code";
        case CORSARO_METRIC_CLASS_TCP_SOURCE_PORT:
            return "TCP source port";
        case CORSARO_METRIC_CLASS_TCP_DEST_PORT:
            return "TCP dest port";
        case CORSARO_METRIC_CLASS_UDP_SOURCE_PORT:
            return "UDP source port";
        case CORSARO_METRIC_CLASS_UDP_DEST_PORT:
            return "UDP dest port";
        case CORSARO_METRIC_CLASS_MAXMIND_CONTINENT:
            return "Maxmind continent";
        case CORSARO_METRIC_CLASS_MAXMIND_COUNTRY:
            return "Maxmind country";
        case CORSARO_METRIC_CLASS_NETACQ_CONTINENT:
            return "Netacq continent";
        case CORSARO_METRIC_CLASS_NETACQ_COUNTRY:
            return "Netacq country";
        case CORSARO_METRIC_CLASS_PREFIX_ASN:
            return "pfx2as ASN";
    }

    return "unknown";

}

#define GEN_METRICID(class, val) \
    ((((uint64_t) class) << 32) + ((uint64_t)val))


static inline void add_new_message_tag(corsaro_report_msg_body_t *body,
        uint64_t metricid, uint16_t iplen, uint8_t issrc) {

    assert(body->numtags < CORSARO_MAX_SUPPORTED_TAGS);

    body->tags[body->numtags].metid = metricid;

    /* Be careful not to count the packet twice per metric */ 
    if (issrc) {
        body->tags[body->numtags].size = iplen;
    } else {
        body->tags[body->numtags].size = 0;
    }

    body->numtags ++;

}

static inline void process_single_tag(corsaro_report_metric_class_t class,
        uint32_t tagval, uint32_t maxtagval, uint16_t iplen,
        corsaro_report_state_t *state, corsaro_report_msg_body_t *body,
        corsaro_logger_t *logger, uint8_t issrc) {

    uint64_t metricid;

    if (maxtagval > 0 && tagval >= maxtagval) {
        corsaro_log(logger, "Invalid %s tag: %u", metclasstostr(class),
                tagval);
        return;
    }

    metricid = GEN_METRICID(class, tagval);
    /*
    if (issrc) {
        update_basic_counter(state, metricid, iplen);
    }
    */

    add_new_message_tag(body, metricid, iplen, issrc);
}


static void process_tags(corsaro_packet_tags_t *tags, uint16_t iplen,
        corsaro_report_msg_body_t *body, corsaro_report_state_t *state,
        corsaro_logger_t *logger, uint32_t addr, uint8_t issrc) {

    body->ipaddr = addr;
    body->issrc = issrc;
    body->numtags = 0;

    process_single_tag(CORSARO_METRIC_CLASS_COMBINED, 0, 0, iplen, state,
            body, logger, issrc);

    if (!tags || tags->providers_used == 0) {
        return;
    }

    process_single_tag(CORSARO_METRIC_CLASS_IP_PROTOCOL, tags->protocol,
            METRIC_IPPROTOS_MAX, iplen, state, body, logger, issrc);

    if (tags->protocol == TRACE_IPPROTO_ICMP) {
        process_single_tag(CORSARO_METRIC_CLASS_ICMP_TYPE, tags->src_port,
                METRIC_ICMP_MAX, iplen, state, body, logger, issrc);
        process_single_tag(CORSARO_METRIC_CLASS_ICMP_CODE, tags->dest_port,
                METRIC_ICMP_MAX, iplen, state, body, logger, issrc);

    } else if (tags->protocol == TRACE_IPPROTO_TCP) {
        process_single_tag(CORSARO_METRIC_CLASS_TCP_SOURCE_PORT, tags->src_port,
                METRIC_PORT_MAX, iplen, state, body, logger, issrc);
        process_single_tag(CORSARO_METRIC_CLASS_TCP_DEST_PORT, tags->dest_port,
                METRIC_PORT_MAX, iplen, state, body, logger, issrc);
    } else if (tags->protocol == TRACE_IPPROTO_UDP) {
        process_single_tag(CORSARO_METRIC_CLASS_UDP_SOURCE_PORT, tags->src_port,
                METRIC_PORT_MAX, iplen, state, body, logger, issrc);
        process_single_tag(CORSARO_METRIC_CLASS_UDP_DEST_PORT, tags->dest_port,
                METRIC_PORT_MAX, iplen, state, body, logger, issrc);
    }

    if (maxmind_tagged(tags)) {
        process_single_tag(CORSARO_METRIC_CLASS_MAXMIND_CONTINENT,
                tags->maxmind_continent, 0, iplen, state, body, logger, issrc);
        process_single_tag(CORSARO_METRIC_CLASS_MAXMIND_COUNTRY,
                tags->maxmind_country, 0, iplen, state, body, logger, issrc);
    }

    if (netacq_tagged(tags)) {
        process_single_tag(CORSARO_METRIC_CLASS_NETACQ_CONTINENT,
                tags->netacq_continent, 0, iplen, state, body, logger, issrc);
        process_single_tag(CORSARO_METRIC_CLASS_NETACQ_COUNTRY,
                tags->netacq_country, 0, iplen, state, body, logger, issrc);
    }

    if (pfx2as_tagged(tags)) {
        process_single_tag(CORSARO_METRIC_CLASS_PREFIX_ASN,
                tags->prefixasn, 0, iplen, state, body, logger, issrc);
    }

}

int corsaro_report_process_packet(corsaro_plugin_t *p, void *local,
        libtrace_packet_t *packet, corsaro_packet_tags_t *tags) {

    corsaro_report_state_t *state;
    uint16_t iplen;
    uint32_t srcaddr, dstaddr;
    int trackerhash;
    corsaro_memsource_t *memsrc;
    corsaro_report_config_t *conf;
    corsaro_report_msg_body_t *body;
    corsaro_report_ip_message_t *msg;

    conf = (corsaro_report_config_t *)(p->config);
    state = (corsaro_report_state_t *)local;

    if (state == NULL) {
        corsaro_log(p->logger,
                "corsaro_report_process_packet: report thread-local state is NULL!");
        return -1;
    }

    if (extract_addresses(packet, &srcaddr, &dstaddr, &iplen) != 0) {
        return 0;
    }

    trackerhash = (srcaddr >> 24) % conf->tracker_count;
    msg = &(state->nextmsg[trackerhash]);
    body = &(msg->update[msg->bodycount]);
    process_tags(tags, iplen, body, state, p->logger, srcaddr, 1);
    msg->bodycount ++;


    if (msg->bodycount == REPORT_BATCH_SIZE) {
        
        if (libtrace_message_queue_count(&(conf->iptrackers[trackerhash].incoming)) >= 2048) {
            state->queueblocks ++;
        }
        libtrace_message_queue_put(&(conf->iptrackers[trackerhash].incoming), (void *)msg);
        msg->bodycount = 0;
        msg->update = (corsaro_report_msg_body_t *)
            get_corsaro_memhandler_item(state->msgbody_handler, &memsrc);
        msg->handler = state->msgbody_handler;
        msg->memsrc = memsrc;
    }

    trackerhash = (dstaddr >> 24) % conf->tracker_count;
    msg = &(state->nextmsg[trackerhash]);
    body = &(msg->update[msg->bodycount]);
    process_tags(tags, iplen, body, state, p->logger, dstaddr, 0);
    msg->bodycount ++;

    if (msg->bodycount == REPORT_BATCH_SIZE) {
        if (libtrace_message_queue_count(&(conf->iptrackers[trackerhash].incoming)) >= 2048) {
            state->queueblocks ++;
        }
        libtrace_message_queue_put(&(conf->iptrackers[trackerhash].incoming), (void *)msg);
        msg->bodycount = 0;
        msg->update = (corsaro_report_msg_body_t *)
            get_corsaro_memhandler_item(state->msgbody_handler, &memsrc);
        msg->handler = state->msgbody_handler;
        msg->memsrc = memsrc;
    }

    return 0;
}

/** ------------- MERGING API -------------------- */

void *corsaro_report_init_merging(corsaro_plugin_t *p, int sources) {

    corsaro_report_merge_state_t *m;

    m = (corsaro_report_merge_state_t *)calloc(1,
            sizeof(corsaro_report_merge_state_t));
    if (m == NULL) {
        corsaro_log(p->logger,
                "corsaro_report_init_merging: out of memory while allocating merge state.");
        return NULL;
    }

    m->writer = corsaro_create_avro_writer(p->logger, REPORT_RESULT_SCHEMA);
    if (m->writer == NULL) {
        corsaro_log(p->logger,
                "error while creating avro writer for report plugin!");
        free(m);
        return NULL;
    }

    m->res_handler = (corsaro_memhandler_t *)malloc(
            sizeof(corsaro_memhandler_t));
    init_corsaro_memhandler(p->logger, m->res_handler,
            sizeof(corsaro_report_result_t), 10000);

    return m;
}

int corsaro_report_halt_merging(corsaro_plugin_t *p, void *local) {
    corsaro_report_merge_state_t *m;

    m = (corsaro_report_merge_state_t *)local;
    if (m == NULL) {
        return 0;
    }

    if (m->writer) {
        corsaro_destroy_avro_writer(m->writer);
    }

    if (m->res_handler) {
        destroy_corsaro_memhandler(m->res_handler);
    }
    free(m);
    return 0;
}

static inline int report_do_avro_write(corsaro_logger_t *logger,
        corsaro_avro_writer_t *writer, corsaro_report_result_t *res) {

    avro_value_t *avro;

    avro = corsaro_populate_avro_item(writer, res, report_result_to_avro);
    if (avro == NULL) {
        corsaro_log(logger,
                "could not convert report result to Avro record");
        return -1;
    }

    if (corsaro_append_avro_writer(writer, avro) < 0) {
        corsaro_log(logger,
                "could not write report result to Avro output file");
        return -1;
    }
    return 0;
}

static int write_single_metric(corsaro_logger_t *logger,
        corsaro_avro_writer_t *writer, corsaro_report_result_t *res) {

    char valspace[2048];

    switch(res->metricid >> 32) {
        case CORSARO_METRIC_CLASS_COMBINED:
            res->metrictype = "combined";
            res->metricval = "all";
            break;
        case CORSARO_METRIC_CLASS_IP_PROTOCOL:
            res->metrictype = "ipprotocol";
            snprintf(valspace, 2048, "%lu", res->metricid & 0xffffffff);
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_ICMP_CODE:
            res->metrictype = "icmp-code";
            snprintf(valspace, 2048, "%lu", res->metricid & 0xffffffff);
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_ICMP_TYPE:
            res->metrictype = "icmp-type";
            snprintf(valspace, 2048, "%lu", res->metricid & 0xffffffff);
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_TCP_SOURCE_PORT:
            res->metrictype = "tcpsourceport";
            snprintf(valspace, 2048, "%lu", res->metricid & 0xffffffff);
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_TCP_DEST_PORT:
            res->metrictype = "tcpdestport";
            snprintf(valspace, 2048, "%lu", res->metricid & 0xffffffff);
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_UDP_SOURCE_PORT:
            res->metrictype = "udpsourceport";
            snprintf(valspace, 2048, "%lu", res->metricid & 0xffffffff);
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_UDP_DEST_PORT:
            res->metrictype = "udpdestport";
            snprintf(valspace, 2048, "%lu", res->metricid & 0xffffffff);
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_MAXMIND_CONTINENT:
            res->metrictype = "maxmind-continent";
            snprintf(valspace, 2048, "%c%c", (int)(res->metricid & 0xff),
                    (int)((res->metricid >> 8) & 0xff));
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_MAXMIND_COUNTRY:
            res->metrictype = "maxmind-country";
            snprintf(valspace, 2048, "%c%c", (int)(res->metricid & 0xff),
                    (int)((res->metricid >> 8) & 0xff));
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_NETACQ_CONTINENT:
            res->metrictype = "netacq-continent";
            snprintf(valspace, 2048, "%c%c", (int)(res->metricid & 0xff),
                    (int)((res->metricid >> 8) & 0xff));
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_NETACQ_COUNTRY:
            res->metrictype = "netacq-country";
            snprintf(valspace, 2048, "%c%c", (int)(res->metricid & 0xff),
                    (int)((res->metricid >> 8) & 0xff));
            res->metricval = valspace;
            break;
        case CORSARO_METRIC_CLASS_PREFIX_ASN:
            res->metrictype = "pfx2asn";
            snprintf(valspace, 2048, "%lu", res->metricid & 0xffffffff);
            res->metricval = valspace;
            break;
    }

    if (report_do_avro_write(logger, writer, res) == -1) {
        return -1;
    }
    return 0;

}

static int write_all_metrics(corsaro_logger_t *logger,
        corsaro_avro_writer_t *writer, corsaro_report_result_t **resultmap,
        corsaro_memhandler_t *handler) {

    corsaro_report_result_t *r, *tmpres;

    HASH_ITER(hh, *resultmap, r, tmpres) {
        write_single_metric(logger, writer, r);
        HASH_DELETE(hh, *resultmap, r);
        release_corsaro_memhandler_item(handler, r->memsrc);
    }

    return 0;

}

static inline corsaro_report_result_t *new_result(uint64_t metricid,
        corsaro_memhandler_t *reshandler, char *outlabel, uint32_t ts) {

    corsaro_report_result_t *r;
    corsaro_memsource_t *memsrc;

    r = (corsaro_report_result_t *)get_corsaro_memhandler_item(
            reshandler, &memsrc);
    r->metricid = metricid;
    r->pkt_cnt = 0;
    r->bytes = 0;
    r->uniq_src_ips = 0;
    r->uniq_dst_ips = 0;
    r->attimestamp = ts;
    r->label = outlabel;
    r->metrictype = NULL;
    r->metricval = NULL;
    r->memsrc = memsrc;
    return r;
}

static void update_tracker_results(corsaro_report_result_t **results,
        corsaro_report_iptracker_t *tracker, uint32_t ts,
        corsaro_report_config_t *conf, corsaro_memhandler_t *reshandler) {

    corsaro_report_result_t *r;
    corsaro_metric_ip_hash_t *iter, *tmp;

    HASH_ITER(hh, tracker->lastresult, iter, tmp) {
        HASH_FIND(hh, *results, &(iter->metricid), sizeof(iter->metricid),
                r);
        if (!r) {
            r = new_result(iter->metricid, reshandler, conf->outlabel, ts);
            HASH_ADD_KEYPTR(hh, *results, &(r->metricid),
                    sizeof(r->metricid), r);
        }
        r->uniq_src_ips += iter->srcips;
        r->uniq_dst_ips += iter->destips;
        r->pkt_cnt += iter->packets;
        r->bytes += iter->bytes;

        HASH_DELETE(hh, tracker->lastresult, iter);
        release_corsaro_memhandler_item(tracker->metric_handler, iter->memsrc);
    }

}

int corsaro_report_merge_interval_results(corsaro_plugin_t *p, void *local,
        void **tomerge, corsaro_fin_interval_t *fin) {

    corsaro_report_config_t *conf, *procconf;
    corsaro_report_merge_state_t *m;
    int i, ret;
    char *outname;
    corsaro_report_result_t *results = NULL;
    uint8_t *trackers_done;
    uint8_t totaldone = 0, skipresult = 0;

    m = (corsaro_report_merge_state_t *)local;
    if (m == NULL) {
        return -1;
    }

    procconf = ((corsaro_report_interim_t *)(tomerge[0]))->baseconf;
    conf = (corsaro_report_config_t *)(p->config);

    corsaro_log(p->logger, "waiting for IP tracker results.....%u", fin->timestamp);
    trackers_done = (uint8_t *)calloc(procconf->tracker_count, sizeof(uint8_t));

    do {
        for (i = 0; i < procconf->tracker_count; i++) {
            if (trackers_done[i]) {
                continue;
            }

            if (pthread_mutex_trylock(&(procconf->iptrackers[i].mutex)) == 0) {
                assert(fin->timestamp >= procconf->iptrackers[i].lastresultts);
                if (procconf->iptrackers[i].lastresultts == fin->timestamp) {
                    update_tracker_results(&results, &(procconf->iptrackers[i]),
                            fin->timestamp, conf, m->res_handler);

                    trackers_done[i] = 1;
                    totaldone ++;
                } else if (procconf->iptrackers[i].haltphase == 2) {
                    /* Tracker thread has been halted, no new results are
                     * coming... */
                    trackers_done[i] = 1;
                    totaldone ++;
                    skipresult = 1;
                }
                pthread_mutex_unlock(&(procconf->iptrackers[i].mutex));
            }
        }
        if (totaldone < procconf->tracker_count) {
            usleep(100);
        }
    } while (totaldone < procconf->tracker_count);

    free(trackers_done);
    corsaro_log(p->logger, "all IP tracker results have been read!");

    if (skipresult) {
        /* This result is invalid because not all of the tracker threads
         * were able to produce a result (due to being interrupted).
         * Don't try writing it to the avro output to avoid being
         * misleading.
         */
        return 0;
    }

    if (!corsaro_is_avro_writer_active(m->writer)) {
        outname = p->derive_output_name(p, local, fin->timestamp, -1);
        if (outname == NULL) {
            return -1;
        }
        if (corsaro_start_avro_writer(m->writer, outname) == -1) {
            free(outname);
            return -1;
        }
        free(outname);
    }

    ret = 0;
    if (write_all_metrics(p->logger, m->writer, &results, m->res_handler) < 0)
    {
        return -1;
    }
    return ret;
}

int corsaro_report_rotate_output(corsaro_plugin_t *p, void *local) {

    corsaro_report_merge_state_t *m;

    m = (corsaro_report_merge_state_t *)local;
    if (m == NULL) {
        return -1;
    }

    if (m->writer == NULL || corsaro_close_avro_writer(m->writer) < 0) {
        return -1;
    }
    return 0;
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
