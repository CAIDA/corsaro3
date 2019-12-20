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

#include "corsaro_report.h"
#include "report_internal.h"
#include "libcorsaro_avro.h"
#include "libcorsaro_libtimeseries.h"
#include "libcorsaro_filtering.h"

#define AVRO_CONVERSION_FAILURE -1
#define AVRO_WRITE_FAILURE -2

#define LOOKUP_GEOTAG_LABEL(contmap, metricid) \
    lookup = metricid & 0xffffffff; \
    JLF(pval, contmap, lookup); \
    if (pval == NULL) { \
        contkey = "notfound"; \
    } else { \
        contkey = (const char *)*pval; \
    }

#define INSERT_IPMETA_LABEL(labelmap, index, labelstr) \
    { \
    PWord_t pval; \
    JLI(pval, labelmap, index); \
    if ((char *)(*pval) != NULL) { \
        free((char *)(*pval)); \
    } \
    *pval = (Word_t)labelstr; \
    }

#define STRIP_METRIC_VALUE(foundkey, dest, remain, len) \
    { \
        char *rstr = strrchr(foundkey, '.'); \
        if (rstr == NULL || rstr - foundkey >= len) { \
            memcpy(dest, foundkey, len - 1); \
            metrickey[len - 1] = '\0'; \
            remain = ""; \
        } else { \
            int keylen = rstr - foundkey; \
            memcpy(dest, foundkey, keylen); \
            dest[keylen] = '\0'; \
            remain = rstr + 1; \
        } \
    }

#define ADD_TIMESERIES_KEY(metric) \
    snprintf(fullkeyname, 5000, "%s.%s", keyname, metric); \
    keyid = timeseries_kp_add_key(m->kp, fullkeyname); \
    if (keyid == -1) { \
        corsaro_log(p->logger, \
                "error adding %s to timeseries key package", fullkeyname); \
        return -1; \
    }

#define ADD_EMPTY_RESULT(metricclass, metricval) \
    metricid = GEN_METRICID(metricclass, metricval); \
    r = new_result(metricid, conf->outlabel, ts); \
    JLI(pval, *results, (Word_t)metricid); \
    *pval = (Word_t)r;

/** Merge thread state for the report plugin */
typedef struct corsaro_report_merge_state {

    /** A writer instance used for writing output in the Avro format */
    corsaro_avro_writer_t *writer;

    /** Libtimeseries state variable */
    timeseries_t *timeseries;

    /** Libtimeseries key package for writing output as time series */
    timeseries_kp_t *kp;

    /** Judy array containing all of the keys that we have added to our
     *  libtimeseries instance.
     */
    Pvoid_t metrickp_keys;

    /** Timestamp from the last label update that we received successfully
     *  from the tagger.
     */
    uint32_t last_label_update;

    /** Map of country IDs to FQ country labels */
    Pvoid_t country_labels;

    /** Map of region IDs to FQ region labels */
    Pvoid_t region_labels;

    /** Map of polygon IDs to FQ polygon labels -- note that polygons can
    */
    Pvoid_t polygon_labels;
} corsaro_report_merge_state_t;


/** Avro schema for report plugin results */
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
        {\"name\": \"byte_cnt\", \"type\": \"long\"}, \
        {\"name\": \"src_asn_cnt\", \"type\": \"long\"} \
        ]}";

/* Pre-defined alpha-2 codes for continents */
#define CORSAROTRACE_NUM_CONTINENTS (8)
const char *alpha2_continents[] = {
    "??", "AF", "AN", "AS", "EU", "NA", "OC", "SA",
};

/* Pre-defined alpha-2 codes for countries */
#define CORSAROTRACE_NUM_COUNTRIES (255)
const char *alpha2_countries[] = {
    "??", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS",
    "AT", "AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH",
    "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV", "BW",
    "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM",
    "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK",
    "DM", "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ",
    "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI",
    "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK",
    "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ",
    "IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM",
    "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR",
    "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH",
    "MK", "ML", "MM", "MN", "MO", "MP", "MQ" ,"MR", "MS", "MT", "MU", "MV",
    "MW", "MX", "MY", "MZ", "NA", "NC" ,"NE", "NF", "NG", "NI", "NL", "NO",
    "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL",
    "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU",
    "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL",
    "SM", "SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD",
    "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR", "TT", "TV",
    "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG",
    "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW",
    "A1", "A2", "O1", "AP", "EU",
};

static inline const char * get_filter_stringname(int fbit) {

    switch(fbit) {
        case CORSARO_FILTERID_ABNORMAL_PROTOCOL:
            return "non-spoofed.abnormal-protocol";
        case CORSARO_FILTERID_TTL_200:
            return "non-spoofed.ttl-200";
        case CORSARO_FILTERID_NO_TCP_OPTIONS:
            return "scan.no-tcp-options";
        case CORSARO_FILTERID_TCPWIN_1024:
            return "scan.tcp-win-1024";
        case CORSARO_FILTERID_FRAGMENT:
            return "non-spoofed.fragmented-v2";
        case CORSARO_FILTERID_LAST_SRC_IP_0:
            return "non-spoofed.last-byte-src-0";
        case CORSARO_FILTERID_LAST_SRC_IP_255:
            return "non-spoofed.last-byte-src-255";
        case CORSARO_FILTERID_SAME_SRC_DEST_IP:
            return "non-spoofed.same-src-dst";
        case CORSARO_FILTERID_UDP_PORT_0:
            return "non-spoofed.udp-port-0";
        case CORSARO_FILTERID_TCP_PORT_0:
            return "non-spoofed.tcp-port-0";
        case CORSARO_FILTERID_UDP_DESTPORT_80:
            return "non-spoofed.udp-destport-80";
        case CORSARO_FILTERID_RFC5735:
            return "non-routed.rfc5735";
        case CORSARO_FILTERID_BACKSCATTER:
            return "non-erratic.backscatter";
        case CORSARO_FILTERID_BITTORRENT:
            return "non-erratic.bittorrent";
        case CORSARO_FILTERID_UDP_0X31:
            return "non-erratic.udp-0x31";
        case CORSARO_FILTERID_UDP_IPLEN_96:
            return "non-erratic.udp-ip-len-96";
        case CORSARO_FILTERID_SIP_STATUS:
            return "non-erratic.sip-status";
        case CORSARO_FILTERID_PORT_53:
            return "non-erratic.port-53";
        case CORSARO_FILTERID_TCP_PORT_23:
            return "non-erratic.tcp-port-23";
        case CORSARO_FILTERID_TCP_PORT_80:
            return "non-erratic.tcp-port-80";
        case CORSARO_FILTERID_TCP_PORT_5000:
            return "non-erratic.tcp-port-5000";
        case CORSARO_FILTERID_DNS_RESP_NONSTANDARD:
            return "non-erratic.dns-resp-non-standard-v2";
        case CORSARO_FILTERID_NETBIOS_QUERY_NAME:
            return "non-erratic.netbios-query-name";
        case CORSARO_FILTERID_UDP_IPLEN_1500:
            return "non-erratic.udp-ip-len-1500";
        case CORSARO_FILTERID_NOTIP:
            return "not-ip";
    }
    return "unexpected";
}

/** Produce fully-qualified labels for both the metric class and the
 *  metric value for a given result.
 *
 */
static inline void metric_to_strings(corsaro_report_merge_state_t *m,
        corsaro_report_result_t *res) {

    Word_t *pval;
    const char *contkey = NULL;
    char *remain;
    char metrickey[128];
    uint64_t lookup;

    /* Convert the 64 bit metric ID into printable strings that we can
     * put in our result output.
     *
     * Hopefully, these will match the strings that were used by
     * previous instances of this plugin...
     */
    switch(res->metricid >> 32) {
        case CORSARO_METRIC_CLASS_COMBINED:
            strncpy(res->metrictype, "overall", 128);
            res->metricval[0] = '\0';
            break;
        case CORSARO_METRIC_CLASS_IP_PROTOCOL:
            strncpy(res->metrictype, "traffic.protocol", 128);
            snprintf(res->metricval, 128, "%lu", res->metricid & 0xffffffff);
            break;
        case CORSARO_METRIC_CLASS_ICMP_CODE:
            strncpy(res->metrictype, "traffic.icmp.code", 128);
            snprintf(res->metricval, 128, "%lu", res->metricid & 0xffffffff);
            break;
        case CORSARO_METRIC_CLASS_ICMP_TYPE:
            strncpy(res->metrictype, "traffic.icmp.type", 128);
            snprintf(res->metricval, 128, "%lu", res->metricid & 0xffffffff);
            break;
        case CORSARO_METRIC_CLASS_TCP_SOURCE_PORT:
            strncpy(res->metrictype, "traffic.port.tcp.src_port", 128);
            snprintf(res->metricval, 128, "%lu", res->metricid & 0xffffffff);
            break;
        case CORSARO_METRIC_CLASS_TCP_DEST_PORT:
            strncpy(res->metrictype, "traffic.port.tcp.dst_port", 128);
            snprintf(res->metricval, 128, "%lu", res->metricid & 0xffffffff);
            break;
        case CORSARO_METRIC_CLASS_UDP_SOURCE_PORT:
            strncpy(res->metrictype, "traffic.port.udp.src_port", 128);
            snprintf(res->metricval, 128, "%lu", res->metricid & 0xffffffff);
            break;
        case CORSARO_METRIC_CLASS_UDP_DEST_PORT:
            strncpy(res->metrictype, "traffic.port.udp.dst_port", 128);
            snprintf(res->metricval, 128, "%lu", res->metricid & 0xffffffff);
            break;
        case CORSARO_METRIC_CLASS_MAXMIND_CONTINENT:
            strncpy(res->metrictype, "geo.maxmind", 128);
            snprintf(res->metricval, 128, "%c%c", (int)(res->metricid & 0xff),
                    (int)((res->metricid >> 8) & 0xff));
            break;
        case CORSARO_METRIC_CLASS_MAXMIND_COUNTRY:
            LOOKUP_GEOTAG_LABEL(m->country_labels, res->metricid)
            STRIP_METRIC_VALUE(contkey, metrickey, remain, 128);
            snprintf(res->metrictype, 256, "geo.maxmind.%s", metrickey);
            snprintf(res->metricval, 128, "%c%c", (int)(res->metricid & 0xff),
                    (int)((res->metricid >> 8) & 0xff));
            break;
        case CORSARO_METRIC_CLASS_NETACQ_CONTINENT:
            strncpy(res->metrictype, "geo.netacuity", 128);
            snprintf(res->metricval, 128, "%c%c", (int)(res->metricid & 0xff),
                    (int)((res->metricid >> 8) & 0xff));
            break;
        case CORSARO_METRIC_CLASS_NETACQ_COUNTRY:
            LOOKUP_GEOTAG_LABEL(m->country_labels, res->metricid)
            STRIP_METRIC_VALUE(contkey, metrickey, remain, 128);
            snprintf(res->metrictype, 256, "geo.netacuity.%s", metrickey);
            snprintf(res->metricval, 128, "%c%c", (int)(res->metricid & 0xff),
                    (int)((res->metricid >> 8) & 0xff));
            break;
        case CORSARO_METRIC_CLASS_NETACQ_REGION:
            LOOKUP_GEOTAG_LABEL(m->region_labels, res->metricid)
            STRIP_METRIC_VALUE(contkey, metrickey, remain, 128);
            snprintf(res->metrictype, 256, "geo.netacuity.%s", metrickey);
            snprintf(res->metricval, 128, "%s", remain);
            break;
        case CORSARO_METRIC_CLASS_NETACQ_POLYGON:
            LOOKUP_GEOTAG_LABEL(m->polygon_labels, res->metricid)
            STRIP_METRIC_VALUE(contkey, metrickey, remain, 128);
            snprintf(res->metrictype, 256, "geo.netacuity.%s", metrickey);
            snprintf(res->metricval, 128, "%s", remain);
            break;
        case CORSARO_METRIC_CLASS_PREFIX_ASN:
            strncpy(res->metrictype , "routing.asn", 128);
            snprintf(res->metricval, 128, "%lu", res->metricid & 0xffffffff);
            break;
        case CORSARO_METRIC_CLASS_FILTER_CRITERIA:
            if ((res->metricid & 0xffffffff) >=
                    CORSARO_FILTERID_ABNORMAL_PROTOCOL) {
                snprintf(res->metrictype, 256, "filter-criteria");
                snprintf(res->metricval, 128, "%s",
                        get_filter_stringname(res->metricid & 0xffffffff));
            }
            break;
    }
}


/** Converts a report result into an Avro value
 *
 *  @return a populated avro_value_t that contains the labels, tallies, etc.
 *          from the given result structure.
 */
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
    CORSARO_AVRO_SET_FIELD(long, av, field, 8, "src_asn_cnt", "report",
            res->uniq_src_asn_count);
    return 0;
}

/** Given a report result, determines the base name for the corresponding
 *  libtimeseries key for lookup in our "known keys" map.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param m            The local state for the merging thread.
 *  @param keyspace     A string buffer that we can write the key name into
 *  @param keylen       The size of the keyspace buffer
 *  @param res          A single report plugin result which we need the key
 *                      name for.
 *
 *  @return the length of the resulting key string.
 */
static inline int derive_libts_keyname(corsaro_plugin_t *p,
        corsaro_report_merge_state_t *m,
        char *keyspace, int keylen, corsaro_report_result_t *res) {

    int ret;
    corsaro_report_config_t *config = (corsaro_report_config_t *)p->config;

    metric_to_strings(m, res);
    /* 'overall' metrics have no suitable metric value, so we need to
     * account for this case.
     */
    if (strlen(res->metricval) > 0) {
        ret = snprintf(keyspace, keylen, "%s.%s.%s",
                config->outlabel, res->metrictype, res->metricval);
    } else {
        ret = snprintf(keyspace, keylen, "%s.%s",
                config->outlabel, res->metrictype);
    }

    if (ret >= keylen) {
        corsaro_log(p->logger,
                "truncated libtimeseries key basename to '%s', output_row_label is too long",
                keyspace);
        ret = keylen - 1;
    }

    return ret;
}



/** Convert a report result into an Avro record and write it to the Avro
 *  output file.
 *
 *  @param logger       A reference to a corsaro logger for error reporting
 *  @param writer       The corsaro Avro writer that will be writing the output
 *  @param res          The report plugin result to be written.
 *  @return 0 if the write is successful, -1 if an error occurs.
 */
static int write_single_metric_avro(corsaro_report_merge_state_t *m,
        corsaro_logger_t *logger,
        corsaro_avro_writer_t *writer, corsaro_report_result_t *res) {

    avro_value_t *avro;

    metric_to_strings(m, res);
    avro = corsaro_populate_avro_item(writer, res, report_result_to_avro);
    if (avro == NULL) {
        corsaro_log(logger,
                "could not convert report result to Avro record");
        return AVRO_CONVERSION_FAILURE;
    }

    if (corsaro_append_avro_writer(writer, avro) < 0) {
        corsaro_log(logger,
                "could not write report result to Avro output file");
        return AVRO_WRITE_FAILURE;
    }
    return 0;
}

/** Writes the combined tallies for each metric to an Avro output file
 *
 *  @param logger       A reference to a corsaro logger for error reporting.
 *  @param writer       The corsaro Avro writer that will be writing the output.
 *  @param resultmap    The hash map containing the combined metric tallies.
 *  @param m            The local state for the merging thread.
 *  @param subtreemask  A bitmask showing which metric classes were actively
 *                      measured during the last interval
 *  @return 0 if successful, -1 if an error occurred.
 */

static int write_all_metrics_avro(corsaro_logger_t *logger,
        corsaro_avro_writer_t *writer, Pvoid_t *resultmap,
        corsaro_report_merge_state_t *m, uint32_t subtreemask) {

    corsaro_report_result_t *r, *tmpres;
    int writeret = 0;
    int stopwriting = 0;
    int haderror = 0;
    Word_t index = 0, judyret;
    PWord_t pval;

    JLF(pval, *resultmap, index);
    while (pval) {
        r = (corsaro_report_result_t *)(*pval);

        /* Don't write metrics for sub-trees that have never been
         * looked at by the upstream tagger, e.g. if we have no
         * maxmind tagging, don't write a bunch of 0s for each
         * country.
         */
        if ((subtreemask & (1 << (r->metricid >> 32))) == 0) {
            free(r);
            JLN(pval, *resultmap, index);
            continue;
        }

        /* If we run into an error while writing, maybe don't try to write
         * anymore.
         */
        if (!stopwriting) {
            writeret = write_single_metric_avro(m, logger, writer, r);
            if (writeret == AVRO_WRITE_FAILURE) {
                stopwriting = 1;
            }
            if (writeret < 0) {
                haderror = 1;
            }
        }
        J1FA(judyret, r->uniq_src_asns);
        free(r);

        JLN(pval, *resultmap, index);
    }

    JLFA(judyret, *resultmap);
    return haderror;

}

/** Writes the combined tallies for each metric using libtimeseries.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param m            The merge thread state for this plugin
 *  @param timestamp    The timestamp for the interval that the tallies
 *                      correspond to
 *  @param results      A Judy array containing the tallies
 *  @param subtreemask  A bitmask showing which metric classes were actively
 *                      measured during the last interval
 *
 *  @return -1 if an error occurs, 0 if successful
 */
static int report_write_libtimeseries(corsaro_plugin_t *p,
        corsaro_report_merge_state_t *m, uint32_t timestamp, Pvoid_t *results,
        uint32_t subtreemask)
{
    corsaro_report_result_t *r;
    Word_t index = 0, judyret;
    PWord_t pval;

    JLF(pval, *results, index);

    /* Iterate over all of the metrics in our array */
    while (pval) {
        r = (corsaro_report_result_t *)(*pval);

        /* Don't write metrics for sub-trees that have never been
         * looked at by the upstream tagger, e.g. if we have no
         * maxmind tagging, don't write a bunch of 0s for each
         * country.
         */
        if ((subtreemask & (1 << (r->metricid >> 32))) == 0) {
            J1FA(judyret, r->uniq_src_asns);
            free(r);
            JLN(pval, *results, index);
            continue;
        }

        JLG(pval, m->metrickp_keys, r->metricid);
        if (pval == NULL) {
            /* This is a metric ID that we haven't seen before so we need
             * to create a new 'key' in libtimeseries for it.
             */
            char keyname[4096];
            char fullkeyname[5000];
            int keyid = -1;

            if (derive_libts_keyname(p, m, keyname, 4096, r) <= 0) {
                corsaro_log(p->logger,
                        "error deriving suitable keyname from metricid %lu",
                        r->metricid);
                return -1;
            }

            /* We'll need a separate key for each of our tallies */
            ADD_TIMESERIES_KEY("uniq_src_ip");

            /* Do the JLI here, as we only want to add the first of the
             * four keys to our metrickp_keys array */
            JLI(pval, m->metrickp_keys, r->metricid);
            *pval = (Word_t)keyid;

            ADD_TIMESERIES_KEY("uniq_dst_ip");
            ADD_TIMESERIES_KEY("uniq_src_asn");
            ADD_TIMESERIES_KEY("pkt_cnt");
            ADD_TIMESERIES_KEY("ip_len");
        }

        /* *pval contains the key ID for uniq_src_ip, but keys are
         * assigned sequentially so we can use that to derive the key IDs
         * for the other tallies. */
        timeseries_kp_set(m->kp, *pval, r->uniq_src_ips);
        timeseries_kp_set(m->kp, (*pval) + 1, r->uniq_dst_ips);
        timeseries_kp_set(m->kp, (*pval) + 2, r->uniq_src_asn_count);
        timeseries_kp_set(m->kp, (*pval) + 3, r->pkt_cnt);
        timeseries_kp_set(m->kp, (*pval) + 4, r->bytes);

        J1FA(judyret, r->uniq_src_asns);
        free(r);
        JLN(pval, *results, index);
    }

    /* Flush all of our results for this interval to the backends */
    timeseries_kp_flush(m->kp, timestamp);
    JLFA(judyret, *results);
    return 0;
}

/** Writes the combined tallies for each metric using a corsaro avro writer.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param m            The merge thread state for this plugin
 *  @param timestamp    The timestamp for the interval that the tallies
 *                      correspond to
 *  @param results      A Judy array containing the tallies
 *  @param subtreemask  A bitmask showing which metric classes were actively
 *                      measured during the last interval
 *
 *  @return -1 if an error occurs, 0 if successful
 */
static int report_write_avro_output(corsaro_plugin_t *p,
        corsaro_report_merge_state_t *m, uint32_t timestamp,
        Pvoid_t *results, uint32_t subtreemask) {

    char *outname;

    /* Make sure we've got a valid Avro writer ready to go */
    if (!corsaro_is_avro_writer_active(m->writer)) {
        outname = p->derive_output_name(p, m, timestamp, -1);
        if (outname == NULL) {
            return -1;
        }
        if (corsaro_start_avro_writer(m->writer, outname, 0) == -1) {
            free(outname);
            return -1;
        }
        free(outname);
    }

    if (write_all_metrics_avro(p->logger, m->writer, results,
                m, subtreemask) < 0) {
        return -1;
    }

    return 0;
}


static void clean_result_map(Pvoid_t *resultmap) {

    corsaro_report_result_t *r;
    Word_t index = 0, judyret;
    PWord_t pval;

    JLF(pval, *resultmap, index);
    while (pval) {
        r = (corsaro_report_result_t *)(*pval);
        free(r);
        JLN(pval, *resultmap, index);
    }

    JLFA(judyret, *resultmap);
}

/** Allocate and initialise a new report plugin result.
 *
 *  @param metricid         The ID of the metric that this result is for
 *  @param outlabel         The additional label to append to this result.
 *  @param ts               The timestamp of the interval that this result will
 *                          belong to.
 *  @return a pointer to a freshly created report plugin result.
 */
static inline corsaro_report_result_t *new_result(uint64_t metricid,
        char *outlabel, uint32_t ts) {

    corsaro_report_result_t *r;

    r = (corsaro_report_result_t *)calloc(1, sizeof(corsaro_report_result_t));
    r->metricid = metricid;
    r->pkt_cnt = 0;
    r->bytes = 0;
    r->uniq_src_ips = 0;
    r->uniq_dst_ips = 0;
    r->uniq_src_asn_count = 0;
    r->uniq_src_asns = NULL;
    r->attimestamp = ts;
    r->label = outlabel;
    r->metrictype[0] = '\0';
    r->metricval[0] = '\0';
    return r;
}

/** Initialises a results array with zeroes for as many metrics as
 *  we can, so we are still able to write a valid value even if the metric
 *  is not observed within an interval.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param results      The Judy array that will be used to store the tallies
 *  @param ts           The timestamp for the current interval
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static int initialise_results(corsaro_plugin_t *p, Pvoid_t *results,
        uint32_t ts) {

    uint64_t metricid, i;
    Word_t *pval;
    corsaro_report_result_t *r;
    corsaro_report_config_t *conf;
    int mm_country_count;
    const char **mm_country_list;

    conf = (corsaro_report_config_t *)(p->config);

    ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_COMBINED, 0);

    /* IP protocols, ICMP codes and types */
    for (i = 0; i < METRIC_ICMP_MAX; i++) {
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_IP_PROTOCOL, i);
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_ICMP_CODE, i);
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_ICMP_TYPE, i);
    }

    /* TCP and UDP ports */
    for (i = 0; i < METRIC_PORT_MAX; i++) {
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_TCP_SOURCE_PORT, i);
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_TCP_DEST_PORT, i);
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_UDP_SOURCE_PORT, i);
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_UDP_DEST_PORT, i);
    }

    /* XXX Do NOT add empty results for filters, as they may or
     * may not be relevant depending on high level filtering */

    /* ASNs are too sparse? */

    /* Continents */
    for (i = 0; i < CORSAROTRACE_NUM_CONTINENTS; i++) {
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_MAXMIND_CONTINENT,
                (((uint64_t)alpha2_continents[i][0]) |
                 ((uint64_t)alpha2_continents[i][1]) << 8));
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_NETACQ_CONTINENT,
                (((uint64_t)alpha2_continents[i][0]) |
                 ((uint64_t)alpha2_continents[i][1]) << 8));
    }

    /* Countries */
    for (i = 0; i < CORSAROTRACE_NUM_COUNTRIES; i++) {
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_MAXMIND_COUNTRY,
                (((uint64_t)alpha2_countries[i][0]) |
                 ((uint64_t)alpha2_countries[i][1]) << 8));
        ADD_EMPTY_RESULT(CORSARO_METRIC_CLASS_NETACQ_COUNTRY,
                (((uint64_t)alpha2_countries[i][0]) |
                 ((uint64_t)alpha2_countries[i][1]) << 8));
    }


    return 0;
}


/** Update the merged result set for an interval with a set of completed
 *  tallies from an IP tracker thread.
 *
 *  @param results          The hash map containing the combined metric tallies.
 *  @param tracker          The IP tracker thread which is providing new
 *                          tallies for our merged result.
 *  @param ts               The timestamp of the interval which this tally
 *                          applies to.
 *  @param conf             The global configuration for this report plugin.
 *  @param logger       A reference to a corsaro logger for error reporting.
 */
static void update_tracker_results(Pvoid_t *results,
        corsaro_report_iptracker_t *tracker, uint32_t ts,
        corsaro_report_config_t *conf,  uint32_t *subtrees_seen,
        corsaro_logger_t *logger) {

    corsaro_report_result_t *r;
    corsaro_metric_ip_hash_t *iter;
    PWord_t pval, pval2;
    Word_t index = 0, index2 = 0, ret;
    int x;

    /* Simple loop over all metrics in the tracker tally and update our
     * combined metric map.
     */

    JLF(pval, tracker->lastresult, index);
    while (pval) {
        iter = (corsaro_metric_ip_hash_t *)(*pval);

        *subtrees_seen = (*subtrees_seen) | (1 << (iter->metricid >> 32));

        JLG(pval2, *results, iter->metricid);
        if (pval2 == NULL) {
            /* This is a new metric, add it to our result hash map */
            r = new_result(iter->metricid, conf->outlabel, ts);
            JLI(pval2, *results, iter->metricid);
            *pval2 = (Word_t)r;
        } else {
            r = (corsaro_report_result_t *)(*pval2);
        }

        J1C(ret, iter->srcips, 0, -1);
        r->uniq_src_ips += (uint32_t)ret;
        J1C(ret, iter->destips, 0, -1);
        r->uniq_dst_ips += (uint32_t)ret;

        /* Consider limiting this to only certain metrics if processing
         * time becomes a problem?
         */
        index2 = 0;
        if (iter->srcasns == NULL) {
            r->uniq_src_asn_count = 0;
        } else {
            J1F(x, iter->srcasns, index2);
            while (x) {
                J1S(x, r->uniq_src_asns, (Word_t)index2);
                if (x != 0) {
                    r->uniq_src_asn_count ++;
                }
                J1N(x, iter->srcasns, index2);
            }
            J1FA(ret, iter->srcasns);
        }

        r->pkt_cnt += iter->packets;
        r->bytes += iter->bytes;

        /* Don't forget to release the metric tally back to the IP tracker */
        J1FA(ret, iter->srcips);
        J1FA(ret, iter->destips);
        free(iter);

        JLN(pval, tracker->lastresult, index);
    }

    JLFA(ret, tracker->lastresult);
    tracker->lastresult = NULL;
}


/** Creates and initialises the internal state required by the merging thread
 *  when using the report plugin.
 *
 *  @param p        A reference to the running instance of the report plugin
 *  @param sources  The number of packet processing threads that will be
 *                  feeding into the merging thread.
 *  @param tagsock  A zeromq socket for sending label update requests to
 *                  the tagger.
 *  @return A pointer to the newly create report merging state.
 */
void *corsaro_report_init_merging(corsaro_plugin_t *p, int sources) {

    corsaro_report_merge_state_t *m;
    corsaro_report_config_t *conf;

    conf = (corsaro_report_config_t *)(p->config);

    m = (corsaro_report_merge_state_t *)calloc(1,
            sizeof(corsaro_report_merge_state_t));
    if (m == NULL) {
        corsaro_log(p->logger,
                "corsaro_report_init_merging: out of memory while allocating merge state.");
        return NULL;
    }

    m->last_label_update = 0;

    if (conf->outformat == CORSARO_OUTPUT_AVRO) {
        m->writer = corsaro_create_avro_writer(p->logger, REPORT_RESULT_SCHEMA);
        if (m->writer == NULL) {
            corsaro_log(p->logger,
                    "error while creating avro writer for report plugin!");
            free(m);
            return NULL;
        }
    } else {
        m->writer = NULL;
    }

    if (conf->outformat == CORSARO_OUTPUT_LIBTIMESERIES) {
        m->timeseries = timeseries_init();
        if (m->timeseries == NULL) {
            corsaro_log(p->logger,
                    "unable to initialize libtimeseries");
            free(m);
            return NULL;
        }

		if (enable_libts_ascii_backend(p->logger, m->timeseries,
                conf->basic.libtsascii)) {
            corsaro_log(p->logger, "skipping libtimeseries ascii output");
        }
        if (enable_libts_kafka_backend(p->logger, m->timeseries,
                conf->basic.libtskafka)) {
            corsaro_log(p->logger, "skipping libtimeseries kafka output");
        }
        if (enable_libts_dbats_backend(p->logger, m->timeseries,
                conf->basic.libtsdbats)) {
            corsaro_log(p->logger, "skipping libtimeseries DBATS output");
        }

        m->kp = timeseries_kp_init(m->timeseries, TIMESERIES_KP_RESET);
        if (m->kp == NULL) {
            corsaro_log(p->logger,
                    "unable to initialize libtimeseries key package");
            timeseries_free(&(m->timeseries));
            free(m);
            return NULL;
        }

    } else {
        m->timeseries = NULL;
        m->kp = NULL;
    }

    m->metrickp_keys = (Pvoid_t) NULL;
    m->country_labels = (Pvoid_t) NULL;
    m->region_labels = (Pvoid_t) NULL;
    m->polygon_labels = (Pvoid_t) NULL;

    return m;
}

/** Tidies up the internal state used by the merging thread to combine
 *  results from the report plugin.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param local        The merge thread state for this plugin
 *  @return 0 if successful, -1 if an error occurs.
 */
int corsaro_report_halt_merging(corsaro_plugin_t *p, void *local) {
    corsaro_report_merge_state_t *m;
    Word_t judyret;

    m = (corsaro_report_merge_state_t *)local;
    if (m == NULL) {
        return 0;
    }

    if (m->writer) {
        corsaro_destroy_avro_writer(m->writer);
    }

    if (m->kp) {
        timeseries_kp_free(&(m->kp));
    }

    if (m->timeseries) {
        timeseries_free(&(m->timeseries));
    }

    JLFA(judyret, m->metrickp_keys);
    corsaro_free_ipmeta_label_map(m->country_labels, 1);
    corsaro_free_ipmeta_label_map(m->region_labels, 1);
    corsaro_free_ipmeta_label_map(m->polygon_labels, 1);

    free(m);
    return 0;
}

static int receive_label_update(void *zmq_taggersock, zmq_msg_t *frame,
		corsaro_logger_t *logger) {
    int attempts = 0;
	zmq_msg_init(frame);

	/* If we don't get a response within a second, assume the tagger is
	 * too busy -- skip the update and try again next time.
	 */
	while (attempts < 10) {
		if (zmq_msg_recv(frame, zmq_taggersock, ZMQ_DONTWAIT) < 0) {
			if (errno == EAGAIN) {
				attempts ++;
				usleep(100000);
				continue;
			}

			corsaro_log(logger, "unable to receive IPmeta update from corsarotagger: %s", strerror(errno));
			return -1;
		}
		break;
	}

	if (attempts >= 10) {
		corsaro_log(logger, "failed to get ipmeta label response in reasonable time frame");
		return -1;
	}
    return 0;
}

static uint16_t process_single_label_update(
		corsaro_report_merge_state_t *state, char *buffer) {

	corsaro_tagger_label_hdr_t *hdr;
	char *labelstr;
	uint32_t index;
    uint16_t labellen;

	hdr = (corsaro_tagger_label_hdr_t *)buffer;
	labellen = ntohs(hdr->label_len);
	labelstr = calloc(labellen + 1, sizeof(char));

	/* TODO actually make this work for regions and/or polygons */
	memcpy(labelstr, buffer + sizeof(corsaro_tagger_label_hdr_t),
			labellen);

	index = ntohl(hdr->subject_id);

	if (hdr->subject_type == TAGGER_LABEL_COUNTRY) {
		INSERT_IPMETA_LABEL(state->country_labels, index, labelstr);
	}
	if (hdr->subject_type == TAGGER_LABEL_POLYGON) {
		INSERT_IPMETA_LABEL(state->polygon_labels, index, labelstr);
	}
	if (hdr->subject_type == TAGGER_LABEL_REGION) {
		INSERT_IPMETA_LABEL(state->region_labels, index, labelstr);
	}

	return labellen;
}
/** Asks the tagger for an updated set of FQ labels for each geo-tagged
 *  country, region and polygon.
 *
 *  @param state    Local state for the merging thread
 *  @param logger   A reference to a corsaro logger for error reporting.
 *
 *  @return -1 if an error occurs, 1 otherwise.
 */
static int update_ipmeta_labels(corsaro_report_merge_state_t *state,
        corsaro_logger_t *logger, void *zmq_taggersock) {

    corsaro_tagger_control_request_t req;
    corsaro_tagger_control_reply_t *reply;
    zmq_msg_t frame;
    char *buffer;
    int buflen;
    int firstpass = 1;
    int iserr = 0;
    uint32_t tocome = 0;
    int more;
    size_t more_size;

    req.request_type = TAGGER_REQUEST_IPMETA_UPDATE;
    req.data.last_version = htonl(state->last_label_update);

    if (zmq_taggersock == NULL) {
        return -1;
    }

    if (zmq_send(zmq_taggersock, &req, sizeof(req), 0) < 0) {
        corsaro_log(logger, "unable to send IPmeta update request to corsarotagger: %s", strerror(errno));
        return -1;
    }

	do {
		if (receive_label_update(zmq_taggersock, &frame, logger) < 0) {
			zmq_msg_close(&frame);
			return -1;
		}

        buffer = zmq_msg_data(&frame);
        buflen = zmq_msg_size(&frame);

        /* Reply may be spread over multiple messages... */
        if (firstpass) {
            reply = (corsaro_tagger_control_reply_t *)buffer;

            state->last_label_update = ntohl(reply->ipmeta_version);
            tocome = ntohl(reply->label_count);
            firstpass = 0;

            buffer += sizeof(corsaro_tagger_control_reply_t);
            buflen -= sizeof(corsaro_tagger_control_reply_t);
        }

        while (buflen > 0) {
            uint16_t labellen;

            if (buflen < sizeof(corsaro_tagger_label_hdr_t)) {
                corsaro_log(logger, "parsing error in received IPmeta update -- %d bytes left over in message, need at least %d",
                        buflen, sizeof(corsaro_tagger_label_hdr_t));
                goto drainmessage;
            }
			labellen = process_single_label_update(state, buffer);


            buffer += (sizeof(corsaro_tagger_label_hdr_t) + labellen);
            buflen -= (sizeof(corsaro_tagger_label_hdr_t) + labellen);

        }

        more_size = sizeof(more);
        if (zmq_getsockopt(zmq_taggersock, ZMQ_RCVMORE, &more,
                    &more_size) < 0) {
            corsaro_log(logger, "error while checking for more IPmeta update content: %s", strerror(errno));
            return -1;
        }

        zmq_msg_close(&frame);
    } while (more);

    return 1;

drainmessage:
    /* Something went wrong with our IPmeta label parsing, so try to drain
     * any remaining message parts from the queue before returning an error
     * code.
     */

    zmq_msg_close(&frame);
    if (zmq_getsockopt(zmq_taggersock, ZMQ_RCVMORE, &more,
                &more_size) < 0) {
        corsaro_log(logger, "error while draining bad IPmeta update content: %s", strerror(errno));
        return -1;
    }

    while (more) {
        zmq_msg_init(&frame);
        if (zmq_msg_recv(zmq_taggersock, &frame, 0) < 0) {
            corsaro_log(logger, "unable to receive IPmeta update from corsarotagger: %s", strerror(errno));
            break;
        }

        if (zmq_getsockopt(zmq_taggersock, ZMQ_RCVMORE, &more,
                    &more_size) < 0) {
            corsaro_log(logger, "error while draining bad IPmeta update content: %s", strerror(errno));
            break;
        }
    }
    zmq_msg_close(&frame);
    return -1;
}

/** Merge the metric tallies for a given interval into a single combined
 *  result and write it to our Avro output file.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param local        The merge thread state for this plugin
 *  @param tomerge      An array of interim results from each of the packet
 *                      processing threads.
 *  @param fin          The interval that has just been completed.
 *  @return 0 if the merge is successful, -1 if an error occurs.
 */
int corsaro_report_merge_interval_results(corsaro_plugin_t *p, void *local,
        void **tomerge, corsaro_fin_interval_t *fin, void *tagsock) {

    corsaro_report_config_t *conf, *procconf;
    corsaro_report_merge_state_t *m;
    int i, reloadsock = 0;
    Pvoid_t results = NULL;
    uint8_t *trackers_done;
    uint8_t totaldone = 0, skipresult = 0;
    int mergeret;

    uint32_t subtrees_seen = 0;

    m = (corsaro_report_merge_state_t *)local;
    if (m == NULL) {
        return CORSARO_MERGE_BAD_ARGUMENTS;
    }

    /* Plugin result data is NULL, must be a partial interval */
    if (tomerge[0] == NULL) {
        return CORSARO_MERGE_NO_ACTION;
    }

    conf = (corsaro_report_config_t *)(p->config);
    /* Now would be a good time to make sure we have a copy of all of the
     * IPmeta labels that we need...
     */
    if (conf->query_tagger_labels && update_ipmeta_labels(m, p->logger,
            tagsock) < 0) {
        corsaro_log(p->logger, "unable to fetch labels for IPmeta metrics: metric names may not be up to date...");
        reloadsock = 1;
    }

    /* All of the interim results should point at the same config, so we
     * only care about tomerge[0].
     *
     * Note that we can't use p->config to get at the IP trackers because
     * the plugin instance 'p' does NOT point at the same plugin instance
     * that was used to run the processing threads.
     */
    procconf = ((corsaro_report_interim_t *)(tomerge[0]))->baseconf;

    trackers_done = (uint8_t *)calloc(procconf->tracker_count, sizeof(uint8_t));

    if (initialise_results(p, &results, fin->timestamp) < 0) {
        return CORSARO_MERGE_BAD_ARGUMENTS;
    }

    do {
        /* The IP tracker threads may not have finished processing all of their
         * outstanding updates for the interval just yet, so we need to
         * keep polling until all of the trackers have finalised their
         * results for this interval.
         */
        for (i = 0; i < procconf->tracker_count; i++) {
            if (trackers_done[i]) {
                continue;
            }

            /* If we can't get the lock, try another tracker thread */
            if (pthread_mutex_trylock(&(procconf->iptrackers[i].mutex)) == 0) {
                if (procconf->iptrackers[i].lastresultts > fin->timestamp) {
                    trackers_done[i] = 1;
                    totaldone ++;
                    skipresult = 1;
                } else if (procconf->iptrackers[i].lastresultts ==
                        fin->timestamp) {
                    update_tracker_results(&results, &(procconf->iptrackers[i]),
                            fin->timestamp, conf, &subtrees_seen, p->logger);
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
        /* Some tracker threads were either busy or still waiting for
         * an interval end message, take a quick break then try again.
         */
        if (totaldone < procconf->tracker_count) {
            usleep(100);
        }
    } while (totaldone < procconf->tracker_count);

    free(trackers_done);

    if (skipresult) {
        /* This result is invalid because not all of the tracker threads
         * were able to produce a result (due to being interrupted).
         * Don't try writing it to the avro output to avoid being
         * misleading.
         */
        clean_result_map(&results);
        mergeret = CORSARO_MERGE_NO_ACTION;
    } else {

        /* All trackers have reported tallies for this interval and they've
         * been merged into a single result -- write it out!
         */
        if (conf->outformat == CORSARO_OUTPUT_AVRO) {
            if (report_write_avro_output(p, m, fin->timestamp, &results,
                    subtrees_seen) < 0) {
                return CORSARO_MERGE_WRITE_FAILED;
            }
        }

        if (conf->outformat == CORSARO_OUTPUT_LIBTIMESERIES) {
            if (report_write_libtimeseries(p, m, fin->timestamp, &results,
                    subtrees_seen) < 0) {
                return CORSARO_MERGE_WRITE_FAILED;
            }
        }
        mergeret = CORSARO_MERGE_SUCCESS;
    }

    for (i = 0; i < fin->threads_ended; i++) {
        free(tomerge[i]);
    }

    if (reloadsock) {
        return CORSARO_MERGE_CONTROL_FAILURE;
    }
    return mergeret;
}

/** Rotates the output file for the report plugin.
 *
 *  @param p            A reference to the running instance of the report plugin
 *  @param local        The merge thread state for this plugin
 *  @return 0 if the file rotation was successful, -1 if an error occurs.
 */
int corsaro_report_rotate_output(corsaro_plugin_t *p, void *local) {

    corsaro_report_merge_state_t *m;
    corsaro_report_config_t *conf;

    conf = (corsaro_report_config_t *)(p->config);
    m = (corsaro_report_merge_state_t *)local;
    if (m == NULL) {
        return -1;
    }

    if (conf->outformat == CORSARO_OUTPUT_AVRO) {
        /* Nothing complicated here, just close the current Avro writer. We'll
         * create a new one (along with a new output file) the next time we have
         * a complete set of results for an interval that needs to be written.
         */
        if (m->writer == NULL || corsaro_close_avro_writer(m->writer) < 0) {
            return -1;
        }
    }

    return 0;
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
