/*
 * corsaro
 *
 * Alistair King, CAIDA, UC San Diego
 * Shane Alcock, WAND, University of Waikato
 *
 * corsaro-info@caida.org
 *
 * Copyright (C) 2012-2021 The Regents of the University of California.
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

#include "config.h"
#include <assert.h>

#include "libcorsaro_flowtuple.h"
#include "libcorsaro_avro.h"
#include "libcorsaro_log.h"
#include <libipmeta.h>

void encode_flowtuple_as_avro(struct corsaro_flowtuple_data *ft,
        corsaro_avro_writer_t *writer, corsaro_logger_t *logger) {

    char valspace[128];
    uint32_t zero = 0;

    if (corsaro_start_avro_encoding(writer) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->interval_ts), sizeof(ft->interval_ts)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->src_ip), sizeof(ft->src_ip)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->dst_ip), sizeof(ft->dst_ip)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->src_port), sizeof(ft->src_port)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->dst_port), sizeof(ft->dst_port)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->protocol), sizeof(ft->protocol)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->ttl), sizeof(ft->ttl)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->tcp_flags), sizeof(ft->tcp_flags)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->ip_len), sizeof(ft->ip_len)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->tcp_synlen), sizeof(ft->tcp_synlen)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->tcp_synwinlen), sizeof(ft->tcp_synwinlen)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->packet_cnt), sizeof(ft->packet_cnt)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->is_spoofed), sizeof(ft->is_spoofed)) < 0) {
        return;
    }

    if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                &(ft->is_masscan), sizeof(ft->is_masscan)) < 0) {
        return;
    }

    assert(ft->tagproviders != 0);

    if (ft->tagproviders & (1 << IPMETA_PROVIDER_MAXMIND)) {
        valspace[0] = (char)(ft->maxmind_continent & 0xff);
        valspace[1] = (char)((ft->maxmind_continent >> 8) & 0xff);
        valspace[2] = '\0';

        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                    valspace, 2) < 0) {
            return;
        }

        valspace[0] = (char)(ft->maxmind_country & 0xff);
        valspace[1] = (char)((ft->maxmind_country >> 8) & 0xff);
        valspace[2] = '\0';

        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                    valspace, 2) < 0) {
            return;
        }

    } else {
        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                "??", 2) < 0) {
            return;
        }
        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                "??", 2) < 0) {
            return;
        }
    }


    if (ft->tagproviders & (1 << IPMETA_PROVIDER_NETACQ_EDGE)) {
        valspace[0] = (char)(ft->netacq_continent & 0xff);
        valspace[1] = (char)((ft->netacq_continent >> 8) & 0xff);
        valspace[2] = '\0';

        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                    valspace, 2) < 0) {
            return;
        }

        valspace[0] = (char)(ft->netacq_country & 0xff);
        valspace[1] = (char)((ft->netacq_country >> 8) & 0xff);
        valspace[2] = '\0';

        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                    valspace, 2) < 0) {
            return;
        }

    } else {
        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                "??", 2) < 0) {
            return;
        }
        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_STRING,
                "??", 2) < 0) {
            return;
        }
    }

    if (ft->tagproviders & (1 << IPMETA_PROVIDER_PFX2AS)) {
        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                    &(ft->prefixasn), sizeof(ft->prefixasn)) < 0) {
            return;
        }

    } else {
        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG,
                    &(zero), sizeof(zero)) < 0) {
            return;
        }
    }
}

/** Decodes an avro flowtuple record back into the corsaro flowtuple struct.
 *
 *  Used by corsaroftmerge, so don't remove this just because it isn't called
 *  in this source file!
 *
 *  @param record       The avro record to be decoded
 *  @param ft           The corsaro flowtuple structure to populate with the
 *                      decoded field contents.
 *
 *  @return 1 on success
 */
int decode_flowtuple_from_avro(avro_value_t *record,
        struct corsaro_flowtuple_data *ft) {

    avro_value_t av;
    int32_t tmp32;
    int64_t tmp64;
    const char *str = NULL;
    size_t strsize = 0;

    /* TODO error detection and handling... */

    avro_value_get_by_index(record, 0, &av, NULL);
    avro_value_get_long(&av, &(tmp64));
    ft->interval_ts = (uint32_t)tmp64;
    avro_value_get_by_index(record, 1, &av, NULL);
    avro_value_get_long(&av, &(tmp64));
    ft->src_ip = (uint32_t)tmp64;

    avro_value_get_by_index(record, 2, &av, NULL);
    avro_value_get_long(&av, &(tmp64));
    ft->dst_ip = (uint32_t)tmp64;

    avro_value_get_by_index(record, 3, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->src_port = (uint16_t)tmp32;

    avro_value_get_by_index(record, 4, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->dst_port = (uint16_t)tmp32;

    avro_value_get_by_index(record, 5, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->protocol = (uint8_t)tmp32;

    avro_value_get_by_index(record, 6, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->ttl = (uint8_t)tmp32;

    avro_value_get_by_index(record, 7, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->tcp_flags = (uint8_t)tmp32;

    avro_value_get_by_index(record, 8, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->ip_len = (uint16_t)tmp32;

    avro_value_get_by_index(record, 9, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->tcp_synlen = (uint16_t)tmp32;

    avro_value_get_by_index(record, 10, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->tcp_synwinlen = (uint16_t)tmp32;

    avro_value_get_by_index(record, 11, &av, NULL);
    avro_value_get_long(&av, &(tmp64));
    ft->packet_cnt = (uint32_t)tmp64;

    avro_value_get_by_index(record, 12, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->is_spoofed = (uint8_t)tmp32;

    avro_value_get_by_index(record, 13, &av, NULL);
    avro_value_get_int(&av, &(tmp32));
    ft->is_masscan = (uint8_t)tmp32;

    avro_value_get_by_index(record, 14, &av, NULL);
    avro_value_get_string(&av, &str, &strsize);
    assert(strsize == 2);
    ft->maxmind_continent = (uint16_t)(str[0]) + (((uint16_t)str[1]) << 8);

    avro_value_get_by_index(record, 15, &av, NULL);
    avro_value_get_string(&av, &str, &strsize);
    assert(strsize == 2);
    ft->maxmind_country = (uint16_t)(str[0]) + (((uint16_t)str[1]) << 8);

    avro_value_get_by_index(record, 16, &av, NULL);
    avro_value_get_string(&av, &str, &strsize);
    assert(strsize == 2);
    ft->netacq_continent = (uint16_t)(str[0]) + (((uint16_t)str[1]) << 8);

    avro_value_get_by_index(record, 17, &av, NULL);
    avro_value_get_string(&av, &str, &strsize);
    assert(strsize == 2);
    ft->netacq_country = (uint16_t)(str[0]) + (((uint16_t)str[1]) << 8);


    avro_value_get_by_index(record, 18, &av, NULL);
    avro_value_get_long(&av, &(tmp64));
    ft->prefixasn = (uint32_t)tmp64;

    ft->tagproviders = (1 << IPMETA_PROVIDER_MAXMIND) |
            (1 << IPMETA_PROVIDER_NETACQ_EDGE) |
            (1 << IPMETA_PROVIDER_PFX2AS);

    ft->hash_val = 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
