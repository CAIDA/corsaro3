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

#include "libcorsaro3_avro.h"
#include "libcorsaro3_mergeapi.h"
#include "libcorsaro3_plugin.h"

corsaro_merge_reader_t *corsaro_create_merge_reader(corsaro_plugin_t *p,
        void *local, char *sourcefilename, corsaro_interim_format_t fmt) {

    corsaro_merge_reader_t *reader;

    reader = (corsaro_merge_reader_t *)malloc(sizeof(corsaro_merge_reader_t));

    reader->fmt = fmt;
    reader->logger = p->logger;

    switch(fmt) {
        case CORSARO_INTERIM_AVRO:
            reader->r.avro = corsaro_create_avro_reader(p->logger,
                    sourcefilename);
            if (reader->r.avro == NULL) {
                corsaro_log(p->logger,
                        "unable to create AVRO reader for %s output.",
                        p->name);
                free(reader);
                return NULL;
            }
            break;
        case CORSARO_INTERIM_PLUGIN:
            reader->r.plugin = p->open_interim_file_reader(p, local,
                    sourcefilename);
            if (reader->r.plugin == NULL) {
                corsaro_log(p->logger,
                        "unable to create merge reader for %s output.",
                        p->name);
                free(reader);
                return NULL;
            }
            break;
        case CORSARO_INTERIM_TRACE:
            reader->r.trace = corsaro_create_trace_reader(p->logger,
                    sourcefilename);
            if (reader->r.trace == NULL) {
                corsaro_log(p->logger,
                        "unable to create packet trace reader for %s output.",
                        p->name);
                free(reader);
                return NULL;
            }
            break;
        default:
            corsaro_log(p->logger, "unknown interim file format %d", fmt);
            free(reader);
            return NULL;
    }

    return reader;
}

void corsaro_close_merge_reader(corsaro_merge_reader_t *reader,
        corsaro_plugin_t *p, void *local) {
    switch(reader->fmt) {
        case CORSARO_INTERIM_AVRO:
            corsaro_destroy_avro_reader(reader->r.avro);
            break;
        case CORSARO_INTERIM_PLUGIN:
            p->close_interim_file(p, local, reader->r.plugin);
            break;
        case CORSARO_INTERIM_TRACE:
            corsaro_destroy_trace_reader(reader->r.trace);
            break;

    }
    free(reader);
}

corsaro_merge_writer_t *corsaro_create_merge_writer(corsaro_plugin_t *p,
        void *local, char *outputfilename, corsaro_interim_format_t fmt) {


    corsaro_merge_writer_t *writer;

    writer = (corsaro_merge_writer_t *)malloc(sizeof(corsaro_merge_writer_t));

    writer->fmt = fmt;
    writer->logger = p->logger;

    switch(fmt) {
        case CORSARO_INTERIM_AVRO:
            writer->w.avro = corsaro_create_avro_writer(p->logger,
                    p->get_avro_schema());
            if (writer->w.avro == NULL) {
                corsaro_log(p->logger,
                        "unable to create avro writer for merged %s output.",
                        p->name);
                free(writer);
                return NULL;
            }
            if (corsaro_start_avro_writer(writer->w.avro, outputfilename)) {
                corsaro_log(p->logger,
                        "unable to start avro writer for merged %s output.",
                        p->name);
                corsaro_destroy_avro_writer(writer->w.avro);
                free(writer);
                return NULL;
            }
            break;
        case CORSARO_INTERIM_PLUGIN:
            writer->w.plugin = p->open_merged_output_file(p, local,
                    outputfilename);
            if (writer->w.plugin == NULL) {
                corsaro_log(p->logger,
                        "unable to create merge writer for %s output.",
                        p->name);
                free(writer);
                return NULL;
            }
            break;
        case CORSARO_INTERIM_TRACE:
            writer->w.trace = corsaro_create_trace_writer(p->logger,
                    outputfilename, CORSARO_TRACE_COMPRESS_LEVEL,
                    CORSARO_TRACE_COMPRESS_METHOD);
            if (writer->w.trace == NULL) {
                corsaro_log(p->logger,
                        "unable to create packet trace writer for %s output.",
                        p->name);
                free(writer);
                return NULL;
            }
            break;
        default:
            corsaro_log(p->logger, "unknown interim file format %d", fmt);
            free(writer);
            return NULL;
    }

    return writer;
}

void corsaro_close_merge_writer(corsaro_merge_writer_t *writer,
        corsaro_plugin_t *p, void *local) {

    switch(writer->fmt) {
        case CORSARO_INTERIM_AVRO:
            corsaro_destroy_avro_writer(writer->w.avro);
            break;
        case CORSARO_INTERIM_PLUGIN:
            p->close_merged_output_file(p, local, writer->w.plugin);
            break;
        case CORSARO_INTERIM_TRACE:
            corsaro_destroy_trace_writer(writer->w.trace);
            break;

    }
    free(writer);
}

int corsaro_read_next_merge_result(corsaro_merge_reader_t *reader,
        corsaro_plugin_t *p, void *local, corsaro_plugin_result_t *res) {

    int ret = -1;

    res->plugin = p;
    res->avrofmt = NULL;
    res->pluginfmt = NULL;
    res->packet = NULL;

    switch(reader->fmt) {
        case CORSARO_INTERIM_AVRO:
            ret = corsaro_read_next_avro_record(reader->r.avro,
                    &(res->avrofmt));
            break;
        case CORSARO_INTERIM_PLUGIN:
            ret = p->read_result(p, local, reader->r.plugin, res);
            break;
        case CORSARO_INTERIM_TRACE:
            res->packet = trace_create_packet();
            ret = corsaro_read_next_packet(p->logger, reader->r.trace,
                    res->packet);
            break;
    }

    if (ret == -1) {
        res->type = CORSARO_RESULT_TYPE_BLANK;
        return -1;
    }

    if (ret == 0) {
        res->type = CORSARO_RESULT_TYPE_EOF;
        return 0;
    }

    res->type = CORSARO_RESULT_TYPE_DATA;
    return 1;
}

int corsaro_write_next_merge_result(corsaro_merge_writer_t *writer,
        corsaro_plugin_t *p, void *local, corsaro_plugin_result_t *res) {

    if (res->type == CORSARO_RESULT_TYPE_EOF) {
        return 0;
    }

    /* XXX are there any cases where we need to convert between formats?
     * Hopefully not...
     */

    if (res->avrofmt && writer->fmt == CORSARO_INTERIM_AVRO) {
        return corsaro_append_avro_writer(writer->w.avro, res->avrofmt);
    }

    if (res->pluginfmt && writer->fmt == CORSARO_INTERIM_PLUGIN) {
        return p->write_result(p, local, res, writer->w.plugin);
    }

    if (res->packet && writer->fmt == CORSARO_INTERIM_TRACE) {
        return corsaro_write_packet(p->logger, writer->w.trace, res->packet);
    }

    corsaro_log(p->logger, "type mismatch when writing merged %s result",
            p->name);
    return -1;

}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
