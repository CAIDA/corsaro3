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

corsaro_merge_writer_t *corsaro_create_merge_writer(corsaro_plugin_t *p,
        void *local, char *outputfilename, corsaro_output_format_t fmt) {


    corsaro_merge_writer_t *writer;

    writer = (corsaro_merge_writer_t *)malloc(sizeof(corsaro_merge_writer_t));

    writer->fmt = fmt;
    writer->logger = p->logger;

    switch(fmt) {
        case CORSARO_OUTPUT_AVRO:
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
        case CORSARO_OUTPUT_PLUGIN:
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
        case CORSARO_OUTPUT_TRACE:
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
        case CORSARO_OUTPUT_AVRO:
            corsaro_destroy_avro_writer(writer->w.avro);
            break;
        case CORSARO_OUTPUT_PLUGIN:
            p->close_merged_output_file(p, local, writer->w.plugin);
            break;
        case CORSARO_OUTPUT_TRACE:
            corsaro_destroy_trace_writer(writer->w.trace);
            break;

    }
    free(writer);
}

int corsaro_write_next_merge_result(corsaro_merge_writer_t *writer,
        corsaro_plugin_t *p, void *local, corsaro_plugin_result_t *res) {

    if (res->type == CORSARO_RESULT_TYPE_EOF) {
        return 0;
    }

    /* XXX are there any cases where we need to convert between formats?
     * Hopefully not...
     */

    if (res->avrofmt && writer->fmt == CORSARO_OUTPUT_AVRO) {
        return corsaro_append_avro_writer(writer->w.avro, res->avrofmt);
    }

    if (res->pluginfmt && writer->fmt == CORSARO_OUTPUT_PLUGIN) {
        return p->write_result(p, local, res, writer->w.plugin);
    }

    if (res->packet && writer->fmt == CORSARO_OUTPUT_TRACE) {
        return corsaro_write_packet(p->logger, writer->w.trace, res->packet);
    }

    corsaro_log(p->logger, "type mismatch when writing merged %s result",
            p->name);
    return -1;

}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
