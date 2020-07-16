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


#ifndef CORSARO_AVRO_H_
#define CORSARO_AVRO_H_

#include "libcorsaro.h"
#include "libcorsaro_log.h"

#include <stdlib.h>
#include <avro.h>

typedef struct corsaro_avro_reader {

    char *filename;
    avro_schema_t schema;
    avro_file_reader_t in;
    avro_value_iface_t *iface;
    avro_value_t value;
    corsaro_logger_t *logger;

} corsaro_avro_reader_t;



typedef struct corsaro_avro_writer {
    const char *schema_string;
    avro_schema_t schema;
    char *fname;
    avro_file_writer_t out;

    char *encodespace;
    uint32_t encodeused;
    uint32_t encodesize;

    avro_value_iface_t *iface;
    avro_value_t value;

    corsaro_logger_t *logger;

} corsaro_avro_writer_t;

enum {
    CORSARO_AVRO_LONG,
    CORSARO_AVRO_STRING,
};

/** Convenience function for generating an output file name based on the given
 *  template string
 *
 * @param template      file name template
 * @param plugin        name of the plugin (used if %P is in the template)
 * @param monitorname   name of the monitor (used if %N is in the template)
 * @param time          the current time (used for strftime formatting)
 * @param threadid      the ID of the thread that is opening this file.
 * @return pointer to a dynamically allocated string with the filename if
 * successful, NULL otherwise
 *
 *
 * If threadid is >= 0, then "--<threadid>" will be appended to the
 * filename.
 *
 * Note: It is the caller's responsibility to free the returned string.
 */
char *corsaro_generate_avro_file_name(const char *template,
        const char *plugin, const char *monitorname, uint32_t time,
        int threadid);

corsaro_avro_writer_t *corsaro_create_avro_writer(corsaro_logger_t *logger,
        const char *schemadef);
void corsaro_destroy_avro_writer(corsaro_avro_writer_t *writer);
avro_value_t *corsaro_populate_avro_item(corsaro_avro_writer_t *writer,
        void *plugindata, int (*callback)(corsaro_logger_t *logger,
            avro_value_t *av, void *plugindata));
int corsaro_start_avro_writer(corsaro_avro_writer_t *writer, char *fname,
        uint8_t usesnappy);
int corsaro_append_avro_writer(corsaro_avro_writer_t *writer,
        avro_value_t *value);
int corsaro_close_avro_writer(corsaro_avro_writer_t *writer);
int corsaro_is_avro_writer_active(corsaro_avro_writer_t *writer);

int corsaro_start_avro_encoding(corsaro_avro_writer_t *writer);
int corsaro_encode_avro_field(corsaro_avro_writer_t *writer,
        uint8_t fieldtype, void *fieldptr, uint32_t fieldlen);

corsaro_avro_reader_t *corsaro_create_avro_reader(corsaro_logger_t *logger,
        char *filename);
void corsaro_destroy_avro_reader(corsaro_avro_reader_t *reader);
int corsaro_read_next_avro_record(corsaro_avro_reader_t *reader,
        avro_value_t **av);


/* Helper functions to simplify Avro population callback functions */
#define CORSARO_AVRO_GET_FIELD_REF(av, f, index, name, plugin) \
    if (avro_value_get_by_index(av, index, &f, NULL) == -1) { \
        corsaro_log(logger, \
                "unable to find '%s' (id %d) field in %s schema: %s", \
                name, index, plugin, avro_strerror()); \
        return -1; \
    }

#define CORSARO_AVRO_SET_FIELD(ftype, av, f, index, name, plugin, val) \
    CORSARO_AVRO_GET_FIELD_REF(av, f, index, name, plugin); \
    if (avro_value_set_##ftype(&f, val) == -1) { \
        corsaro_log(logger, \
                "unable to set '%s' (id %d) field in %s schema: %s", \
                name, index, plugin, avro_strerror()); \
        return -1; \
    }



#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

