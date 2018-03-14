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


#ifndef CORSARO_AVRO_H_
#define CORSARO_AVRO_H_

#include "libcorsaro3.h"
#include "libcorsaro3_log.h"

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
    avro_file_writer_t out;
    avro_value_iface_t *iface;
    avro_value_t value;

    corsaro_logger_t *logger;

} corsaro_avro_writer_t;

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
int corsaro_start_avro_writer(corsaro_avro_writer_t *writer, char *fname);
int corsaro_append_avro_writer(corsaro_avro_writer_t *writer,
        avro_value_t *value);
int corsaro_close_avro_writer(corsaro_avro_writer_t *writer);
int corsaro_is_avro_writer_active(corsaro_avro_writer_t *writer);

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

