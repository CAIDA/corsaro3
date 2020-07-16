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

#include <stdio.h>
#include <errno.h>
#include <sys/time.h>

#include "libcorsaro_avro.h"
#include "libcorsaro.h"
#include "libcorsaro_log.h"

corsaro_avro_writer_t *corsaro_create_avro_writer(corsaro_logger_t *logger,
        const char *schemadef) {

    corsaro_avro_writer_t *w = (corsaro_avro_writer_t *)malloc(
            sizeof(corsaro_avro_writer_t));

    if (w == NULL) {
        corsaro_log(logger, "unable to allocate memory for Avro writer.");
        return NULL;
    }

    w->schema_string = schemadef;
    if (w->schema_string == NULL) {
        corsaro_log(logger,
                "schema string cannot be NULL!");
        free(w);
        return NULL;
    }

    w->schema = NULL;
    w->out = NULL;
    w->logger = logger;
    w->iface = NULL;

    w->encodespace = NULL;
    w->encodesize = 0;
    w->encodeused = 0;
    return w;

}

corsaro_avro_reader_t *corsaro_create_avro_reader(corsaro_logger_t *logger,
        char *filename) {

    corsaro_avro_reader_t *r = (corsaro_avro_reader_t *)malloc(
            sizeof(corsaro_avro_reader_t));

    if (r == NULL) {
        corsaro_log(logger, "unable to allocate memory for Avro reader.");
        return NULL;
    }

    if (filename == NULL) {
        corsaro_log(logger, "filename for an Avro reader cannot be NULL!");
        free(r);
        return NULL;
    }

    r->schema = NULL;
    r->in = NULL;
    r->logger = logger;
    r->iface = NULL;
    r->filename = filename;



    return r;
}

void corsaro_destroy_avro_writer(corsaro_avro_writer_t *writer) {

    if (writer->schema) {
        avro_schema_decref(writer->schema);
    }

    if (writer->iface) {
        avro_value_iface_decref(writer->iface);
        avro_value_decref(&(writer->value));
    }

    if (writer->out) {
        avro_file_writer_close(writer->out);
    }

    if (writer->encodespace) {
        free(writer->encodespace);
    }

    if (writer->fname) {
        free(writer->fname);
    }

    free(writer);

}

void corsaro_destroy_avro_reader(corsaro_avro_reader_t *reader) {

    if (reader->schema) {
        avro_schema_decref(reader->schema);
    }

    if (reader->iface) {
        avro_value_iface_decref(reader->iface);
        avro_value_decref(&(reader->value));
    }

    if (reader->in) {
        avro_file_reader_close(reader->in);
    }

    free(reader);

}

int corsaro_read_next_avro_record(corsaro_avro_reader_t *reader,
        avro_value_t **av) {

    int ret;

    *av = NULL;
    if (reader->in == NULL) {
        if (avro_file_reader(reader->filename, &(reader->in))) {
            corsaro_log(reader->logger,
                    "unable to open Avro file %s for reading: %s",
                    reader->filename, avro_strerror());
            return -1;
        }

        reader->schema = avro_file_reader_get_writer_schema(reader->in);
        if (reader->schema == NULL) {
            corsaro_log(reader->logger,
                    "had a problem extracting schema from Avro file %s: %s",
                    reader->filename, avro_strerror());
            return -1;
        }

        reader->iface = avro_generic_class_from_schema(reader->schema);
        if (reader->iface == NULL) {
            corsaro_log(reader->logger,
                    "unable to create generic interface from Avro schema: %s",
                    avro_strerror());
            return -1;
        }

        if (avro_generic_value_new(reader->iface, &(reader->value))) {
            corsaro_log(reader->logger,
                    "unable to create generic value for reading Avro: %s",
                    avro_strerror());
            return -1;
        }
    }

    if ((ret = avro_file_reader_read_value(reader->in, &(reader->value)))
                == 0) {
        *av = &(reader->value);
        return 1;
    }

    if (ret == EOF) {
        return 0;
    }

    corsaro_log(reader->logger,
            "error while reading Avro record from file: %s", avro_strerror());
    return -1;
}


int corsaro_close_avro_writer(corsaro_avro_writer_t *writer) {

    if (writer->out == NULL) {
        return 0;
    }

    avro_file_writer_close(writer->out);
    writer->out = NULL;

    char donebuf[1024];
    if (snprintf(donebuf, sizeof(donebuf), "%s.done", writer->fname)
        >= sizeof(donebuf)) {
        corsaro_log(writer->logger, "unable to build .done file name");
        return -1;
    }
    fclose(fopen(donebuf, "w"));
    return 0;
}

int corsaro_is_avro_writer_active(corsaro_avro_writer_t *writer) {
    if (writer->out != NULL) {
        return 1;
    }
    return 0;
}

int corsaro_start_avro_writer(corsaro_avro_writer_t *writer, char *fname,
        uint8_t usesnappy) {

    int ret = -1;
    avro_schema_error_t error;

    if (writer->out != NULL) {
        corsaro_log(writer->logger,
                "attempting to start an Avro writer when it is already open!");
        return -1;
    }

    /* Save file name so we can create a .done file */
    writer->fname = strdup(fname);

    if (writer->schema == NULL) {
        /* Create the schema */
        if (avro_schema_from_json(writer->schema_string,
                    strlen(writer->schema_string),
                    &(writer->schema), &error)) {
            corsaro_log(writer->logger,
                    "unable to parse Avro schema string: %s",
                    avro_strerror());
            return -1;
        }
    }

    /* I assume a block size of zero just uses the default?? */


    if (usesnappy) {

        /* Try snappy first, as that is faster (albeit with a worse ratio).
         * If snappy fails, i.e. libavro was built without snappy support,
         * then fall back to deflate.
         */
        ret = avro_file_writer_create_with_codec(fname, writer->schema,
                &(writer->out), "snappy", 16 * 1024);
    }

    if (ret) {
        ret = avro_file_writer_create_with_codec(fname, writer->schema,
                &(writer->out), "deflate", 16 * 1024);
    }

    if (ret) {
        corsaro_log(writer->logger,
                "error opening Avro output file %s: %s", fname,
                avro_strerror());
        return -1;
    }

    return 0;
}

#define CORSARO_INIT_AVRO_ENCODING_SPACE (8096)

int corsaro_start_avro_encoding(corsaro_avro_writer_t *writer) {

    if (writer->encodespace == NULL) {
        writer->encodespace = (char *)malloc(CORSARO_INIT_AVRO_ENCODING_SPACE);
        writer->encodesize = CORSARO_INIT_AVRO_ENCODING_SPACE;
    }

    writer->encodeused = 0;
    if (writer->encodespace == NULL) {
        return -1;
    }
    return 0;
}

static inline void grow_encode_buffer(corsaro_avro_writer_t *writer) {
    writer->encodespace = (char *)realloc(writer->encodespace,
                writer->encodesize + CORSARO_INIT_AVRO_ENCODING_SPACE);
    writer->encodesize += CORSARO_INIT_AVRO_ENCODING_SPACE;
}

int corsaro_encode_avro_field(corsaro_avro_writer_t *writer,
        uint8_t fieldtype, void *fieldptr, uint32_t fieldlen) {

    if (fieldtype == CORSARO_AVRO_LONG) {
        int64_t l;
        uint64_t n;

        if (fieldlen == 1) {
            l = *(uint8_t *)(fieldptr);
        } else if (fieldlen == 2) {
            l = *(uint16_t *)(fieldptr);
        } else if (fieldlen == 4) {
            l = *(uint32_t *)(fieldptr);
        } else if (fieldlen == 8) {
            l = *(uint64_t *)(fieldptr);
        } else {
            corsaro_log(writer->logger,
                    "unexpected integer size of %u when encoding avro.",
                    fieldlen);
            return -1;
        }

        if (writer->encodesize - writer->encodeused < 8) {
            grow_encode_buffer(writer);
        }

        n = (l << 1) ^ (l >> 63);

        while (n & ~0x7F) {
            writer->encodespace[writer->encodeused] = 
                    (char)((((uint8_t) n) & 0x7F) | 0x80);
            n >>= 7;
            writer->encodeused ++;
        }
        writer->encodespace[writer->encodeused] = (char)n;
        writer->encodeused ++;
    } else if (fieldtype == CORSARO_AVRO_STRING) {
        if (corsaro_encode_avro_field(writer, CORSARO_AVRO_LONG, &fieldlen,
                sizeof(fieldlen)) < 0) {
            corsaro_log(writer->logger,
                    "unable to encode length of avro string.");
            return -1;
        }

        if (writer->encodesize - writer->encodeused < fieldlen) {
            grow_encode_buffer(writer);
        }
        memcpy(writer->encodespace + writer->encodeused, fieldptr, fieldlen);
        writer->encodeused += fieldlen;
    } else {
        corsaro_log(writer->logger,
                "asked to encode unexpected avro type %u\n", fieldtype);
        return -1;
    }
    return 0;
}

avro_value_t *corsaro_populate_avro_item(corsaro_avro_writer_t *writer,
        void *plugindata,
        int (*callback)(corsaro_logger_t *logger, avro_value_t *av,
                void *plugindata)) {

    if (writer->iface == NULL) {
        writer->iface = avro_generic_class_from_schema(writer->schema);

        if (writer->iface == NULL) {
            corsaro_log(writer->logger,
                    "unable to allocate memory for Avro output interface.");
            return NULL;
        }

        if (avro_generic_value_new(writer->iface, &(writer->value))) {
            corsaro_log(writer->logger,
                    "unable to create Avro 'value' for output record: %s",
                    avro_strerror());
            return NULL;
        }

    }

    if (callback(writer->logger, &(writer->value), plugindata) == -1) {
        return NULL;
    }

    return &(writer->value);

}

int corsaro_append_avro_writer(corsaro_avro_writer_t *writer,
        avro_value_t *value) {

    int ret = 0;
    errno = 0;

    if (value == NULL) {
        if (avro_file_writer_append_encoded(writer->out, writer->encodespace,
                    writer->encodeused)) {
            corsaro_log(writer->logger,
                    "Unable to append encoded user record to Avro output file: %s",
                    avro_strerror());
            ret = -1;
        }
    } else {
        if (avro_file_writer_append_value(writer->out, value)) {
            corsaro_log(writer->logger,
                    "Unable to encode user record for Avro output file: %s",
                    avro_strerror());
            ret = -1;
        }
    }

    if (errno != 0) {
        corsaro_log(writer->logger,
                "Error detected while writing user record to Avro output: %s",
                strerror(errno));
        ret = -1;
    }

    return ret;
}

static char *stradd(const char *str, char *bufp, char *buflim)
{
    while (bufp < buflim && (*bufp = *str++) != '\0') {
        ++bufp;
    }
    return bufp;
}

char *corsaro_generate_avro_file_name(const char *template,
        const char *plugin,
        const char *monitorname,
        uint32_t time,
        int threadid)
{
    /* some of the structure of this code is borrowed from the
       FreeBSD implementation of strftime */

    /* the output buffer */
    /* @todo change the code to dynamically realloc this if we need more
       space */
    char buf[1024];
    char tbuf[1024];
    char *bufp = buf;
    char *buflim = buf + sizeof(buf);

    /* cast away const, but we don't modify the buffer */
    char *tmpl = (char*)template;
    char secs[11]; /* length of UINT32_MAX +1 */
    struct timeval tv;

    if (template == NULL) {
        return NULL;
    }


    for (; *tmpl; ++tmpl) {
        if (*tmpl == '%') {
            switch (*++tmpl) {
                case '\0':
                    --tmpl;
                    break;

                    /* BEWARE: if you add a new pattern here, you must also add
                     * it to corsaro_io_template_has_timestamp */

                case CORSARO_IO_MONITOR_PATTERN:
                    if (monitorname == NULL) {
                        return NULL;
                    }
                    bufp = stradd(monitorname, bufp, buflim);
                    continue;

                case CORSARO_IO_PLUGIN_PATTERN:
                    if (plugin == NULL) {
                        return NULL;
                    }
                    bufp = stradd(plugin, bufp, buflim);
                    continue;

                case 's':
                    snprintf(secs, sizeof(secs), "%" PRIu32, time);
                    bufp = stradd(secs, bufp, buflim);
                    continue;
                    /* fall through */
                default:
                    /* we want to be generous and leave non-recognized formats
                       intact - especially for strftime to use */
                    --tmpl;
            }
        }
        if (bufp == buflim)
            break;
        *bufp++ = *tmpl;
    }

    if (bufp >= buflim) {
        /* Not enough space for the full filename */
        return NULL;
    }

    bufp = stradd(".avro", bufp, buflim);
    if (bufp >= buflim) {
        /* Not enough space for the full filename */
        return NULL;
    }

    if (threadid >= 0) {
        char thspace[1024];
        snprintf(thspace, 1024, "--%d", threadid);
        bufp = stradd(thspace, bufp, buflim);
    }
    if (bufp >= buflim) {
        /* Not enough space for the full filename */
        return NULL;
    }

    *bufp = '\0';

    /* now let strftime have a go */
    tv.tv_sec = time;
    strftime(tbuf, sizeof(tbuf), buf, gmtime(&tv.tv_sec));
    return strdup(tbuf);
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
