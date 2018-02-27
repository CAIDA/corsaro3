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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include <wandio.h>

#include "libcorsaro3_io.h"
#include "libcorsaro3_log.h"
#include "libcorsaro3.h"
#include "wandio_utils.h"

/** The string to prefix file names with when creating trace files */
#define CORSARO_FILE_TRACE_FORMAT "pcapfile:"

/** The string that is assumed to be at the start of any corsaro ASCII file */
#define CORSARO_FILE_ASCII_CHECK "# CORSARO"

/** The string that is assumed to be at the start of any corsaro binary file */
#define CORSARO_FILE_BINARY_CHECK "EDGR"



corsaro_file_t *corsaro_file_open(corsaro_logger_t *logger, char *fname,
        corsaro_file_mode_t mode, corsaro_file_compress_t compress_type,
        int compress_level, int flags) {

    corsaro_file_t *f = NULL;

    size_t flen, rlen, len;
    char *ptr, *traceuri;

    if ((f = malloc(sizeof(corsaro_file_t))) == NULL) {
        corsaro_log(logger, "could not malloc new corsaro_file_t");
        return NULL;
    }

    f->mode = mode;
    f->filename = fname;

    /* did they ask for a libtrace file? */
    switch (mode) {
        case CORSARO_FILE_MODE_TRACE:
            flen = strlen(CORSARO_FILE_TRACE_FORMAT);
            rlen = strlen(fname);
            len = flen + rlen + 1;
            if ((ptr = traceuri = malloc(len)) == NULL) {
                corsaro_log(logger, "could not malloc traceuri");
                return NULL;
            }
            strncpy(traceuri, CORSARO_FILE_TRACE_FORMAT, flen);
            ptr += flen;
            strncpy(ptr, fname, rlen);
            traceuri[len - 1] = '\0';
            f->trace_io = trace_create_output(traceuri);
            free(traceuri);

            if (trace_is_err_output(f->trace_io)) {
                corsaro_log(logger, "trace_create_output failed for %s",
                        fname);
                return NULL;
            }
            if (trace_config_output(f->trace_io, TRACE_OPTION_OUTPUT_COMPRESS,
                        &compress_level) ||
                    trace_config_output(f->trace_io, TRACE_OPTION_OUTPUT_COMPRESSTYPE,
                        &compress_type) != 0) {
                corsaro_log(logger,
                        "could not set compression levels for trace");
                return NULL;
            }
            if (trace_start_output(f->trace_io) == -1) {
                corsaro_log(logger, "trace_start_output failed for %s",
                        fname);
                return NULL;
            }
            /* trace is configured! */
            break;
        case CORSARO_FILE_MODE_ASCII:
        case CORSARO_FILE_MODE_BINARY:
            if ((f->wand_io = wandio_wcreate(fname, compress_type,
                        compress_level, flags)) == NULL) {
                corsaro_log(logger, "wandio could not create file %s",
                        fname);
                free(f);
                return NULL;
            }
            break;

        default:
            corsaro_log(logger, "invalid file mode %d", mode);
            free(f);
            return NULL;
    }

    return f;
}

void corsaro_file_close(corsaro_file_t *file)
{
    switch (file->mode) {
        case CORSARO_FILE_MODE_ASCII:
        case CORSARO_FILE_MODE_BINARY:
            /* close the wandio object */
            assert(file->wand_io != NULL);
            wandio_wdestroy(file->wand_io);
            file->wand_io = NULL;
            break;

        case CORSARO_FILE_MODE_TRACE:
            assert(file->trace_io != NULL);
            trace_destroy_output(file->trace_io);
            file->trace_io = NULL;
            break;

        default:
            assert(0);
    }

    if (file->filename) {
        free(file->filename);
    }
    free(file);
    return;
}


off_t corsaro_file_vprintf(corsaro_file_t *file, const char *format,
        va_list args) {
    /* let's not try and print text to a libtrace file... */
    assert(file != NULL);
    assert(file->mode == CORSARO_FILE_MODE_ASCII ||
            file->mode == CORSARO_FILE_MODE_BINARY ||
            file->mode == CORSARO_FILE_MODE_UNKNOWN);
    assert(file->wand_io != NULL);

    return wandio_vprintf(file->wand_io, format, args);
}

off_t corsaro_file_printf(corsaro_file_t *file, const char *format, ...)
{
    off_t ret;
    va_list ap;

    va_start(ap, format);
    ret = corsaro_file_vprintf(file, format, ap);
    va_end(ap);
    return ret;
}

off_t corsaro_file_write(corsaro_file_t *file, const void *buffer,
        off_t len) {
    /* let's not try and write raw bytes to a libtrace file... */
    assert(file->mode == CORSARO_FILE_MODE_ASCII ||
            file->mode == CORSARO_FILE_MODE_BINARY ||
            file->mode == CORSARO_FILE_MODE_UNKNOWN);
    assert(file->wand_io != NULL);

    return wandio_wwrite(file->wand_io, buffer, len);
}

off_t corsaro_file_write_interval(corsaro_file_t *file,
        corsaro_interval_t *interval, uint8_t isstart) {

    if (file->mode == CORSARO_FILE_MODE_BINARY) {
        corsaro_interval_t nint;
        /* byte flip all the fields */
        nint.corsaro_magic = htonl(interval->corsaro_magic);
        nint.magic = htonl(interval->magic);
        nint.number = htons(interval->number);
        nint.time = htonl(interval->time);

        return wandio_wwrite(file->wand_io, &nint, sizeof(corsaro_interval_t));
    } else if (file->mode == CORSARO_FILE_MODE_ASCII && isstart) {
        return corsaro_file_printf(file, "# CORSARO_INTERVAL_START %d %ld\n",
                interval->number, interval->time);
    } else if (file->mode == CORSARO_FILE_MODE_ASCII) {
        return corsaro_file_printf(file, "# CORSARO_INTERVAL_END %d %ld\n",
                interval->number, interval->time);
    }

    /* Not a valid output type for writing intervals? */
    return -1;
}

int corsaro_file_read_ascii_interval(char *ascline,
        corsaro_interval_t *interval, corsaro_logger_t *logger) {

    char intervalstr[128];
    uint32_t intnum;
    uint32_t intts;
    int restype = -1;

    /* Interval marker */
    if (sscanf(ascline, "# %s %u %u", intervalstr, &intnum, &intts) != 3) {
        corsaro_log(logger,
                "poorly formatted interval line: %s",
                ascline);
        return -1;
    }

    if (strcmp(intervalstr, "CORSARO_INTERVAL_START") == 0) {
        restype = 1;
    } else if (strcmp(intervalstr, "CORSARO_INTERVAL_END") == 0) {
        restype = 0;
    } else {
        corsaro_log(logger,
                "unexpected interval marker %s in output.",
                intervalstr);
        return -1;
    }

    interval->number = intnum;
    interval->time = intts;
    interval->corsaro_magic = CORSARO_MAGIC;
    interval->magic = CORSARO_MAGIC_INTERVAL;

    return restype;
}


corsaro_file_in_t *corsaro_file_ropen(corsaro_logger_t *logger, char *fname) {

    corsaro_file_in_t *rf = NULL;
    int len;
    char peekbuf[128];

    rf = (corsaro_file_in_t *)malloc(sizeof(corsaro_file_in_t));

    if (rf == NULL) {
        /* OOM */
        corsaro_log(logger, "failed to allocate memory for corsaro_file_in_t.");
        goto ropen_fail;
    }

    rf->mode = CORSARO_FILE_MODE_UNKNOWN;
    rf->filename = fname;

    rf->wandio = wandio_create(fname);
    if (rf->wandio == NULL) {
        corsaro_log(logger, "failed to open rfile %s.", fname);
        goto ropen_fail;
    }

    len = wandio_peek(rf->wandio, peekbuf, sizeof(peekbuf));
    if (len >= strlen(CORSARO_FILE_ASCII_CHECK) &&
            memcmp(CORSARO_FILE_ASCII_CHECK, peekbuf,
                    strlen(CORSARO_FILE_ASCII_CHECK)) == 0) {
        rf->mode = CORSARO_FILE_MODE_ASCII;
    } else if (len >= strlen(CORSARO_FILE_BINARY_CHECK) &&
            memcmp(CORSARO_FILE_BINARY_CHECK, peekbuf,
                    strlen(CORSARO_FILE_BINARY_CHECK)) == 0) {
        rf->mode = CORSARO_FILE_MODE_BINARY;
    }

    return rf;

ropen_fail:
    if (rf) {
        free(rf);
    }
    return NULL;
}

void corsaro_file_rclose(corsaro_file_in_t *file) {

    if (file == NULL) {
        return;
    }

    if (file->wandio) {
        wandio_destroy(file->wandio);
    }

    file->wandio = NULL;
    free(file);
}

off_t corsaro_file_rread_ascii_line(corsaro_logger_t *logger,
        corsaro_file_in_t *file, char *line, off_t len) {

    off_t ret;
    if (file->mode != CORSARO_FILE_MODE_ASCII) {
        corsaro_log(logger, "attempted to read a line from a non-ASCII file.");
        return -1;
    }

    if (line == NULL || len <= 0) {
        corsaro_log(logger,
                "line and/or len parameters for corsaro_read_ascii_line() are invalid.");
        return -1;
    }

    if ((ret = wandio_fgets(file->wandio, line, len, 0)) < 0) {
        corsaro_log(logger,
                "wandio has failed to read a line from an ASCII corsaro file.");
    } else if (ret == 0) {
        return ret;
    } else {
        /* Remove the '\n' -- we're mostly using this for parsing */
        if (line[ret - 1] != '\n') {
            printf("%d %d %s:  %02x\n", ret, strlen(line), line, line[ret - 1]);
        }
        assert(line[ret - 1] == '\n');
        line[ret - 1] = '\0';
    }

    return ret;
}

off_t corsaro_file_rread_bytes(corsaro_logger_t *logger,
        corsaro_file_in_t *file, char *buf, off_t len) {

    off_t ret;

    if (file->mode != CORSARO_FILE_MODE_BINARY && file->mode !=
            CORSARO_FILE_MODE_ASCII) {
        corsaro_log(logger,
                "attempted to read bytes from an incompatible file.");
        return 0;
    }

    if (buf == NULL || len <= 0) {
        corsaro_log(logger,
                "buffer and/or len parameters for corsaro_read_bytes() are invalid.");
        return 0;
    }

    if ((ret = wandio_read(file->wandio, buf, len)) < 0) {
        corsaro_log(logger,
                "wandio has failed to read bytes from a corsaro file.");
    }

    return ret;
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

