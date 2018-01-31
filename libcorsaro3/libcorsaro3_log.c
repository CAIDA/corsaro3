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

#define _BSD_SOURCE
#include "config.h"

#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "libcorsaro3_log.h"
/* Yes, I know about the redundancy between this enum and the one
 * in libcorsaro3_log.h -- feel free to fix if it is bothering you.
 */
enum {
    CORSARO_LOG_SYSLOG,
    CORSARO_LOG_STDERR,
    CORSARO_LOG_FILE
};

void corsaro_log(corsaro_logger_t *logger, const char *fmt, ...) {

    va_list ap;
    FILE *out = NULL;
    char bigbuf[2048];

    if (logger == NULL) {
        return;
    }

    va_start(ap, fmt);
    if (logger->mode == CORSARO_LOG_SYSLOG) {
        /* syslog is thread-safe, so skip the mutex */
        if (logger->name) {
            snprintf(bigbuf, sizeof(bigbuf), "[%s] %s", logger->name, fmt);
            vsyslog(LOG_DAEMON, bigbuf, ap);
        } else {
            vsyslog(LOG_DAEMON, fmt, ap);
        }
    } else {
        if (logger->mode == CORSARO_LOG_STDERR) {
            out = stderr;
        } else {
            out = logger->out;
        }
        pthread_mutex_lock(&logger->mutex);
        if (logger->name) {
            fprintf(out, "%s: ", logger->name);
        }
        vfprintf(out, fmt, ap);
        fprintf(out, "\n");
        pthread_mutex_unlock(&logger->mutex);
    }

    va_end(ap);
}

corsaro_logger_t *init_corsaro_logger(char *name, char *fname) {

    corsaro_logger_t *logger = NULL;

    logger = (corsaro_logger_t *)malloc(sizeof(corsaro_logger_t));

    if (logger == NULL) {
        if (name) {
            fprintf(stderr, "%s: unable to allocate memory for logging.\n",
                    name);
        } else {
            fprintf(stderr,
                    "corsaro-logger: unable to allocate memory for logging.\n");
        }
        return NULL;
    }

    logger->out = NULL;
    logger->name = NULL;

    if (fname == NULL) {
        openlog(name, LOG_PID, LOG_DAEMON);
        logger->mode = CORSARO_LOG_SYSLOG;
    } else if (strcmp(fname, "") == 0) {
        logger->mode = CORSARO_LOG_STDERR;
        if (name) {
            logger->name = strdup(name);
        }
    } else {
        logger->out = fopen(fname, "w");
        if (name) {
            logger->name = strdup(name);
        }
        if (logger->out == NULL) {
            if (name) {
                fprintf(stderr, "%s: unable to open %s for logging: %s\n", name,
                        fname, strerror(errno));
            } else {
                fprintf(stderr,
                        "corsaro-logger: unable to open %s for logging: %s\n",
                        fname, strerror(errno));
            }

            free(logger);
            return NULL;
        }
    }

    pthread_mutex_init(&logger->mutex, NULL);

}


void destroy_corsaro_logger(corsaro_logger_t *logger) {

    if (logger == NULL) {
        return;
    }

    if (logger->mode == CORSARO_LOG_SYSLOG) {
        closelog();
    }

    if (logger->out) {
        fclose(logger->out);
    }

    if (logger->name) {
        free(logger->name);
    }
    pthread_mutex_destroy(&logger->mutex);
    free(logger);

}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
