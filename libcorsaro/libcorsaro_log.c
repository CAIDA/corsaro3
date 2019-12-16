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

#define _BSD_SOURCE
#include "config.h"

#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <math.h>

#include "libcorsaro_log.h"
/* Yes, I know about the redundancy between this enum and the one
 * in libcorsaro_log.h -- feel free to fix if it is bothering you.
 */
enum {
    CORSARO_LOG_SYSLOG,
    CORSARO_LOG_STDERR,
    CORSARO_LOG_FILE
};

void corsaro_log(corsaro_logger_t *logger, const char *fmt, ...) {

    va_list ap;
    FILE *out = NULL;
    char timebuf[1024];
    char bigbuf[4096];
    struct tm *tm_info;
    struct timeval tv;
    int millisec;

    if (logger == NULL) {
        return;
    }

    va_start(ap, fmt);
    if (logger->mode == CORSARO_LOG_SYSLOG) {
        /* syslog is thread-safe, so skip the mutex */
        if (logger->name) {
            snprintf(bigbuf, sizeof(bigbuf), "%s: %s",
                logger->name, fmt);
            vsyslog(LOG_DAEMON | LOG_DEBUG, bigbuf, ap);
        } else {
            vsyslog(LOG_DAEMON | LOG_DEBUG, fmt, ap);
        }
    } else {
        gettimeofday(&tv, NULL);
        millisec = lrint(tv.tv_usec / 1000.0);
        if (millisec >= 1000) {
            millisec -= 1000;
            tv.tv_sec ++;
        }
        tm_info = localtime(&tv.tv_sec);
        strftime(timebuf, 1024, "%H:%M:%S", tm_info);

        if (logger->mode == CORSARO_LOG_STDERR) {
            out = stderr;
        } else {
            out = logger->out;
        }
        pthread_mutex_lock(&logger->mutex);
        fprintf(out, "[%s.%03d]", timebuf, millisec);
        if (logger->name) {
            fprintf(out, " %s", logger->name);
        }
        fprintf(out, ": ");
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
    return logger;
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
