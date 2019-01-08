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

#ifndef LIBCORSARO_LOG_H_
#define LIBCORSARO_LOG_H_

#include <stdarg.h>
#include <pthread.h>
#include <stdio.h>

enum {
    GLOBAL_LOGMODE_STDERR = 0,
    GLOBAL_LOGMODE_SYSLOG = 1,
    GLOBAL_LOGMODE_DISABLED = 2,
    GLOBAL_LOGMODE_FILE = 3,
};

typedef struct corsaro_logger {
    FILE *out;      // File pointer for writing to a log file.
    char *name;     // String to prepend to each log message.
    int mode;       // Where we log to (e.g. file, syslog, stderr).
    pthread_mutex_t mutex;  // mutex to prevent thread races.

} corsaro_logger_t;

corsaro_logger_t *init_corsaro_logger(char *name, char *fname);
void destroy_corsaro_logger(corsaro_logger_t *logger);
void corsaro_log(corsaro_logger_t *logger, const char *fmt, ...);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
