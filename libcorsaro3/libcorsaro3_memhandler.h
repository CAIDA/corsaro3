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


#ifndef CORSARO_MEMHANDLER_H
#define CORSARO_MEMHANDLER_H

#include <inttypes.h>
#include <stdint.h>

#include "libcorsaro3_log.h"

typedef struct corsaro_memblob corsaro_memsource_t;

struct corsaro_memblob {

    uint8_t *blob;
    size_t itemsize;
    uint32_t alloceditems;

    uint32_t nextavail;
    uint32_t released;

    corsaro_memsource_t *nextfree;
};

typedef struct corsaro_memhandler {

    corsaro_logger_t *logger;
    uint32_t items_per_blob;
    size_t itemsize;

    corsaro_memsource_t *current;
    corsaro_memsource_t *freelist;

} corsaro_memhandler_t;

void init_corsaro_memhandler(corsaro_logger_t *logger,
        corsaro_memhandler_t *handler, size_t itemsize,
        uint32_t itemsperalloc);
void destroy_corsaro_memhandler(corsaro_memhandler_t *handler);

uint8_t *get_corsaro_memhandler_item(corsaro_memhandler_t *handler,
        corsaro_memsource_t **itemsource);
void release_corsaro_memhandler_item(corsaro_memhandler_t *handler,
        corsaro_memsource_t *itemsource);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
