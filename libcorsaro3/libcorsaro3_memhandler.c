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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>

#include "libcorsaro3_log.h"
#include "libcorsaro3_memhandler.h"

static inline corsaro_memsource_t *create_fresh_blob(uint32_t itemcount,
        size_t itemsize) {

    corsaro_memsource_t *blob;

    blob = (corsaro_memsource_t *)malloc(sizeof(corsaro_memsource_t));

    blob->blob = (uint8_t *)calloc(itemcount, itemsize);
    blob->itemsize = itemsize;
    blob->alloceditems = itemcount;
    blob->nextavail = 0;
    blob->released = 0;
    blob->nextfree = NULL;

    return blob;
}

void init_corsaro_memhandler(corsaro_logger_t *logger,
        corsaro_memhandler_t *handler, size_t itemsize, uint32_t itemsperalloc) {

    assert(handler != NULL);
    assert(itemsize > 0);

    handler->logger = logger;
    handler->items_per_blob = itemsperalloc;
    handler->itemsize = itemsize;
    handler->users = 1;

    pthread_mutex_init(&handler->mutex, NULL);

    handler->current = create_fresh_blob(handler->items_per_blob,
            handler->itemsize);
    handler->freelist = NULL;
}

void destroy_corsaro_memhandler(corsaro_memhandler_t *handler) {

    corsaro_memsource_t *blob, *tmp;

    handler->users --;
    if (handler->users > 0) {
        return;
    }

    blob = handler->freelist;
    while (blob) {
        tmp = blob;
        blob = blob->nextfree;
        free(tmp->blob);
        free(tmp);
    }

    /* Only free current if all references have been released back
     * to us, otherwise there are still items out there that are
     * in use. Hopefully, whoever has those items still has a
     * memory handler around to use to release them...
     */
    if (handler->current->released >= handler->current->nextavail) {
        free(handler->current->blob);
        free(handler->current);
    }

    pthread_mutex_destroy(&handler->mutex);

}

void add_corsaro_memhandler_user(corsaro_memhandler_t *handler) {
    handler->users ++;
}

uint8_t *get_corsaro_memhandler_item(corsaro_memhandler_t *handler,
        corsaro_memsource_t **itemsource) {
    uint8_t *mem;

    /* If the current blob still have slots available, just return one
     * of those.
     * Otherwise, we need to create a new handler and grab the first slot
     * from that.
     */

    if (handler->current->nextavail >= handler->current->alloceditems) {
        if (pthread_mutex_trylock(&handler->mutex) == 0) {
            if (handler->freelist == NULL) {
                handler->current = create_fresh_blob(handler->items_per_blob,
                        handler->itemsize);
            } else {
                handler->current = handler->freelist;
                handler->freelist = handler->freelist->nextfree;
                handler->current->nextavail = 0;
                handler->current->released = 0;
                handler->current->nextfree = NULL;
            }
        } else {
            handler->current = create_fresh_blob(handler->items_per_blob,
                    handler->itemsize);
        }

    }

    mem = handler->current->blob + (handler->current->nextavail *
            handler->current->itemsize);
    handler->current->nextavail ++;
    *itemsource = handler->current;
    return mem;

}

void release_corsaro_memhandler_item(corsaro_memhandler_t *handler,
        corsaro_memsource_t *itemsource) {

    assert(itemsource->released < itemsource->nextavail);
    itemsource->released ++;

    if (itemsource->released >= handler->current->alloceditems) {
        if (pthread_mutex_trylock(&handler->mutex) == 0) {
            itemsource->nextfree = handler->freelist;
            handler->freelist = itemsource;
        } else {
            free(itemsource->blob);
            free(itemsource);
        }
    }
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
