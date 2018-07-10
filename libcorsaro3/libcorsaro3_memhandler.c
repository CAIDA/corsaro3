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
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>

#include "libcorsaro3_log.h"
#include "libcorsaro3_memhandler.h"

static inline corsaro_memsource_t *create_fresh_blob(uint32_t itemcount,
        size_t itemsize, corsaro_memhandler_t *handler) {

    corsaro_memsource_t *blob;
    size_t upsize;

    upsize = (((itemsize * itemcount) / handler->pagesize) + 1) * handler->pagesize;

    blob = (corsaro_memsource_t *)malloc(sizeof(corsaro_memsource_t));

    blob->blob = mmap(NULL, upsize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                -1, 0);
    if (blob->blob == MAP_FAILED) {
        corsaro_log(handler->logger, "mmap failed: %s\n", strerror(errno));
        free(blob);
        return NULL;
    }

    blob->blobsize = upsize;
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
    handler->pagesize = sysconf(_SC_PAGE_SIZE);

    pthread_mutex_init(&handler->mutex, NULL);

    handler->current = create_fresh_blob(handler->items_per_blob,
            handler->itemsize, handler);
    handler->freelist = NULL;
    handler->freelistavail = 0;
    handler->unreleased = 1;

}

void destroy_corsaro_memhandler(corsaro_memhandler_t *handler) {

    corsaro_memsource_t *blob, *tmp;

    pthread_mutex_lock(&handler->mutex);
    handler->users --;
    if (handler->users > 0) {
        printf("%p, unreleased=%u freelist=%u blobsize=%lu totalmem=%lu\n",
            handler, handler->unreleased, handler->freelistavail,
            (handler->items_per_blob * handler->itemsize),
            (handler->items_per_blob * handler->itemsize) *
            (handler->unreleased + handler->freelistavail));
                    
        pthread_mutex_unlock(&handler->mutex);
        return;
    }
    pthread_mutex_unlock(&handler->mutex);

    blob = handler->freelist;
    while (blob) {
        tmp = blob;
        blob = blob->nextfree;
        munmap(tmp->blob, tmp->blobsize);
        free(tmp);
    }

    /* Only free current if all references have been released back
     * to us, otherwise there are still items out there that are
     * in use. Hopefully, whoever has those items still has a
     * memory handler around to use to release them...
     */
    if (handler->current->released >= handler->current->nextavail) {
        munmap(handler->current->blob, handler->current->blobsize);
        free(handler->current);
    }

    pthread_mutex_destroy(&handler->mutex);
    free(handler);
}

void add_corsaro_memhandler_user(corsaro_memhandler_t *handler) {
    pthread_mutex_lock(&handler->mutex);
    handler->users ++;
    pthread_mutex_unlock(&handler->mutex);
}

uint8_t *get_corsaro_memhandler_item(corsaro_memhandler_t *handler,
        corsaro_memsource_t **itemsource) {
    uint8_t *mem;

    /* If the current blob still have slots available, just return one
     * of those.
     * Otherwise, we need to create a new handler and grab the first slot
     * from that.
     */

    pthread_mutex_lock(&handler->mutex);
    if (handler->current->nextavail >= handler->current->alloceditems) {

        if (handler->current->released == handler->current->alloceditems) {
            /* User has been releasing as fast as they've been allocating,
             * just reuse current */
            handler->current->nextavail = 0;
            handler->current->released = 0;
            handler->current->nextfree = NULL;
        } else if (handler->freelist == NULL) {
            /* No available blobs in the freelist, create a new one */
            handler->current = create_fresh_blob(handler->items_per_blob,
                    handler->itemsize, handler);
            handler->unreleased ++;
        } else {
            /* Pop an old blob off the freelist */
            handler->current = handler->freelist;
            handler->freelist = handler->freelist->nextfree;
            handler->current->nextavail = 0;
            handler->current->released = 0;
            handler->current->nextfree = NULL;
            handler->freelistavail --;
            handler->unreleased ++;
        }
    }

    mem = handler->current->blob + (handler->current->nextavail *
            handler->current->itemsize);
    handler->current->nextavail ++;
    *itemsource = handler->current;
    pthread_mutex_unlock(&handler->mutex);
    return mem;

}

void release_corsaro_memhandler_item(corsaro_memhandler_t *handler,
        corsaro_memsource_t *itemsource) {

    pthread_mutex_lock(&handler->mutex);
    itemsource->released ++;

    if (itemsource->released > handler->items_per_blob) {
        pthread_mutex_unlock(&handler->mutex);
        return;
    }

    if (itemsource != handler->current &&
            itemsource->released == handler->items_per_blob) {
        assert(handler->freelist != itemsource);
        itemsource->nextfree = handler->freelist;
        handler->freelist = itemsource;
        handler->freelistavail ++;
        handler->unreleased --;
    }

    while (handler->freelistavail > 100) {
        corsaro_memsource_t *tmp = handler->freelist;
        handler->freelist = handler->freelist->nextfree;
        handler->freelistavail --;
        munmap(tmp->blob, tmp->blobsize);
        free(tmp);
    }

    pthread_mutex_unlock(&handler->mutex);
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
