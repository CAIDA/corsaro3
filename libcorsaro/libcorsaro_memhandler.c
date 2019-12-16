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
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,  * EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED
 * HEREUNDER IS ON AN “AS IS” BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO
 * OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>

#include "libcorsaro_log.h"
#include "libcorsaro_memhandler.h"

/** Corsaro memory handler
 *  ======================
 *
 *  Efficient memory allocation and release for situations where you are
 *  wanting to allocate (and free) instances of the exact same structure
 *  repeatedly.
 *
 *  There is a surprising amount of overhead involved in each call to
 *  malloc or free that you make. If you are dealing with 1000s (or millions)
 *  of allocated instances of the same structure, it therefore makes much
 *  more sense to bulk allocate contiguous blobs of memory that you can then
 *  manually sub-divide and distribute as needed, i.e. one allocation
 *  gives you enough structures to store 10,000 flowtuple results.
 *
 *  The other issue with malloc/free is that the memory seldom gets returned
 *  to the OS before the process ends; it is usually cached within the
 *  process just in case it is needed again. In the corsaro context, this
 *  means that a single busy interval can cause our long-running process to
 *  permanently have a larger than usual memory footprint.
 *
 *  The latter problem can be resolved by using mmap instead of malloc to
 *  allocate memory. mmap itself is a somewhat coarse approach to memory
 *  allocation, completely unsuitable for small memory allocations. Since we
 *  are committed to doing large bulk allocations anyway, mmap works great
 *  for us. Calls to munmap will release the memory back to the OS, so we
 *  only need to worry about caching as much released memory as we think
 *  we'll need in the general case.
 *
 *  How it works
 *  ============
 *  The core component of the memory handler system is the "blob". A blob is
 *  simply a contiguous block of mmapped memory that is big enough to fit
 *  a pre-configured number of instances of a particular structure, much like
 *  an array.
 *
 *  When we first initialise a memory handler, we are given the size of the
 *  structure that the user wants to bulk allocate and the number of instances
 *  to allocate each time we call mmap. The new handler will use mmap to
 *  allocate the first blob, which will be initialised as having zero items
 *  used.
 *
 *  Whenever a user requests a new item from the memory handler, it first
 *  checks to see if there are any unused items available in the most
 *  recently allocated blob. If yes, it will return a pointer to the
 *  first unused portion of the blob as well as a reference to the blob
 *  itself (used later on to help release the item back to the blob). If
 *  no, a new blob is allocated and the first item from that blob is
 *  returned instead.
 *
 *  When a user has finished with the item that they had requested, they
 *  call the release API method on the handler and the blob that the item
 *  came from. The number of released items for the blob is incremented.
 *  If we also determine that the blob is both not the most recently
 *  allocated blob AND all of its items have been released back, we can
 *  then finally munmap the blob and return its memory back to the OS.
 *
 *  In practice, we keep a few extra blobs around in a free list so we
 *  aren't continually mmaping and munmaping blobs that we could just
 *  recycle instead.

 *  Since we are reference-counting only, we make no effort to validate
 *  that the item being released to us is legit. It is the user's
 *  responsibility to make sure that they do not release the same item
 *  twice or release an item they did not request. The main reasons for
 *  not adding that validation are
 *    - this is an internal corsaro API, so any screw ups with this API
 *      would be our own fault anyway.
 *    - not having to keep track of which specific segments of a blob
 *      have been released will save us quite a bit of memory and CPU
 *      overhead, which was the point of adding the handler in the first
 *      place.
 */

static inline corsaro_memsource_t *create_fresh_blob(uint32_t itemcount,
        size_t itemsize, corsaro_memhandler_t *handler) {

    corsaro_memsource_t *blob;
    size_t upsize;

    /* Our allocation needs to be a multiple of the page size -- round up
     * to the next page if need be.
     */
    upsize = (((itemsize * itemcount) / handler->pagesize) + 1) * handler->pagesize;

    blob = (corsaro_memsource_t *)malloc(sizeof(corsaro_memsource_t));

    /* Just need some anonymous writable memory that is limited to our process
     * only */
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

    /* Only actually destroy the memory handler if we are the last
     * user left standing. */
    pthread_mutex_lock(&handler->mutex);
    handler->users --;
    if (handler->users > 0) {
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

static inline uint8_t *_get_corsaro_memhandler_item(
        corsaro_memhandler_t *handler, corsaro_memsource_t **itemsource) {

    uint8_t *mem;
    /* If the current blob still have slots available, just return one
     * of those. Otherwise, we need to create a new blob and grab the first
     * slot from that.
     */

    if (handler->current->nextavail >= handler->current->alloceditems) {

        if (handler->current->released == handler->current->alloceditems) {
            /* User has been releasing as fast as they've been allocating,
             * just reuse current rather than bothering with the freelist */
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

    /* Find the next available slot in the current blob */
    mem = handler->current->blob + (handler->current->nextavail *
            handler->current->itemsize);
    handler->current->nextavail ++;
    *itemsource = handler->current;
    return mem;
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
    mem = _get_corsaro_memhandler_item(handler, itemsource);
    pthread_mutex_unlock(&handler->mutex);
    return mem;

}

uint8_t *get_corsaro_memhandler_item_nolock(corsaro_memhandler_t *handler,
        corsaro_memsource_t **itemsource) {
    return _get_corsaro_memhandler_item(handler, itemsource);
}

static inline void _release_corsaro_memhandler_item(
        corsaro_memhandler_t *handler,
        corsaro_memsource_t *itemsource) {

    itemsource->released ++;

    if (itemsource->released > handler->items_per_blob) {
        pthread_mutex_unlock(&handler->mutex);
        return;
    }

    if (itemsource != handler->current &&
            itemsource->released == handler->items_per_blob) {
        /* Put the blob on the freelist for possible re-use */
        assert(handler->freelist != itemsource);
        itemsource->nextfree = handler->freelist;
        handler->freelist = itemsource;
        handler->freelistavail ++;
        handler->unreleased --;
    }

    /* Don't allow our freelist to grow too large -- may as well
     * return the excess blobs back to the OS at this point. */
    while (handler->freelistavail > 100) {
        corsaro_memsource_t *tmp = handler->freelist;
        handler->freelist = handler->freelist->nextfree;
        handler->freelistavail --;
        munmap(tmp->blob, tmp->blobsize);
        free(tmp);
    }

}

void release_corsaro_memhandler_item(corsaro_memhandler_t *handler,
        corsaro_memsource_t *itemsource) {

    pthread_mutex_lock(&handler->mutex);
    _release_corsaro_memhandler_item(handler, itemsource);
    pthread_mutex_unlock(&handler->mutex);
}

void release_corsaro_memhandler_item_nolock(corsaro_memhandler_t *handler,
        corsaro_memsource_t *itemsource) {
    _release_corsaro_memhandler_item(handler, itemsource);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
