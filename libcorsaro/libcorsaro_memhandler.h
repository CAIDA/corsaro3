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
#include <pthread.h>

#include "libcorsaro_log.h"

typedef struct corsaro_memblob corsaro_memsource_t;

/** A large chunk of contiguous memory that is used to sub-allocate
 *  memory for small frequently used structures.
 */
struct corsaro_memblob {

    /** Pointer to the contiguous memory blob */
    uint8_t *blob;

    /** Size of the contiguous memory blob */
    size_t blobsize;

    /** Size of the structure that we are allocated out of this blob */
    size_t itemsize;

    /** Number of structures that can be allocated out of this blob */
    uint32_t alloceditems;

    /** The index of the next available sub-allocation */
    uint32_t nextavail;

    /** Number of sub-allocations that have been released */
    uint32_t released;

    /** Reference to the next blob in a handler's free list */
    corsaro_memsource_t *nextfree;
};

/** Custom memory allocator / manager that allows us to do bulk memory
 *  allocations for structures that we would otherwise be frequently
 *  allocating and freeing.
 */
typedef struct corsaro_memhandler {

    /** Reference to a corsaro logger for error reporting */
    corsaro_logger_t *logger;

    /** Number of structures that should be allocated in a single bulk alloc */
    uint32_t items_per_blob;

    /** Size of the structure that is being allocated using this handler */
    size_t itemsize;

    /** Number of threads that are currently using memory allocated by this
     *  handler.
     */
    int users;

    /** Number of blobs that are currently available in the freelist */
    int freelistavail;

    /** Mutex for protecting key fields against concurrent access */
    pthread_mutex_t mutex;

    /** Reference to the blob that is currently being used for sub-allocations
     */
    corsaro_memsource_t *current;

    /** A free list containing blobs that have been entirely released back
     *  to the handler and can therefore be reused.
     */
    corsaro_memsource_t *freelist;

    /** Number of blobs that have been allocated by this handler and not yet
     *  completely released by the user.
     */
    uint32_t unreleased;

    /** Page size for the system running this memory handler -- our bulk
     *  allocations need to be a multiple of the page size.
     */
    size_t pagesize;

} corsaro_memhandler_t;

/** Initialises a new memory handler and allocates the first memory blob.
 *
 *  @param logger       A reference to a corsaro logger for error reporting
 *  @param handler      The memory handler to be initialised
 *  @param itemsize     The size of the structure that is to be bulk allocated
 *                      by this handler.
 *  @param itemsperalloc    The number of structures that should be allocated
 *                          by each bulk allocation.
 */
void init_corsaro_memhandler(corsaro_logger_t *logger,
        corsaro_memhandler_t *handler, size_t itemsize,
        uint32_t itemsperalloc);

/** Decrements the user count for a memory handler. If the user count reaches
 *  zero, the memory handler will be destroyed.
 *
 *  @param handler      The memory handler to be destroyed.
 *
 *  @note Ideally, all blobs should have been fully released by the time you
 *        call this for the last time, otherwise they may be leaked.
 */
void destroy_corsaro_memhandler(corsaro_memhandler_t *handler);

/** Increments the user count for a memory handler. You will want to do this
 *  once for every thread that is working with structures that have been
 *  allocated by the memory handler.
 *
 *  @param handler      The memory handler that is to be shared with another
 *                      thread.
 */
void add_corsaro_memhandler_user(corsaro_memhandler_t *handler);

/** Requests a reference to a single, unused instance of the structure that is
 *  being bulk allocated by a memory handler.
 *
 *  @param handler      The memory handler which will provide the new instance
 *  @param itemsource[out]  Updated with a reference to the blob that the
 *                          new instance has come from -- will be needed when
 *                          it comes time to release the memory.
 *  @return a pointer to memory that can be used to store an instance of the
 *          structure managed by this handler.
 *
 *  It is *very* important that you keep track of 'itemsource' for every
 *  instance you get from this function. I usually add a corsaro_memsource_t
 *  pointer to my managed structure and set that to be 'itemsource' as soon
 *  as this function returns.
 */
uint8_t *get_corsaro_memhandler_item(corsaro_memhandler_t *handler,
        corsaro_memsource_t **itemsource);

/** Releases a reference to a single structure instance back to the memory
 *  handler that originally provided it.
 *
 *  @param handler      The memory handler which originally provided the
 *                      instance to be released.
 *  @param itemsource   A reference to the blob that the released memory was
 *                      allocated from.
 *
 *  @note You don't need to provide a pointer to the structure itself, as
 *        internally we only count references requested and references
 *        released. This means the user must be careful not to release the
 *        same structure instance twice, because we have no information
 *        available that would help detect this situation.
 */
void release_corsaro_memhandler_item(corsaro_memhandler_t *handler,
        corsaro_memsource_t *itemsource);
uint8_t *get_corsaro_memhandler_item_nolock(corsaro_memhandler_t *handler,
        corsaro_memsource_t **itemsource);
void release_corsaro_memhandler_item_nolock(corsaro_memhandler_t *handler,
        corsaro_memsource_t *itemsource);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
