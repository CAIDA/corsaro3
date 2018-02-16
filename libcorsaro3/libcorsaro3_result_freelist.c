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

#define FREELIST_MAX_ITEMS 1000


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "libcorsaro3_result_freelist.h"

corsaro_result_freelist_t *corsaro_start_result_freelist(size_t item_size) {

    corsaro_result_freelist_t *fl = NULL;

    fl = (corsaro_result_freelist_t *)malloc(
            sizeof(corsaro_result_freelist_t));

    if (fl == NULL) {
        return NULL;
    }

    fl->avail = libtrace_list_init(sizeof(void *));
    fl->totalitems = 0;
    fl->itemsize = item_size;

    return fl;
}

void corsaro_destroy_result_freelist(corsaro_result_freelist_t *list,
        void *provided, void (*callback)(void *, void *)) {

    libtrace_list_node_t *n;

    if (list == NULL) {
        return;
    }

    n = list->avail->head;

    while (n) {
        void *itemdata = n->data;
        if (callback) {
            callback(provided, itemdata);
        }
        n = n->next;
    }

    libtrace_list_deinit(list->avail);
    free(list);
}

void *corsaro_acquire_result_from_freelist(corsaro_result_freelist_t *list) {

    void *item = NULL;

    if (libtrace_list_get_size(list->avail) == 0) {

        /* No free items available */
        if (list->totalitems >= FREELIST_MAX_ITEMS) {
            return NULL;
        }

        item = malloc(list->itemsize);
        list->totalitems ++;
        return item;
    }

    if (libtrace_list_pop_front(list->avail, &(item)) == 0) {
        return NULL;
    }

    return item;
}


void corsaro_release_result_to_freelist(corsaro_result_freelist_t *list,
        void *released) {

    libtrace_list_push_front(list->avail, &(released));

}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
