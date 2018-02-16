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

#ifndef CORSARO_RESULT_FREELIST_H_
#define CORSARO_RESULT_FREELIST_H_

#include <libtrace/linked_list.h>

typedef struct corsaro_result_freelist {

    uint32_t totalitems;
    size_t itemsize;
    libtrace_list_t *avail;

} corsaro_result_freelist_t;


corsaro_result_freelist_t *corsaro_start_result_freelist(size_t item_size);

void *corsaro_acquire_result_from_freelist(corsaro_result_freelist_t *list);

void corsaro_release_result_to_freelist(corsaro_result_freelist_t *list,
        void *released);

void corsaro_destroy_result_freelist(corsaro_result_freelist_t *list,
        void *provided,  void (*callback)(void *, void *));

#endif



// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

