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

#ifndef LIBCORSARO_H_
#define LIBCORSARO_H_

#include <inttypes.h>

#define CORSARO_MAGIC (0x45444752)
#define CORSARO_MAGIC_INTERVAL (0x494E5452)

typedef struct corsaro_fin_interval corsaro_fin_interval_t;
typedef struct corsaro_interval corsaro_interval_t;


struct corsaro_interval {
    uint32_t corsaro_magic;
    uint32_t magic;
    uint32_t number;
    uint32_t time;
};

struct corsaro_fin_interval {
    uint32_t interval_id;
    uint32_t timestamp;
    uint16_t threads_ended;
    corsaro_fin_interval_t *next;
};

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
