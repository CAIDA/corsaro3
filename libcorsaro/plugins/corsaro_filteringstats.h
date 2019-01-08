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

#ifndef CORSARO_FILTERINGSTATS_PLUGIN_H_
#define CORSARO_FILTERINGSTATS_PLUGIN_H_

#include "config.h"
#include "libcorsaro.h"
#include "libcorsaro_plugin.h"

corsaro_plugin_t *corsaro_filteringstats_alloc(void);
CORSARO_PLUGIN_GENERATE_PROTOTYPES(corsaro_filteringstats)

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
