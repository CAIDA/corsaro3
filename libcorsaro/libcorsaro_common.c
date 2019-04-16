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

#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "libcorsaro_common.h"
#include "libcorsaro_log.h"

int parse_onoff_option(corsaro_logger_t *logger, char *value,
        uint8_t *opt, const char *optstr) {

    if (strcmp(value, "yes") == 0 || strcmp(value, "true") == 0 ||
            strcmp(value, "on") == 0 || strcmp(value, "enabled") == 0) {
        *opt = 1;
    }

    else if (strcmp(value, "no") == 0 || strcmp(value, "false") == 0 ||
            strcmp(value, "off") == 0 || strcmp(value, "disabled") == 0) {
        *opt = 0;
    } else {
        corsaro_log(logger,
                "invalid value for '%s' option: '%s'", optstr, value);
        corsaro_log(logger,
                "try using 'yes' to enable %s or 'no' to disable it.", optstr);
        return -1;
    }

    return 0;
}

/* Byte swapping functions for various inttypes */
uint64_t byteswap64(uint64_t num)
{
    return (byteswap32((num&0xFFFFFFFF00000000ULL)>>32))
        |((uint64_t)byteswap32(num&0x00000000FFFFFFFFULL)<<32);
}

uint32_t byteswap32(uint32_t num)
{
    return ((num&0x000000FFU)<<24)
        | ((num&0x0000FF00U)<<8)
        | ((num&0x00FF0000U)>>8)
        | ((num&0xFF000000U)>>24);
}

uint16_t byteswap16(uint16_t num)
{
    return ((num<<8)&0xFF00)|((num>>8)&0x00FF);
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
