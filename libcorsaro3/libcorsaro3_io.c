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
#include <time.h>

#include "libcorsaro3_io.h"

static char *stradd(const char *str, char *bufp, char *buflim)
{
    while (bufp < buflim && (*bufp = *str++) != '\0') {
        ++bufp;
    }
    return bufp;
}


char *corsaro_generate_file_name(const char *template,
        const char *plugin,
        const char *monitorname,
        uint32_t time,
        corsaro_file_compress_t compress,
        int threadid)
{
    /* some of the structure of this code is borrowed from the
       FreeBSD implementation of strftime */

    /* the output buffer */
    /* @todo change the code to dynamically realloc this if we need more
       space */
    char buf[1024];
    char tbuf[1024];
    char *bufp = buf;
    char *buflim = buf + sizeof(buf);

    /* cast away const, but we don't modify the buffer */
    char *tmpl = (char*)template;
    char secs[11]; /* length of UINT32_MAX +1 */
    struct timeval tv;

    if (template == NULL) {
        return NULL;
    }


    for (; *tmpl; ++tmpl) {
        if (*tmpl == '.' && compress == CORSARO_FILE_COMPRESS_NONE) {
            if (strncmp(tmpl, CORSARO_FILE_ZLIB_SUFFIX,
                        strlen(CORSARO_FILE_ZLIB_SUFFIX)) == 0 ||
                    strncmp(tmpl, CORSARO_FILE_BZ2_SUFFIX,
                        strlen(CORSARO_FILE_BZ2_SUFFIX)) == 0) {
                break;
            }
        } else if (*tmpl == '%') {
            switch (*++tmpl) {
                case '\0':
                    --tmpl;
                    break;

                    /* BEWARE: if you add a new pattern here, you must also add
                     * it to corsaro_io_template_has_timestamp */

                case CORSARO_IO_MONITOR_PATTERN:
                    if (monitorname == NULL) {
                        return NULL;
                    }
                    bufp = stradd(monitorname, bufp, buflim);
                    continue;

                case CORSARO_IO_PLUGIN_PATTERN:
                    if (plugin == NULL) {
                        return NULL;
                    }
                    bufp = stradd(plugin, bufp, buflim);
                    continue;

                case 's':
                    snprintf(secs, sizeof(secs), "%" PRIu32, time);
                    bufp = stradd(secs, bufp, buflim);
                    continue;
                    /* fall through */
                default:
                    /* we want to be generous and leave non-recognized formats
                       intact - especially for strftime to use */
                    --tmpl;
            }
        }
        if (bufp == buflim)
            break;
        *bufp++ = *tmpl;
    }

    if (bufp >= buflim) {
        /* Not enough space for the full filename */
        return NULL;
    }

    if (threadid >= 0) {
        char thspace[1024];
        snprintf(thspace, 1024, "--%d", threadid);
        bufp = stradd(thspace, bufp, buflim);
    }

    if (bufp >= buflim) {
        /* Not enough space for the full filename */
        return NULL;
    }

    *bufp = '\0';

    /* now let strftime have a go */
    tv.tv_sec = time;
    strftime(tbuf, sizeof(tbuf), buf, gmtime(&tv.tv_sec));
    return strdup(tbuf);
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
