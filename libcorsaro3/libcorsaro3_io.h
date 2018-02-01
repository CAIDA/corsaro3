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

#ifndef CORSARO_IO_H_
#define CORSARO_IO_H_

#include <inttypes.h>
#include <wandio.h>

/** The default compression level */
#define CORSARO_FILE_COMPRESS_LEVEL_DEFAULT 6


/** The suffix used to detect gzip output is desired */
#define CORSARO_FILE_ZLIB_SUFFIX ".gz"

/** The suffix used to detect bzip output is desired */
#define CORSARO_FILE_BZ2_SUFFIX ".bz2"

/** The character to replace with the name of the plugin */
#define CORSARO_IO_PLUGIN_PATTERN 'P'
/** The pattern to replace in the output file name with the name of the plugin
 */
#define CORSARO_IO_PLUGIN_PATTERN_STR "%P"

 /** The character to replace with the monitor name */
#define CORSARO_IO_MONITOR_PATTERN 'N'
 /** The pattern to replace in the output file name with monitor name */
#define CORSARO_IO_MONITOR_PATTERN_STR "%N"

/** Supported compression types (must be kept in sync with wandio) */
typedef enum corsaro_file_compress {
    /** No compression */
    CORSARO_FILE_COMPRESS_NONE = WANDIO_COMPRESS_NONE,
    /** Zlib compression (gzip) */
    CORSARO_FILE_COMPRESS_ZLIB = WANDIO_COMPRESS_ZLIB,
    /** Bzip compression */
    CORSARO_FILE_COMPRESS_BZ2 = WANDIO_COMPRESS_BZ2,
    /** LZO Compression */
    CORSARO_FILE_COMPRESS_LZO = WANDIO_COMPRESS_LZO,

    /** Special value used to indicate no type chosen yet */
    CORSARO_FILE_COMPRESS_UNSET = 255,

    /** Default compression */
    CORSARO_FILE_COMPRESS_DEFAULT = CORSARO_FILE_COMPRESS_ZLIB
} corsaro_file_compress_t;

/** Enum of supported file modes */
typedef enum corsaro_file_mode {
    /** ASCII IO mode */
    CORSARO_FILE_MODE_ASCII = 0,
    /** Binary IO mode */
    CORSARO_FILE_MODE_BINARY = 1,
    /** Pseudo IO mode which allows trace files to be written */
    CORSARO_FILE_MODE_TRACE = 2,
    /** Unknown IO mode */
    CORSARO_FILE_MODE_UNKNOWN = 3,

    /** Default IO mode */
    CORSARO_FILE_MODE_DEFAULT = CORSARO_FILE_MODE_UNKNOWN
} corsaro_file_mode_t;


/** Convenience function for generating a file name based on the given
 *  template string
 *
 * @param template      file name template
 * @param plugin        name of the plugin (used if %P is in the template)
 * @param monitorname   name of the monitor (used if %N is in the template)
 * @param time          the current time (used for strftime formatting)
 * @param compress      if set to CORSARO_FILE_COMPRESS_NONE then any .gz or
 *                      .bz2 file extension will be removed
 * @return pointer to a dynamically allocated string with the filename if
 * successful, NULL otherwise
 *
 * Note: It is the caller's responsibility to free the returned string
 */
char *corsaro_generate_file_name(const char *template,
        const char *plugin,
        const char *monitorname,
        uint32_t time,
        corsaro_file_compress_t compress);


#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
