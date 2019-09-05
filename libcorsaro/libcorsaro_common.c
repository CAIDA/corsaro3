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
#include <errno.h>

#include "libcorsaro_common.h"
#include "libcorsaro_log.h"

int parse_corsaro_generic_config(void *glob, char *filename, char *progname,
		int logmode, 
		int (*parsefunc)(void *, yaml_document_t *doc, yaml_node_t *,
                yaml_node_t *, corsaro_logger_t *logger)) {

	corsaro_logger_t *logger;
    yaml_parser_t parser;
    yaml_document_t document;
    yaml_node_t *root, *key, *value;
    yaml_node_pair_t *pair;
    FILE *in = NULL;
    int ret = 0;

	/* create a temporary logger for config parsing errors */
	if (logmode == GLOBAL_LOGMODE_SYSLOG) {
		logger = init_corsaro_logger(progname, NULL);
	} else {
		/* use stderr because we don't know the filename to log to yet */
		logger = init_corsaro_logger(progname, "");
	}

	if (logger == NULL) {
		fprintf(stderr, "%s: failed to create a logger, exiting...\n",
                progname);
		return -2;
	}


    if ((in = fopen(filename, "r")) == NULL) {
        corsaro_log(logger, "Failed to open config file: %s", strerror(errno));
        return -1;
    }

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, in);

    if (!yaml_parser_load(&parser, &document)) {
        corsaro_log(logger, "Malformed config file");
        ret = -1;
        goto yamlfail;
    }

    root = yaml_document_get_root_node(&document);
    if (!root) {
        corsaro_log(logger, "Config file is empty!");
        ret = -1;
        goto endconfig;
    }

    if (root->type != YAML_MAPPING_NODE) {
        corsaro_log(logger, "Top level of config should be a map");
        ret = -1;
        goto endconfig;
    }

    for (pair = root->data.mapping.pairs.start;
            pair < root->data.mapping.pairs.top; pair ++) {

        key = yaml_document_get_node(&document, pair->key);
        value = yaml_document_get_node(&document, pair->value);

        ret = parsefunc(glob, &document, key, value, logger);
        if (ret <= 0) {
            break;
        }
        ret = 0;
    }

endconfig:
    yaml_document_delete(&document);
	yaml_parser_delete(&parser);

yamlfail:
	destroy_corsaro_logger(logger);
	fclose(in);
	return ret;
}

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
