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
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,
 * EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED
 * HEREUNDER IS ON AN “AS IS” BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO
 * OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
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
