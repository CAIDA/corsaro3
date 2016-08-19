/*
 * corsaro
 *
 * Alistair King, CAIDA, UC San Diego
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

#include "config.h"
#include "corsaro_int.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libtrace.h"

#include "utils.h"
#include "wandio_utils.h"

#include "corsaro_io.h"
#include "corsaro_log.h"
#include "corsaro_plugin.h"
#include "corsaro_tag.h"

#include "corsaro_filterdark.h"

/** @file
 *
 * @brief Corsaro Dark-filter plugin
 *
 * @note this plugin does not support processing flowtuple files
 *
 * @author Alistair King
 *
 */

/** The magic number for this plugin - "FDRK" */
#define CORSARO_DARK_MAGIC 0x4644524B

/** The name of this plugin */
#define PLUGIN_NAME "filterdark"

/* max number of /24s in a /8 darknet */
#define EXCLUDE_LEN (1<<16)

/** Common plugin information across all instances */
static corsaro_plugin_t corsaro_filterdark_plugin = {
  PLUGIN_NAME,                                 /* name */
  CORSARO_PLUGIN_ID_FILTERDARK,                /* id */
  CORSARO_DARK_MAGIC,                          /* magic */
  CORSARO_PLUGIN_GENERATE_PTRS(corsaro_filterdark),
  CORSARO_PLUGIN_GENERATE_TAIL,
};

/** Holds the state for an instance of this plugin */
struct corsaro_filterdark_state_t {
  /* Darknet byte */
  uint32_t darknet;

  /* excluded /24s */
  uint8_t *exclude;
};

/** Extends the generic plugin state convenience macro in corsaro_plugin.h */
#define STATE(corsaro)						\
  (CORSARO_PLUGIN_STATE(corsaro, filterdark, CORSARO_PLUGIN_ID_FILTERDARK))

/** Extends the generic plugin plugin convenience macro in corsaro_plugin.h */
#define PLUGIN(corsaro)						\
  (CORSARO_PLUGIN_PLUGIN(corsaro, CORSARO_PLUGIN_ID_FILTERDARK))

static int parse_excl_file(corsaro_t *corsaro, const char *excl_file) {
  struct corsaro_filterdark_state_t *state = STATE(corsaro);
  io_t *file;
  char buf[1024];
  char *mask_str;
  int mask;

  uint32_t addr;

  uint32_t first_addr;
  uint32_t last_addr;

  uint32_t first_slash24;
  uint32_t last_slash24;

  uint64_t x;

  int cnt = 0;
  int overlaps = 0;
  int idx;

  if ((file = wandio_create(excl_file)) == NULL) {
    return -1;
  }

  while (wandio_fgets(file, buf, 1024, 1) != 0) {
    // split the line to get ip and len
    if ((mask_str = strchr(buf, '/')) == NULL) {
      fprintf(stderr, "ERROR: Malformed prefix: %s\n", buf);
      goto err;
    }
    *mask_str = '\0';
    mask_str++;

    // convert the ip and mask to a number
    addr = inet_addr(buf);
    addr = ntohl(addr);
    mask = atoi(mask_str);
    if (mask < 0 || mask > 32) {
      fprintf(stderr, "ERROR: Malformed prefix: %s/%s\n", buf, mask_str);
      goto err;
    }

    // compute the /24s that this prefix covers
    // perhaps not the most efficient way to do this, but i've borrowed it from
    // other code that I'm sure actually works, and this only happens once at
    // startup, so whatevs ;)
    first_addr = addr & (~0 << (32-mask));
    last_addr = first_addr + (1<<(32-mask))-1;

    first_slash24 = (first_addr/256)*256;
    last_slash24 = (last_addr/256)*256;

    for(x = first_slash24; x <= last_slash24; x += 256) {
      idx = (x&0x00FFFF00)>>8;
      if (state->exclude[idx] == 0) {
        state->exclude[idx] = 1;
        cnt++;
      } else {
        overlaps++;
      }
    }
  }

  corsaro_log(__func__, corsaro, "Excluding %d /24s\n", cnt);
  corsaro_log(__func__, corsaro, "Overlaps %d /24s\n", overlaps);

  wandio_destroy(file);

  return 0;

 err:
  wandio_destroy(file);
  return -1;
}


/** Print usage information to stderr */
static void usage(corsaro_plugin_t *plugin)
{
  fprintf(stderr,
	  "plugin usage: %s -e <file> -s <value>\n"
          "       -e <file>     specifies a list of prefixes to exclude.\n"
          "                     all packets to these prefixes will be skipped.\n"
          "       -s <value>    specifies the first octet of the destination address.\n"
          "                     all packets with a different first octet will be skipped\n",
	  plugin->argv[0]);
}

/** Parse the arguments given to the plugin */
static int parse_args(corsaro_t *corsaro)
{
  corsaro_plugin_t *plugin = PLUGIN(corsaro);
  struct corsaro_filterdark_state_t *state = STATE(corsaro);
  int opt;
  const char *excl_file = NULL;
  int first_octet = -1;

  /* remember the storage for the argv strings belongs to us, we don't need
     to strdup them */

  /* NB: remember to reset optind to 1 before using getopt! */
  optind = 1;

  while((opt = getopt(plugin->argc, plugin->argv, ":e:s:?")) >= 0)
    {
      switch(opt)
	{

        case 'e':
          excl_file = optarg;
          break;

        case 's':
          first_octet = atoi(optarg);
          break;

	case '?':
	case ':':
	default:
	  usage(plugin);
	  return -1;
	}
    }


  if (first_octet == -1) {
    fprintf(stderr, "ERROR: First octet must be specified using -s\n");
    usage(plugin);
    return -1;
  }

  if (first_octet < 0 || first_octet > 255) {
    fprintf(stderr, "ERROR: Invalid first octet: %d\n", first_octet);
    usage(plugin);
    return -1;
  }
  state->darknet = first_octet << 24;

  if (excl_file == NULL) {
    fprintf(stderr, "ERROR: Exclusion file must be specified using -e\n");
    usage(plugin);
    return -1;
  }

  return parse_excl_file(corsaro, excl_file);
}

/* == PUBLIC PLUGIN FUNCS BELOW HERE == */

/** Implements the alloc function of the plugin API */
corsaro_plugin_t *corsaro_filterdark_alloc(corsaro_t *corsaro)
{
  return &corsaro_filterdark_plugin;
}

/** Implements the probe_filename function of the plugin API */
int corsaro_filterdark_probe_filename(const char *fname)
{
  /* this does not write files */
  return 0;
}

/** Implements the probe_magic function of the plugin API */
int corsaro_filterdark_probe_magic(corsaro_in_t *corsaro, corsaro_file_in_t *file)
{
  /* this does not write files */
  return 0;
}

/** Implements the init_output function of the plugin API */
int corsaro_filterdark_init_output(corsaro_t *corsaro)
{
  struct corsaro_filterdark_state_t *state;
  corsaro_plugin_t *plugin = PLUGIN(corsaro);

  assert(plugin != NULL);

  if((state = malloc_zero(sizeof(struct corsaro_filterdark_state_t))) == NULL)
    {
      corsaro_log(__func__, corsaro,
		"could not malloc corsaro_filterdark_state_t");
      goto err;
    }
  corsaro_plugin_register_state(corsaro->plugin_manager, plugin, state);

  /* init the exclude list */
  if ((state->exclude = malloc_zero(sizeof(uint8_t) * EXCLUDE_LEN)) == NULL) {
    goto err;
  }

  /* parse the arguments */
  if(parse_args(corsaro) != 0)
    {
      /* parse args calls usage itself, so do not goto err here */
      return -1;
    }

  return 0;

 err:
  corsaro_filterdark_close_output(corsaro);
  return -1;
}

/** Implements the init_input function of the plugin API */
int corsaro_filterdark_init_input(corsaro_in_t *corsaro)
{
  assert(0);
  return -1;
}

/** Implements the close_input function of the plugin API */
int corsaro_filterdark_close_input(corsaro_in_t *corsaro)
{
  assert(0);
  return -1;
}

/** Implements the close_output function of the plugin API */
int corsaro_filterdark_close_output(corsaro_t *corsaro)
{
  struct corsaro_filterdark_state_t *state = STATE(corsaro);

  if(state == NULL)
    {
      return 0;
    }

  free(state->exclude);
  state->exclude = NULL;

  corsaro_plugin_free_state(corsaro->plugin_manager, PLUGIN(corsaro));

  return 0;
}

/** Implements the read_record function of the plugin API */
off_t corsaro_filterdark_read_record(struct corsaro_in *corsaro,
			       corsaro_in_record_type_t *record_type,
			       corsaro_in_record_t *record)
{
  assert(0);
  return -1;
}

/** Implements the read_global_data_record function of the plugin API */
off_t corsaro_filterdark_read_global_data_record(struct corsaro_in *corsaro,
			      enum corsaro_in_record_type *record_type,
			      struct corsaro_in_record *record)
{
  /* we write nothing to the global file. someone messed up */
  return -1;
}

/** Implements the start_interval function of the plugin API */
int corsaro_filterdark_start_interval(corsaro_t *corsaro,
				corsaro_interval_t *int_start)
{
  /* we do not care */
  return 0;
}

/** Implements the end_interval function of the plugin API */
int corsaro_filterdark_end_interval(corsaro_t *corsaro,
				corsaro_interval_t *int_end)
{
  /* we do not care */
  return 0;
}

/** Implements the process_packet function of the plugin API */
int corsaro_filterdark_process_packet(corsaro_t *corsaro,
                                      corsaro_packet_t *packet)
{
  struct corsaro_filterdark_state_t *state = STATE(corsaro);
  libtrace_ip_t  *ip_hdr  = NULL;
  uint32_t ip_addr;

  /* check for ipv4 */
  if((ip_hdr = trace_get_ip(LT_PKT(packet))) == NULL) {
    /* not an ip packet */
    goto skip;
  }
  ip_addr = htonl(ip_hdr->ip_dst.s_addr);

  if(((ip_addr & 0xFF000000) != state->darknet) ||
     (state->exclude[(ip_addr & 0x00FFFF00) >> 8] != 0)) {
    goto skip;
  }

  return 0;

 skip:
  /* flip on the ignore bit if any of the filters match */
  packet->state.flags |= CORSARO_PACKET_STATE_FLAG_IGNORE;
  return 0;
}
