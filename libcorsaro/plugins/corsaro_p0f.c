/*
 * corsaro
 *
 * Alistair King, CAIDA, UC San Diego
 * alistair@caida.org
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libtrace.h"

#include "utils.h"

#include "corsaro_io.h"
#include "corsaro_file.h"
#include "corsaro_log.h"
#include "corsaro_plugin.h"

#include "corsaro_p0f.h"

/*p0f includes */
#include "libp0f/readfp.h"  /* to read in p0F rules */
#include "libp0f/fp_tcp.h"  /* to call fingerprint_tcp */
#include "libp0f/tcp.h"     /* for flags */
#include "libp0f/alloc-inl.h"  /* so we can free the sig created by fingerprint_tcp */

/** @file
 *
 * @brief Hack to get OS info from p0f
 *
 * @author Karyn Benson
 *
 */

/*#define CORSARO_P0F_DEBUG*/

#define FINGERPRINT_FILE "/data/telescope/meta/misc/p0f/3.05b/p0f.fp"

/** The magic number for this plugin - "p0fP" */
#define CORSARO_P0F_MAGIC 0x70306650

/** The name of this plugin - should match the file name */
#define PLUGIN_NAME "p0f"

/** Common plugin information across all instances */
static corsaro_plugin_t corsaro_p0f_plugin = {
  PLUGIN_NAME,                                 /* name */
  CORSARO_PLUGIN_ID_P0F,                         /* id */
  CORSARO_P0F_MAGIC,                             /* magic */
  CORSARO_PLUGIN_GENERATE_PTRS(corsaro_p0f),       /* func ptrs */
  CORSARO_PLUGIN_GENERATE_TAIL,
};

#if 0
/** Holds the state for an instance of this plugin */
struct corsaro_p0f_state_t {
};

/** Extends the generic plugin state convenience macro in corsaro_plugin.h */
#define STATE(corsaro)						\
  (CORSARO_PLUGIN_STATE(corsaro, p0f, CORSARO_PLUGIN_ID_P0F))
#endif

/** Extends the generic plugin plugin convenience macro in corsaro_plugin.h */
#define PLUGIN(corsaro)						\
  (CORSARO_PLUGIN_PLUGIN(corsaro, CORSARO_PLUGIN_ID_P0F))

/* == PUBLIC PLUGIN FUNCS BELOW HERE == */

corsaro_plugin_t *corsaro_p0f_alloc(corsaro_t *corsaro)
{
  return &corsaro_p0f_plugin;
}

int corsaro_p0f_probe_filename(const char *fname)
{
  /* look for 'corsaro_p0f' in the name */
  return corsaro_plugin_probe_filename(fname, &corsaro_p0f_plugin);
}

int corsaro_p0f_probe_magic(corsaro_in_t *corsaro, corsaro_file_in_t *file)
{
  /* we don't write any output files */
  return 0;
}

int corsaro_p0f_init_output(corsaro_t *corsaro)
{
  /* 12/21/12 - ak notes that read_config takes a pointer to a uint8_t. which
     they then proceed to cast to char *. gross */
  /* 02/21/13 - ak notes that this causes a memory leak because read_config
     malloc's memory which is never freed. Because the p0f plugin is shady at
     best, I'm not going to fix this, but note that if you use libcorsaro and
     p0f, it will leak each time it is init'd */
  read_config((uint8_t*)&(FINGERPRINT_FILE));
  return 0;
}

int corsaro_p0f_init_input(corsaro_in_t *corsaro)
{
  return -1;
}

int corsaro_p0f_close_input(corsaro_in_t *corsaro)
{
  return -1;
}

int corsaro_p0f_close_output(corsaro_t *corsaro)
{
  return 0;
}

off_t corsaro_p0f_read_record(struct corsaro_in *corsaro,
			  corsaro_in_record_type_t *record_type,
			  corsaro_in_record_t *record)
{
  /* This plugin wrote no data... */
  return -1;
}

off_t corsaro_p0f_read_global_data_record(struct corsaro_in *corsaro,
			      enum corsaro_in_record_type *record_type,
			      struct corsaro_in_record *record)
{
  /* we write nothing to the global file. someone messed up */
  return -1;
}

int corsaro_p0f_start_interval(corsaro_t *corsaro, corsaro_interval_t *int_start)
{
  /* we don't care */
  return 0;
}

int corsaro_p0f_end_interval(corsaro_t *corsaro, corsaro_interval_t *int_end)
{
  /* we don't care */
  return 0;
}

int corsaro_p0f_process_packet(corsaro_t *corsaro,
			     corsaro_packet_t *packet)
{
  libtrace_packet_t *ltpacket = LT_PKT(packet);

  libtrace_ip_t  *ip_hdr  = NULL;
  u8 *ip_hdr_u8 = NULL;

  struct pcap_pkthdr hdr;
  /* ok, so this is technically non-portable, but there is a bug in GCC.
     see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=53119 */
  memset(&hdr, 0, sizeof(struct pcap_pkthdr));
  struct packet_data pk;
  memset(&pk, 0, sizeof(struct packet_data));

  struct tcp_sig * sig;
  struct tcp_sig_record * m;

  /* TCP SYN PACKET?*/

  /* check for ipv4 */
  if((ip_hdr = trace_get_ip(ltpacket)) == NULL)
    {
      /* not an ip packet */
      return 0;
    }

  if(ip_hdr->ip_p != TRACE_IPPROTO_TCP)
    {
      /* not a tcp packet */
      return 0;
    }

  ip_hdr_u8 = (u8*)ip_hdr;

  /* let p0f process the packet */

  hdr.ts=trace_get_timeval(ltpacket);
  hdr.len=trace_get_wire_length(ltpacket);
  hdr.caplen=trace_get_capture_length(ltpacket);
  parse_packet_helper(&pk, &hdr, ip_hdr_u8,0);

  /* the syn and syn-ack packets are the ones with the signatures we are
   * interested in */
  if (pk.tcp_type == TCP_SYN)
    {
      sig=fingerprint_tcp_simple(1, &pk);
    }
  else if (pk.tcp_type == (TCP_SYN|TCP_ACK))
    {
      sig=fingerprint_tcp_simple(0, &pk);
    }
  else
    {
      return 0;
    }

  if ((m=sig->matched))
    {

      packet->state.os_class_id = m->class_id;
      packet->state.os_name_id  = m->name_id;
      if (m->flavor != NULL)
	{
	  strncpy (packet->state.os_flavor, (char*)m->flavor,
		   CORSARO_PACKET_STATE_OS_FLAVOR_MAX_LEN);
	  packet->
	    state.os_flavor[CORSARO_PACKET_STATE_OS_FLAVOR_MAX_LEN -1] = '\0';
	}

      packet->state.flags |= CORSARO_PACKET_STATE_FLAG_P0F;

#ifdef CORSARO_P0F_DEBUG
      corsaro_log(__func__, corsaro, "FLAGS:%x   ip %s is %d %s %s",
		  packet->state.flags, inet_ntoa(ip_hdr->ip_src),
		  packet->state.os_class_id,
		  fp_os_names[packet->state.os_name_id],
		  packet->state.os_flavor);
#endif

    }

  ck_free(sig);
  return 0;
}
