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

#include <arpa/inet.h>
#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h> 
#include <time.h>

#include "libtrace.h"

#include "corsaro.h"
#include "corsaro_log.h"
#include "corsaro_io.h"

#include "corsaro_flowtuple.h"

#include "ksort.h" 

#include "libpatricia/patricia.h"

#define CORSARO_FILTER_MAX_LINE_LEN 1024

#define simple_compare(a,b) ((a) < (b))

KSORT_INIT(seen_dest, uint32_t, simple_compare);

KHASH_MAP_INIT_INT(seen_dest, uint16_t)
KHASH_MAP_INIT_INT(proto_port, uint32_t);

typedef struct corsaro_ft_chXX_value {
  uint16_t dsts_with_prng_error;
  uint16_t dsts_without_prng_error;
  uint16_t num_flows;
  uint16_t all_same_packet_size;
  uint32_t num_packets;
  uint32_t sum_packet_size;
  uint32_t num_2_packets;
  //uint32_t second_byte [8];
  //uint32_t third_byte [8];
  //uint32_t fourth_byte [8];
  khash_t(seen_dest) *h;
  //khash_t(seen_dest) *slash_24s;
  uint32_t first_time;
  uint32_t last_time;
} PACKED corsaro_ft_chXX_value_t;


typedef struct corsaro_ft_chXX_key {
  uint32_t src_ip;
  uint16_t dst_port;
  uint16_t protocol;
} PACKED corsaro_ft_chXX_key_t;




/** Convenience macro to help with the hashing function */
#define CORSARO_SCANNER_SHIFT_AND_XOR(value)  h = ((h<<5) ^ ((h&0xf8000000)>>27)) ^ value

static inline khint32_t corsaro_ft_chXX_hash_func(corsaro_ft_chXX_key_t* t)
{
khint32_t h=(khint32_t) t->src_ip;
CORSARO_SCANNER_SHIFT_AND_XOR(t->src_ip*13);
CORSARO_SCANNER_SHIFT_AND_XOR (((t->protocol*t->protocol+6) * (t->dst_port+91)));
return h;
}

#define corsaro_ft_chXX_hash_eq(alpha, bravo) \
  ((alpha)->src_ip    == (bravo)->src_ip && \
    (alpha)->dst_port    == (bravo)->dst_port && \
   (alpha)->protocol    == (bravo)->protocol)


static void chXX_free(corsaro_ft_chXX_key_t * t){
  free(t);
}



KHASH_INIT(chXX, corsaro_ft_chXX_key_t*, corsaro_ft_chXX_value_t*, 1, corsaro_ft_chXX_hash_func, corsaro_ft_chXX_hash_eq)



static khash_t(chXX) * c_hash = NULL;
static khash_t(seen_dest) * d_hash=NULL;

static corsaro_in_t *corsaro = NULL;
static corsaro_in_record_t *record = NULL;

static uint32_t current_interval_time = 0;

/** The number of flowtuple records we have processed */
static uint64_t flowtuple_cnt = 0;

uint32_t interval_ct =0;



/** function to read file with ips and store in patricia tree.  Pretty much the same as patricia.cc */
patricia_tree_t *corsaro_filter_read_networks(char *routeviewsfilename)
{
  fprintf(stderr, "Loading file %s\n", routeviewsfilename);

  FILE *mapping_fp = fopen (routeviewsfilename, "r");
  if (mapping_fp == NULL)
    {
      return NULL;
    }
  
  patricia_tree_t *tree;
  patricia_node_t *node;


  patricia_tree_t *ret = New_Patricia(32);
  
  char line[CORSARO_FILTER_MAX_LINE_LEN];
  char ipstr[CORSARO_FILTER_MAX_LINE_LEN];
  uint32_t port;
  uint32_t protocol;

  while (fgets(line, CORSARO_FILTER_MAX_LINE_LEN, mapping_fp))
    {
      /* format is:
         ip       port       protocol
      */
      sscanf(line, "%s\t%d\t%d", ipstr, &port, &protocol);
      if (ipstr[0] == '\0')
        {
          continue;
        }

      //struct proto_port_pair * this_value= (struct proto_port_pair *) malloc (sizeof (struct proto_port_pair));
      //this_value->port=htons(port);
      //this_value->protocol=protocol;
      //this_value->next=NULL;
      
      prefix_t * p;
      struct in_addr sin;
      sin.s_addr=inet_addr(ipstr);
      p=New_Prefix(AF_INET, &sin, 32);
      node = patricia_search_exact (ret, p);
      khiter_t k;
      int r;
      if (node == NULL ){
	strncat(ipstr, "/32", CORSARO_FILTER_MAX_LINE_LEN-strlen(ipstr)-3);
	node=make_and_lookup(ret, ipstr);
	node->data= kh_init(proto_port);
	k=kh_put(proto_port, node->data, protocol << 16 | htons(port), &r);
	assert(r);
      } 
      else {
	k = kh_get(proto_port, node->data, protocol << 16 | htons(port));
	if (k == kh_end((khash_t(proto_port) *) node->data)){
	  k=kh_put(proto_port, node->data, protocol << 16 | htons(port), &r);
	  assert(r);
	}
	//this_value->next=node->data;
	//node->data=this_value;
      }
      free(p);
    }
  fclose(mapping_fp);
  fprintf(stderr, "Done loading file %s\n",routeviewsfilename);
  return ret;
  
}


static void clean()
{ 
  if(record != NULL)
    {
      corsaro_in_free_record(record);
      record = NULL;
    }

  if(corsaro != NULL)
    {
      corsaro_finalize_input(corsaro);
      corsaro = NULL;
    }
}

static int init_corsaro(char *corsarouri)
{
  /* get an corsaro_in object */
  if((corsaro = corsaro_alloc_input(corsarouri)) == NULL)
    {
      fprintf(stderr, "could not alloc corsaro_in\n");
      clean();
      return -1;
    }
  
  /* get a record */
  if ((record = corsaro_in_alloc_record(corsaro)) == NULL) {
    fprintf(stderr, "could not alloc record\n");
    clean();
    return -1;
  }

  /* start corsaro */
  if(corsaro_start_input(corsaro) != 0)
    {
      fprintf(stderr, "could not start corsaro\n");
      clean();
      return -1;
    }

  return 0;
}

static uint32_t num_used(uint32_t * b)
{
  uint32_t c=0;
  for (int i=0; i< 8 ; i++){
    for (int j=0; j<32; j++){
      if ((1 << j)  & b[i])
	c+=1;
    }
  }
  return c;
}

static uint32_t max_consecutive(uint32_t *b)
{
  uint32_t consec=0;
  uint32_t max_consec=0;
  for (int i=0; i< 8 ; i++){
    for (int j=0; j<32; j++){
      if ((1 << j)  & b[i]){
	consec+=1;
      } else {
	if (consec > max_consec) {max_consec=consec;}
	consec=0;
      }
    }
  }
  if (consec > max_consec) {max_consec=consec;}
  return max_consec;
}
	


static void flowtuple_print_64(corsaro_ft_chXX_key_t * key, corsaro_ft_chXX_value_t * value)
{
  char ip_a[16];
  uint32_t tmp;
  uint32_t * sorted = malloc(sizeof(uint32_t)*kh_size(value->h));
  khiter_t k, k2;
  int j=0;
  khash_t(seen_dest) *slash_24s;
  int ret, i;
  uint32_t dsts_with_prng_error =0;

  uint32_t second_byte [8];
  uint32_t third_byte [8];
  uint32_t fourth_byte [8];
  
  uint8_t byte2, byte3, byte4;



  for (int i=0; i< 8; i++){
    second_byte[i]=0;
    third_byte[i]=0;
    fourth_byte[i]=0;
  }


  slash_24s=kh_init(seen_dest);

  for(k = kh_begin(value->h); k != kh_end(value->h); ++k)                       
    {   
      if(kh_exist(value->h, k))
	{
	  sorted[j]=kh_key(value->h, k);
	  k2 = kh_put(seen_dest, slash_24s , kh_key(value->h, k)/256, &ret);
	  byte4 = (kh_key(value->h, k) & 0x000000ff);
	  byte3 = (kh_key(value->h, k) & 0x0000ff00) >> 8;
	  byte2 = (kh_key(value->h, k) & 0x00ff0000) >> 16;

	  if (byte2 < 128 && byte4 < 128)
	    {
	      dsts_with_prng_error+=1;
	    }
	  second_byte[(byte2 & 0xe0) >> 5] |= (1<< (byte2 & 0x1f));
	  third_byte[(byte3 & 0xe0) >> 5] |= (1<< (byte3 & 0x1f));
	  fourth_byte[(byte4 & 0xe0) >> 5] |= (1<< (byte4 & 0x1f));
	  ++j;
	}
    }
  
  ks_combsort(seen_dest, kh_size(value->h), sorted);



  tmp = key->src_ip;
  inet_ntop(AF_INET,&tmp, &ip_a[0], 16);

  printf("%s|%d|%d|%d|%d|%d|%d|%f|%d|%d|%d|%d|%d|%d|%d|%d\n", 
	 ip_a,
	 kh_size(value->h),			
	 value->num_flows,
	 value->num_packets,
	 value->first_time,
	 value->last_time,
	 value->all_same_packet_size,
	 ((float)(value->sum_packet_size))/value->num_flows,
	 num_used(second_byte),				   
	 num_used(third_byte),
	 num_used(fourth_byte),
	 kh_size(slash_24s),
	 dsts_with_prng_error,			
	 sorted[kh_size(value->h)-1] - sorted[0],
	 ntohs(key->dst_port),
	 key->protocol
	 );
  /*p_from_birthday_spacing(sorted, kh_size(value->h))*/
  kh_destroy(seen_dest, slash_24s);
  free(sorted);
}


static void dump_hash(khash_t(chXX) * c_hash)
{
  khiter_t k;
  corsaro_ft_chXX_key_t * key;
  fprintf(stderr,"dump\n");

  /* dump the hash */
  if(kh_size(c_hash) > 0)
    {
      for(k = kh_begin(c_hash); k != kh_end(c_hash); ++k)
	{
	  if(kh_exist(c_hash, k))
	    {
              key = kh_key(c_hash, k);
              flowtuple_print_64(key, kh_val(c_hash, k));        
	      kh_destroy(seen_dest, kh_val(c_hash, k)->h);
	      //kh_destroy(seen_dest, kh_val(c_hash, k)->slash_24s);
	      free(kh_val(c_hash, k));
	      kh_del(chXX, c_hash, k);
	    }
	}
    }

  /* empty the hash */
  kh_free(chXX, c_hash, &chXX_free);
  kh_destroy(chXX, c_hash);
  c_hash=NULL;
}


static void not_last_day(khash_t(chXX) * c_hash)
{
  khiter_t k, k2;
  corsaro_ft_chXX_key_t * key;
  fprintf(stderr,"dump\n");

  /* dump the hash */
  if(kh_size(c_hash) > 0)
    {
      for(k = kh_begin(c_hash); k != kh_end(c_hash); ++k)
	{
	  if(kh_exist(c_hash, k))
	    {
              key = kh_key(c_hash, k);
	      if (kh_val(c_hash,k)->last_time !=0 && kh_val(c_hash, k)->last_time + 300 < interval_ct){
		for(k2 = kh_begin(kh_val(c_hash,k)->h); k2 != kh_end(kh_val(c_hash, k)->h); ++k2)
		  {
		    kh_del(seen_dest, kh_val(c_hash,k)->h, k2);
		    //kh_del(seen_dest, kh_val(c_hash,k)->slash_24s, k2);
		  }
		kh_destroy(seen_dest, kh_val(c_hash,k)->h);
		//kh_destroy(seen_dest, kh_val(c_hash,k)->slash_24s);
		kh_value(c_hash, k)->h=kh_init(seen_dest);
		//kh_value(c_hash, k)->slash_24s=kh_init(seen_dest);
		kh_val(c_hash, k)->last_time=0;
	      }
	    }
	}
    }
}






static int process_flowtuple(corsaro_flowtuple_t *tuple, khash_t(chXX) * c_hash, patricia_tree_t * pt)
{

  int i;
  int value;
  int yes_src = 0;
  if (pt != NULL && (tuple->protocol == 6 || tuple->protocol == 17 || (tuple->protocol == 1 && tuple->src_port == htons(8) && tuple->dst_port == 0)))
    {
      patricia_node_t *node = NULL;  
      prefix_t * p;
      struct in_addr sin;
      sin.s_addr=tuple->src_ip;
      p=New_Prefix(AF_INET, &sin, 32);
      if ((node=patricia_search_best(pt,p)) 
	  != NULL)
	{
	  khiter_t k = kh_get(proto_port, node->data, tuple->protocol << 16 | tuple->dst_port);
	  if (k != kh_end((khash_t(proto_port) *) node->data))
	    yes_src=1;
	  //struct proto_port_pair * tester = (struct proto_port_pair *) node->data;
	  //while (tester != NULL && !found){
	  //  //fprintf (stderr, "%x %d %d %d %d\n", tuple->src_ip, tester->protocol, tester->port, tuple->protocol, tuple->dst_port);
	  //  if (tester->protocol == tuple->protocol && tester->port == tuple->dst_port){
	  //    yes_src=in_pat_tree_action;
	  //  }
	  //  tester=tester->next;
	}
      free(p);
    }

  if (! yes_src) {
    return 0;
  }

  uint32_t packets = (uint32_t) ntohl(tuple->packet_cnt);
  uint32_t packet_size = (uint32_t) ntohs(tuple->ip_len);
  //uint8_t fourth_byte = (CORSARO_FLOWTUPLE_SIXT_TO_IP(tuple) & 0xff000000) >> 24;
  //uint8_t third_byte = (CORSARO_FLOWTUPLE_SIXT_TO_IP(tuple) & 0x00ff0000) >> 16;
  //uint8_t second_byte = (CORSARO_FLOWTUPLE_SIXT_TO_IP(tuple) & 0x0000ff00) >> 8;

  khiter_t khiter;
  int khret;
  corsaro_ft_chXX_key_t key;
  corsaro_ft_chXX_key_t* new_key;

  int ret, is_missing;
  khiter_t k;
    
  key.src_ip=tuple->src_ip;
  key.dst_port=tuple->dst_port;
  key.protocol=tuple->protocol;


  if((khiter = kh_get(chXX, c_hash, &key)) == kh_end(c_hash)){
    /*** new source ***/
    /* add it to the hash */
    if((new_key = malloc(sizeof(corsaro_ft_chXX_key_t))) == NULL)
      {
        fprintf(stderr, "malloc failed (key)");
        return -1;
      }
  
    /* fill it */
    memcpy(new_key, &key, sizeof(corsaro_ft_chXX_key_t));


    khiter = kh_put(chXX, c_hash, new_key, &khret);
    
 
    if (!khret || khiter==kh_end(c_hash))
      {
        fprintf(stderr, "error creating hash %d %d\n", khret, khiter==kh_end(c_hash));
        return -1;
      }
              
    /* create a new value */
    if((kh_value(c_hash, khiter) = malloc(sizeof(corsaro_ft_chXX_value_t))) == NULL)
      {
        fprintf(stderr, "malloc failed (value)");
        return -1;
      }
    
    /* fill it */
    //kh_value(c_hash, khiter)->dsts_with_prng_error= (second_byte < 128 && fourth_byte < 128);
    //kh_value(c_hash, khiter)->dsts_without_prng_error= (!(second_byte < 128 && fourth_byte < 128));
    kh_value(c_hash, khiter)->num_flows=1;
    kh_value(c_hash, khiter)->num_packets=packets;
    kh_value(c_hash, khiter)->num_2_packets=(packets==2);
    kh_value(c_hash, khiter)->sum_packet_size=packet_size;
    kh_value(c_hash, khiter)->all_same_packet_size=1;
    //for (int i=0; i< 8; i++){
    //  kh_value(c_hash, khiter)->second_byte[i]=0;
    //  kh_value(c_hash, khiter)->third_byte[i]=0;
    //  kh_value(c_hash, khiter)->fourth_byte[i]=0;
    //}



    //kh_value(c_hash, khiter)->second_byte[(second_byte & 0xe0) >> 5] = (1<< (second_byte & 0x1f));
    //kh_value(c_hash, khiter)->third_byte[(third_byte & 0xe0) >> 5] = (1<< (third_byte & 0x1f));
    //kh_value(c_hash, khiter)->fourth_byte[(fourth_byte & 0xe0) >> 5] = (1<< (fourth_byte & 0x1f));

	
    
    kh_value(c_hash, khiter)->h=kh_init(seen_dest);
    //kh_value(c_hash, khiter)->slash_24s=kh_init(seen_dest);
    k = kh_put(seen_dest, kh_value(c_hash, khiter)->h , ntohl(CORSARO_FLOWTUPLE_SIXT_TO_IP(tuple)), &ret);
    kh_value(kh_value(c_hash, khiter)->h , k) = tuple->src_port;
    //k = kh_put(seen_dest, kh_value(c_hash, khiter)->slash_24s , ntohl(CORSARO_FLOWTUPLE_SIXT_TO_IP(tuple))/256, &ret);
    
    kh_value(c_hash, khiter)->first_time=current_interval_time;
    kh_value(c_hash, khiter)->last_time=current_interval_time;
    
  } else {
    k = kh_get(seen_dest, kh_value(c_hash, khiter)->h, ntohl(CORSARO_FLOWTUPLE_SIXT_TO_IP(tuple)));
    if (k == kh_end(kh_value(c_hash, khiter)->h))
      {
	/*** new destination ***/
	k = kh_put(seen_dest, kh_value(c_hash, khiter)->h , ntohl(CORSARO_FLOWTUPLE_SIXT_TO_IP(tuple)), &ret);
	//if (second_byte < 128 && fourth_byte < 128) {
	//  kh_value(c_hash, khiter)->dsts_with_prng_error+=1;
	//} else {
	//  kh_value(c_hash, khiter)->dsts_without_prng_error+=1;
	//}
	//if (kh_get(seen_dest, kh_value(c_hash, khiter)->slash_24s, ntohl(CORSARO_FLOWTUPLE_SIXT_TO_IP(tuple))/256) == kh_end(kh_value(c_hash, khiter)->slash_24s))
	//{
	//  kh_put(seen_dest, kh_value(c_hash, khiter)->slash_24s , ntohl(CORSARO_FLOWTUPLE_SIXT_TO_IP(tuple))/256, &ret);
	//  }
	//kh_value(c_hash, khiter)->second_byte[(second_byte & 0xe0) >> 5] |= (1<< (second_byte & 0x1f));
	//kh_value(c_hash, khiter)->third_byte[(third_byte & 0xe0) >> 5] |= (1<< (third_byte & 0x1f));
	//kh_value(c_hash, khiter)->fourth_byte[(fourth_byte & 0xe0) >> 5] |= (1<< (fourth_byte & 0x1f));
	kh_value(c_hash, khiter)->num_flows+=1;
	kh_value(kh_value(c_hash, khiter)->h , k) = tuple->src_port;
	kh_value(c_hash, khiter)->sum_packet_size+=packet_size;
      }
    else {
      if (kh_value(kh_value(c_hash, khiter)->h, k) != tuple->src_port)
	{
	  /*** old destination, new port ***/
	  kh_value(c_hash, khiter)->num_flows+=1;
	  kh_value(kh_value(c_hash, khiter)->h , k) = tuple->src_port;
	  kh_value(c_hash, khiter)->sum_packet_size+=packet_size;
	}
    }

    /*** update packet stats for this destinaiton ***/
    if ((!kh_value(c_hash, khiter)->all_same_packet_size)	||	\
	(((float)kh_value(c_hash, khiter)->sum_packet_size)/kh_value(c_hash, khiter)->num_flows != ((float)packet_size))){
      kh_value(c_hash, khiter)->all_same_packet_size=0;
    }

    kh_value(c_hash, khiter)->num_packets+=packets;
    kh_value(c_hash, khiter)->num_2_packets+=(packets==2);
    kh_value(c_hash, khiter)->last_time=current_interval_time;

  }
  return 0;
}

static void usage(const char *name)
{
}

int main(int argc, char *argv[])
{
  int opt;
  int i;

  int field_cnt = 0;

  /** The name of the file which contains the list of input files */
  char *flist_name = NULL;
  /** A pointer to the file which contains the list of input files */
  FILE *flist = NULL;
  /** The file currently being processed by corsaro */
  char file[1024];

  corsaro_in_record_type_t type = CORSARO_IN_RECORD_TYPE_NULL;
  off_t len = 0;

  corsaro_flowtuple_t *tuple;
  corsaro_interval_t *interval_record;
  patricia_tree_t* pt = NULL;

  srand(time(NULL));

  if (argc == 1){
    fprintf(stderr, "");
    return -1;
  }

  /* argv[1] is the list of corsaro files */	
  flist_name = argv[1];

  /* read each file in the list */
  if(strcmp(flist_name, "-") == 0)
    {
      flist = stdin;
    }
  else if((flist = fopen(flist_name, "r")) == NULL)
    {
      fprintf(stderr, "failed to open list of input files (%s)\n"
	      "NB: File List MUST be sorted\n", flist_name);
      return -1;
    }


  if (argc == 3)
    {
      if ((pt = corsaro_filter_read_networks(argv[2])) == NULL)
        {
          fprintf(stderr, "failed to get list of ip address (%s)\n", argv[2]);
          return -1;
        }
    }

  c_hash = kh_init(chXX);
  d_hash = kh_init(seen_dest);
    
  while(fgets(file, sizeof(file), flist) != NULL)
    {
      /* chomp off the newline */
      file[strlen(file)-1] = '\0';

      fprintf(stderr, "processing %s\n", file);

      /* this must be done before corsaro_init_output */
      if(init_corsaro(file) != 0)
	{
	  fprintf(stderr, "failed to init corsaro\n");
	  clean();
	  return -1;
	}

  
      
      while ((len = corsaro_in_read_record(corsaro, &type, record)) > 0) {
	/* we want to know the current time, so we will watch for interval start
	   records */
	if(type == CORSARO_IN_RECORD_TYPE_IO_INTERVAL_START)
	  {
	    interval_record = (corsaro_interval_t *)
              corsaro_in_get_record_data(record);
	    current_interval_time=interval_record->time;
	    interval_ct+=1;
	    if (interval_ct % 300 == 0)
	      {
		//not_last_day(c_hash);
	      }
	  }
	else if(type == CORSARO_IN_RECORD_TYPE_IO_INTERVAL_END)
	  {
	    interval_record = (corsaro_interval_t *)
              corsaro_in_get_record_data(record);
	  }
	else if(type == CORSARO_IN_RECORD_TYPE_FLOWTUPLE_FLOWTUPLE)
	  {
	    tuple = (corsaro_flowtuple_t *)corsaro_in_get_record_data(record);

	    //if (tuple->protocol ==6 && tuple->dst_port == htons(443))
	      {
		flowtuple_cnt++;
		process_flowtuple(tuple, c_hash, pt);
	      }
	  }
	/* reset the type to NULL to indicate we don't care */
	type = CORSARO_IN_RECORD_TYPE_NULL;
      }
      
      if(len < 0)
	{
	  fprintf(stderr, "corsaro_in_read_record failed to read record\n");
	  clean();
	  return -1;
	}
      
      clean();
    }

  /* dump again if the hash is not empty */
  dump_hash(c_hash);
  fclose(flist);
}
