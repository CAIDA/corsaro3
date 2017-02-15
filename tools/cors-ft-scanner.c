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

#include "libtrace.h"

#include "corsaro.h"
#include "corsaro_log.h"
#include "corsaro_io.h"

#include "libpatricia/patricia.h"
#include "corsaro_flowtuple.h"

#define CORSARO_FILTER_MAX_LINE_LEN 1024

/** @file
 *
 * @brief Code which uses libcorsaro to convert an corsaro output file to ascii
 *
 * @author Alistair King
 *
 */


typedef struct corsaro_ft_scannerXX_list {
  uint32_t time;
  uint32_t dst_ip;
  uint32_t src_ip;
  uint16_t dst_port;
  uint16_t protocol;
  struct corsaro_ft_scannerXX_list * next;
} PACKED corsaro_ft_scannerXX_list_t;


typedef struct corsaro_ft_scannerXX_value {
  uint32_t start_time;
  uint32_t end_time;
  uint32_t num_values;
  struct corsaro_ft_scannerXX_list * scanner_list;
} PACKED corsaro_ft_scannerXX_value_t;


typedef struct corsaro_ft_scannerXX_key {
  uint32_t src_ip;
  uint16_t dst_port;
  uint16_t protocol;
} PACKED corsaro_ft_scannerXX_key_t;

/** Convenience macro to help with the hashing function */
#define CORSARO_SCANNER_SHIFT_AND_XOR(value)  h = ((h<<5) ^ ((h&0xf8000000)>>27)) ^ value

static inline khint32_t corsaro_ft_scannerXX_hash_func(corsaro_ft_scannerXX_key_t* t)
{
  khint32_t h=(khint32_t) t->src_ip;
  CORSARO_SCANNER_SHIFT_AND_XOR(t->src_ip*13);
  CORSARO_SCANNER_SHIFT_AND_XOR (((t->protocol*t->protocol+6) * (t->dst_port+91)));
  return h;
  
}

#define corsaro_ft_scannerXX_hash_eq(alpha, bravo) \
  ((alpha)->src_ip    == (bravo)->src_ip && \
   (alpha)->dst_port    == (bravo)->dst_port && \
   (alpha)->protocol    == (bravo)->protocol)


static void scannerXX_free(corsaro_ft_scannerXX_key_t * t){
  free(t);
}



/** Initialize the hash functions and datatypes */
KHASH_INIT(scannerXX, corsaro_ft_scannerXX_key_t*, corsaro_ft_scannerXX_value_t*, 1, corsaro_ft_scannerXX_hash_func, corsaro_ft_scannerXX_hash_eq)
KHASH_INIT(known_scanners_map, corsaro_ft_scannerXX_key_t*, uint32_t, 1, corsaro_ft_scannerXX_hash_func, corsaro_ft_scannerXX_hash_eq)

//KHASH_MAP_INIT_INT(scannerXX, corsaro_ft_scannerXX_value_t*)
//KHASH_MAP_INIT_INT(known_scanners_map, corsaro_ft_scannerXX_value_t*)


static khash_t(known_scanners_map) * known_scanners = NULL;
static khash_t(scannerXX) * find_scanners = NULL;

static corsaro_in_t *corsaro = NULL;
static corsaro_in_record_t *record = NULL;

/** The amount of time to wait until we dump the hash */
static int interval = 300;

/** How often do we clear things that are no good */
static int clear_interval = 60;
static uint32_t last_clear = 0;
			  static uint32_t current_interval_time = 0;

static int scan_max = 25;

/** The number of flowtuple records we have processed */
static uint64_t flowtuple_cnt = 0;


/** the END time of the interval that we last dumped data */
static corsaro_interval_t last_dump_end = {
  CORSARO_MAGIC,
  CORSARO_MAGIC_INTERVAL,
  0,
  0
};

/** The time that we need to dump the next interval at */
static int next_interval = 0;
/** The time that the last interval ended */
static corsaro_interval_t last_interval_end = {
  CORSARO_MAGIC,
  CORSARO_MAGIC_INTERVAL,
  0,
  0
};







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
  char prefix_start[CORSARO_FILTER_MAX_LINE_LEN];
  char *ipstr;
  uint32_t ipstr_len;
  char *mask;
  char *as_start;

  while (fgets(line, CORSARO_FILTER_MAX_LINE_LEN, mapping_fp))
    {
      /* format is:
         ip       mask       asnum
      */
      ipstr = strtok(line, "\t");
      if (ipstr == NULL)
        {
          continue;
        }
      strncpy(prefix_start, ipstr, CORSARO_FILTER_MAX_LINE_LEN);
      ipstr_len=strlen(ipstr);
      prefix_start[ipstr_len]='/';
      prefix_start[ipstr_len+1]='\0';

      mask = strtok(NULL, "\t");
      if (mask == NULL)
        {
          continue;
        }
      strncat(prefix_start, mask, CORSARO_FILTER_MAX_LINE_LEN-ipstr_len-3);

      as_start = strtok(NULL, "\t");
      if (as_start == NULL)
        {
          continue;
        }

      node = make_and_lookup(ret, prefix_start);
      uint64_t fixme = atoi(as_start);
      node->user1 = (void*) fixme;
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


static void scanner_print_64(corsaro_ft_scannerXX_key_t * scan_key, corsaro_ft_scannerXX_value_t * scan_value)
//static void scanner_print_64(uint64_t scan_key, corsaro_ft_scannerXX_value_t * scan_value)
{
  char ip_a[16];
  uint32_t tmp;

  tmp = scan_key->src_ip;
  //tmp=(scan_key >> 32);
  inet_ntop(AF_INET,&tmp, &ip_a[0], 16);

  fprintf(stdout, "%s"
	  "|%"PRIu16"|%"PRIu16
	  "|%"PRIu32"|%"PRIu32
	  "|%"PRIu32"\n",                                        
          ip_a, 
          ntohs(scan_key->dst_port),
	  //ntohs((scan_key << 32)>>48),
          scan_key->protocol, 
	  //(scan_key << 48) >> 48,
	  scan_value->start_time,
	  scan_value->end_time,
	  scan_value->num_values);
}

static int remove_old_from_value (uint32_t current_time, corsaro_ft_scannerXX_value_t * scan_value, corsaro_ft_scannerXX_key_t * scan_key){
  /* modes: remove everything before a certain time (current_time!=0, scan_key == NULL) or remove everything that belongs to a certain ip (current_time=0, scan_key != NULL) or remove everything (current_time ==0 and scan_key == NULL)  */


  corsaro_ft_scannerXX_list_t * scan_list;
  corsaro_ft_scannerXX_list_t * temp;
  corsaro_ft_scannerXX_list_t * first;
  uint8_t looking_first=1;



  scan_list=scan_value->scanner_list;
  first=scan_list;
  while (scan_list != NULL &&\
	 ((current_time == 0)  || (current_time - scan_list->time  > interval))){
    if (scan_key==NULL || (scan_list->src_ip == scan_key->src_ip && scan_list->dst_port == scan_key->dst_port && scan_list->protocol == scan_key->protocol)) {
      temp=scan_list->next;
      free(scan_list);
      scan_list=temp;
      first=temp;
    } else {
      if (looking_first){
	first=scan_list;
	looking_first=0;
	scan_list=scan_list->next;
      }
    }
  }

  /* check to see if this has no values left */
  if (first == NULL) {
    free(scan_value);
    return 1;
  }

  scan_value->scanner_list=first;
  scan_value->start_time=first->time;

  return 0;
}


static void remove_old()
{
  khiter_t k;

  /* dump the hash */
  if(kh_size(find_scanners) > 0)
    {
      for(k = kh_begin(find_scanners); k != kh_end(find_scanners); ++k)
	{
	  if(kh_exist(find_scanners, k))
	    {
	      if (remove_old_from_value (last_interval_end.time, kh_value(find_scanners, k), NULL))
		{
		  kh_del(scannerXX, find_scanners, k);
		}
	      
	    }
	}
    }
  /* move on to the next interval start */
  last_dump_end.number++;
  /* move on to the next interval end */
  last_interval_end.number++;
  /* translate from int_end to int_start */
  last_dump_end.time = last_interval_end.time+1;
}


static int process_flowtuple(corsaro_flowtuple_t *tuple, patricia_tree_t * pt, patricia_tree_t * pt_dst)
{
  int i;
  int value;
  int yes_src = 0;
  int yes_dst = 0;
  if (pt == NULL)
    {
      yes_src=1;
    }
  else
    {
      patricia_node_t *node = NULL;  
      prefix_t * p;
      struct in_addr sin;
      sin.s_addr=tuple->src_ip;
      p=New_Prefix(AF_INET, &sin, 32);
      if ((node=patricia_search_best(pt,p)) 
	  != NULL)
	{
	  /* found it, the as number is in node->user1 */
	  yes_src=((uint32_t) node->user1);  /* gives a warning, 
						  we are using a void* to store an uint32_t 
						  instead of pointing to a struct with a uint32_t
					 */
	}
      free(p);
    }
  
  if (yes_src) {  /* don't bother with the dst if we are excluding the src */
    if (pt_dst == NULL)
      {
	yes_dst=1;
      }
    else
      {
	patricia_node_t *node = NULL;  
	prefix_t * p;
	struct in_addr sin;
	sin.s_addr=CORSARO_FLOWTUPLE_SIXT_TO_IP(tuple);
	p=New_Prefix(AF_INET, &sin, 32);
	if ((node=patricia_search_best(pt_dst,p)) 
	    != NULL)
	  {
	    /* found it, the as number is in node->user1 */
	    yes_dst=((uint32_t) node->user1);  /* gives a warning, 
						  we are using a void* to store an uint32_t 
						  instead of pointing to a struct with a uint32_t
					       */
	  }
	free(p);
      }
  }

  if (yes_src && yes_dst){
    khiter_t k, khiter;
    int khret;

    corsaro_ft_scannerXX_key_t key;
    corsaro_ft_scannerXX_key_t * new_key;

    key.src_ip = tuple->src_ip;
    key.dst_port = tuple->dst_port;
    key.protocol = tuple->protocol;
    if (!(key.protocol==6 || key.protocol ==17))
      key.dst_port=0;
    /* Is the key in the list of scanners we are considering? */
    k = kh_get(scannerXX, find_scanners, &key);
    if (k == kh_end(find_scanners))
      {
	/** NO?  Add it **/
	if((new_key = malloc(sizeof(corsaro_ft_scannerXX_key_t))) == NULL)
	{
	 fprintf(stderr, "malloc failed (key)");
	 return -1;
	}
  
	/* fill it */
	memcpy(new_key, &key, sizeof(corsaro_ft_scannerXX_key_t));
	khiter = kh_put(scannerXX, find_scanners, new_key, &khret);
    
	if (!khret || khiter==kh_end(find_scanners))
	  {
	    fprintf(stderr, "error creating hash %d %d\n", khret, khiter==kh_end(find_scanners));
	    return -1;
	  }
              
	/* create a new value */
	if((kh_value(find_scanners, khiter) = malloc(sizeof(corsaro_ft_scannerXX_value_t))) == NULL)
	  {
	    fprintf(stderr, "malloc failed (value)");
	    return -1;
	  }

	/* fill it */
	kh_value(find_scanners, khiter)->start_time=current_interval_time;
	kh_value(find_scanners, khiter)->end_time=current_interval_time;
	kh_value(find_scanners, khiter)->num_values=0;
	if ((kh_value(find_scanners, khiter)->scanner_list = malloc(sizeof(corsaro_ft_scannerXX_list_t))) == NULL)
	  {
	    fprintf(stderr, "malloc failed (scan_list)");
	    return -1;
	  }

	(kh_value(find_scanners, khiter)->scanner_list)->src_ip=key.src_ip;
	(kh_value(find_scanners, khiter)->scanner_list)->dst_port=key.dst_port;
	(kh_value(find_scanners, khiter)->scanner_list)->protocol=key.protocol;
	(kh_value(find_scanners, khiter)->scanner_list)->time=current_interval_time;
	(kh_value(find_scanners, khiter)->scanner_list)->dst_ip=CORSARO_FLOWTUPLE_SIXT_TO_IP(tuple);
	(kh_value(find_scanners, khiter)->scanner_list)->next=NULL;
	assert (scan_max > 1); /* this would print out everything*/
	
      }
    else
      {
	/** YES? **/
	/*** clean up by removing all the old ***/
	if (remove_old_from_value (current_interval_time, kh_value(find_scanners, k), NULL))
	  {
	    kh_del(scannerXX, find_scanners, k);
	    
	    /* in removing all the old, we deleted everything and freed the value.  so create a new one. */
	    
	    if((new_key = malloc(sizeof(corsaro_ft_scannerXX_key_t))) == NULL)
	      {
		fprintf(stderr, "malloc failed (key)");
		return -1;
	      }

	    /* fill it */
	    memcpy(new_key, &key, sizeof(corsaro_ft_scannerXX_key_t));
	    khiter = kh_put(scannerXX, find_scanners, new_key, &khret);

	    if (!khret || khiter==kh_end(find_scanners))
	      {
		fprintf(stderr, "error creating hash %d %d\n", khret, khiter==kh_end(find_scanners));
		return -1;
	      }


	    /* create a new value */
	    if((kh_value(find_scanners, khiter) = malloc(sizeof(corsaro_ft_scannerXX_value_t))) == NULL)
	      {
		fprintf(stderr, "malloc failed (value)");
		return -1;
	      }
    
	    /* fill it */
	    kh_value(find_scanners, khiter)->start_time=current_interval_time;
	    kh_value(find_scanners, khiter)->end_time=current_interval_time;
	    kh_value(find_scanners, khiter)->num_values=0;
	    if ((kh_value(find_scanners, khiter)->scanner_list = malloc(sizeof(corsaro_ft_scannerXX_list_t))) == NULL)
	      {
		fprintf(stderr, "malloc failed (scan_list)");
		return -1;
	      }
	    (kh_value(find_scanners, khiter)->scanner_list)->time=current_interval_time;
	    (kh_value(find_scanners, khiter)->scanner_list)->dst_ip=CORSARO_FLOWTUPLE_SIXT_TO_IP(tuple);
	    (kh_value(find_scanners, khiter)->scanner_list)->next=NULL;
	    (kh_value(find_scanners, khiter)->scanner_list)->src_ip=key.src_ip;
	    (kh_value(find_scanners, khiter)->scanner_list)->dst_port=key.dst_port;
	    (kh_value(find_scanners, khiter)->scanner_list)->protocol=key.protocol;
	    assert (scan_max > 1); /* this would print out everything*/
	  }
	else
	  {
	    /*** traverse the list looking for the IP ***/
	    corsaro_ft_scannerXX_list_t * scan_list = kh_value(find_scanners, k)->scanner_list;
	    corsaro_ft_scannerXX_list_t * prev=NULL;
	    corsaro_ft_scannerXX_list_t * temp=NULL;
	    int count=0;
	    int vals_in_list = 0;

	    while (scan_list != NULL){
	      if (scan_list->dst_ip==CORSARO_FLOWTUPLE_SIXT_TO_IP(tuple)  && \
		  scan_list->src_ip == tuple->src_ip &&\
		  scan_list->protocol == tuple->protocol &&\
		  scan_list->dst_port==tuple->dst_port){
		/**** Found? Remove it ****/
		if (prev == NULL)
		  {
		    kh_value(find_scanners, k)->scanner_list=scan_list->next;
		  }
		else
		  {
		    prev->next=scan_list->next;
		  }
		free(scan_list);
		count-=1;
		vals_in_list-=1;
	      }
	      else { 
		count += (scan_list->src_ip == tuple->src_ip &&		\
			  scan_list->protocol == tuple->protocol &&	\
			  scan_list->dst_port==tuple->dst_port);
		//fprintf (stderr, "%d %d matching %x %x %d %d %d %d\n",  count, vals_in_list, scan_list->src_ip, tuple->src_ip, scan_list->protocol, tuple->protocol, scan_list->dst_port, tuple->dst_port);
		prev=scan_list;
		vals_in_list+=1;
	      }
	      scan_list=scan_list->next;
	    }
	    count+=1;
	    vals_in_list+=1;
	    /**** Add the Scanner to the END - prev is the last value ****/
	    if (prev == NULL) 
	      {
		if ((kh_value(find_scanners, k)->scanner_list = malloc(sizeof(corsaro_ft_scannerXX_list_t))) == NULL)
		  {
		    fprintf(stderr, "malloc failed (scan_list)");
		    return -1;
		  }
		(kh_value(find_scanners, k)->scanner_list)->time=current_interval_time;
		(kh_value(find_scanners, k)->scanner_list)->dst_ip=CORSARO_FLOWTUPLE_SIXT_TO_IP(tuple);
		(kh_value(find_scanners, k)->scanner_list)->next=NULL;
		kh_value(find_scanners, k)->num_values=0;
		kh_value(find_scanners, k)->start_time=current_interval_time;
		kh_value(find_scanners, k)->end_time=current_interval_time;
		(kh_value(find_scanners, k)->scanner_list)->src_ip=tuple->src_ip;
		(kh_value(find_scanners, k)->scanner_list)->dst_port=tuple->dst_port;
		(kh_value(find_scanners, k)->scanner_list)->protocol=tuple->protocol;
	      }
	    else
	      {
		if ((temp = malloc(sizeof(corsaro_ft_scannerXX_list_t))) == NULL)
		  {
		    fprintf(stderr, "malloc failed (scan_list)");
		    return -1;
		  }
		prev->next=temp;
		temp->time=current_interval_time;
		temp->dst_ip=CORSARO_FLOWTUPLE_SIXT_TO_IP(tuple);
		temp->src_ip=tuple->src_ip;
		temp->dst_port=tuple->dst_port;
		temp->protocol=tuple->protocol;
		temp->next=NULL;
		kh_value(find_scanners, k)->end_time=current_interval_time;
		/**** Check to see if this makes this IP a scanner ****/	   
		if (count >= scan_max) {
		  /***** Print it *****/
		  kh_value(find_scanners, k)->num_values=count;
		  scanner_print_64(&key, kh_value(find_scanners, k));
		  /***** Remove it from find_scanners *****/
		  if (vals_in_list != count){
		    fprintf(stderr, "vals = %d, count = %d\n", vals_in_list, count);
		  }
		  if (remove_old_from_value(0, kh_value(find_scanners, k), &key))
		    {
		      kh_del(scannerXX, find_scanners, k);
		    }
		  /***** add it known_scanners *****/
		  //uint64_t key_64 = tuple->src_ip;
		  //key_64= (key_64 << 16) | tuple->dst_port;
		  //key_64= (key_64 <<16) | tuple->protocol;
		  if((new_key = malloc(sizeof(corsaro_ft_scannerXX_key_t))) == NULL)
		    {
		      fprintf(stderr, "malloc failed (key)");
		      return -1;
		    }

		  /* fill it */
		  memcpy(new_key, &key, sizeof(corsaro_ft_scannerXX_key_t));
		  khiter = kh_put(known_scanners_map, known_scanners, new_key, &khret);
		}
	      }
	  }
      }
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

   /** The name of the file which contains the list of input files */
  char *flist_name = NULL;
  /** A pointer to the file which contains the list of input files */
  FILE *flist = NULL;
  /** The file currently being processed by corsaro */
  char file[1024];

  corsaro_in_record_type_t type = CORSARO_IN_RECORD_TYPE_NULL;
  off_t len = 0;

  corsaro_flowtuple_t *tuple;

  int wanted_n_fields = 0;

  patricia_tree_t* pt;  /* for sources */
  patricia_tree_t* pt_dst;
  static const char novalue []="None";

  corsaro_interval_t *interval_record;

  khiter_t k;
  corsaro_ft_scannerXX_key_t key;
  //uint64_t key;
  
  while((opt = getopt(argc, argv, "i:I:m:?")) >= 0)
    {
      switch(opt)
	{
	case 'i':
	  interval = atoi(optarg);
	  break;
	case 'I':
	  clear_interval=atoi(optarg);
	  break;
	case 'm':
	  scan_max=atoi(optarg);
	  break;
	case '?':
	  usage(argv[0]);
	  exit(0);
	  break;

	default:
	  usage(argv[0]);
	  exit(-1);
	}
    }


  if(!((optind == argc - 1) || (optind == argc - 2) || (optind == argc - 3)))
    {
      usage(argv[0]);
      exit(-1);
    }

  /* argv[1] is the list of corsaro files */	
  flist_name = argv[optind];

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

  known_scanners = kh_init(known_scanners_map);
  find_scanners = kh_init(scannerXX);
  
  /* argv[2] is a file that has the networks to include as sources */
  if (optind>=argc - 3 && (strcmp(argv[optind+1], novalue) !=0))
    {
      if ((pt = corsaro_filter_read_networks(argv[optind+1])) == NULL)
	{
	  fprintf(stderr, "failed to get list of ip address (%s)\n", argv[optind+1]);
	  return -1;
	}
    }
  else
    {
      pt=NULL;
    }


  /* argv[3] is a file that has the networks to include as destinations */
  if (optind>=argc - 3 && (strcmp(argv[optind+2], novalue) !=0))
    {
      if ((pt_dst = corsaro_filter_read_networks(argv[optind+2])) == NULL)
	{
	  fprintf(stderr, "failed to get list of ip address (%s)\n", argv[optind+2]);
	  return -1;
	}
    }
  else
    {
      pt_dst=NULL;
    }
  
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

	    if(interval_record->time <= last_dump_end.time)
	      {
		fprintf(stderr, "ERROR: decrease in timestamp.\n"
			"Are the input files sorted properly?\n");
		clean();
		return -1;
	      }

	    if(flowtuple_cnt == 0)
	      {
		last_dump_end.time = interval_record->time;
		next_interval = interval_record->time + clear_interval;
	      }

	    /* an interval of 0 means dump at the source interval */
	    if(last_interval_end.time > 0)
	      {
		if(clear_interval == 0)
		  {
		    remove_old();
		  } 
		else if(clear_interval > 0)
		  {
		    remove_old();
		    while(interval_record->time >= next_interval)
		      {
			next_interval += clear_interval;
		      }
		  }
		/* else, if interval < 0, only dump at the end */	
	      }
	  }
	else if(type == CORSARO_IN_RECORD_TYPE_IO_INTERVAL_END)
	  {
	    interval_record = (corsaro_interval_t *)
	      corsaro_in_get_record_data(record);

	    last_interval_end.time = interval_record->time;
    
	  }
	else if(type == CORSARO_IN_RECORD_TYPE_FLOWTUPLE_FLOWTUPLE)
	  {
	    tuple = (corsaro_flowtuple_t *)corsaro_in_get_record_data(record);
	    flowtuple_cnt++;
	    if (tuple->protocol == 6 || tuple->protocol == 17 || (tuple->protocol == 1 && tuple->src_port == htons(8) && tuple->dst_port == 0)){
	      /*check to see if source is known scanner*/
	      key.src_ip=tuple->src_ip;
	      key.dst_port=tuple->dst_port;
	      key.protocol=tuple->protocol;
	      k = kh_get(known_scanners_map, known_scanners, &key);
	      if (k == kh_end(known_scanners))
		{
		  process_flowtuple(tuple, pt, pt_dst);
		}
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

  /* free stuff */
  last_interval_end.time = 0;
  remove_old();
  /* empty the hashes */
  kh_free(scannerXX, find_scanners, &scannerXX_free);
  kh_destroy(scannerXX, find_scanners);
  find_scanners=NULL;
  kh_destroy(known_scanners_map, known_scanners);
  known_scanners=NULL;

  fclose(flist);
  if (pt!=NULL)
    Destroy_Patricia(pt, NULL);
  return 0;
}
