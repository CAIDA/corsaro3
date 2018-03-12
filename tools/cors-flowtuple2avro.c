/*
 * corsaro
 *
 * Alistair King, CAIDA, UC San Diego
 * corsaro-info@caida.org
 *
 * Copyright (C) 2017 The Regents of the University of California.
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
#include <assert.h>
#include <avro.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wandio.h>
#include "corsaro.h"
#include "corsaro_io.h"
#include "corsaro_log.h"
#include "corsaro_flowtuple.h"

/** @file
 *
 * @brief Code which uses libcorsaro and libavro to convert a binary FlowTuple
 * file to Avro
 *
 * @author Alistair King
 *
 */

/** Default to rotating output files every 60s */
#define DEFAULT_ROTATE_SECONDS 60

/** The corsaro_in object for reading the input file */
static corsaro_in_t *corsaro = NULL;

/** The record object to read into */
static corsaro_in_record_t *record = NULL;

static char *avro_template = NULL;

#define AVRO_CODEC "deflate"
#define AVRO_BLOCKSIZE 65536

static int avro_init = 0;
static avro_schema_t a_schema = {0};
static avro_file_writer_t a_writer = {0};
static int a_writer_init = 0;
static avro_value_iface_t *a_class = NULL;
static avro_value_t a_record = {0};

static uint32_t batch_len = DEFAULT_ROTATE_SECONDS;
static uint32_t current_batch = 0;

static char next_done_fname[1024];

#define RECORD_BATCH(time) ((time/batch_len)*batch_len)

/* Auto-generated schema include file
 * built by make using:
 * `xxd -i flowtuple.avsc.json flowtuple_avsc_json.inc`
 */
#include "flowtuple_avsc_json.inc"
#include "flowtuple_compact_avsc_json.inc"
static int use_compact_schema = 0;

enum {
  FIELD_TIME,
  FIELD_SRC_IP,
  FIELD_DST_IP,
  FIELD_SRC_PORT,
  FIELD_DST_PORT,
  FIELD_PROTOCOL,
  FIELD_TTL,
  FIELD_TCP_FLAGS,
  FIELD_IP_LEN,
  FIELD_PKT_CNT,
};

static int close_avro_writer()
{
  iow_t *df = NULL;

  /* close the writer */
  errno = 0;
  if (avro_file_writer_close(a_writer) != 0 || errno != 0) {
    fprintf(stderr, "ERROR: Could not close file (%s) (errno:%d)\n",
            avro_strerror(), errno);
    goto err;
  }
  /* write a "done" file */
  if ((df = wandio_wcreate(next_done_fname, WANDIO_COMPRESS_NONE, 0, O_CREAT)) ==
      NULL) {
    goto err;
  }
  wandio_wdestroy(df);

  a_writer_init = 0;

 err:
    return -1;
}

static void avro_clean()
{
  if (avro_init == 0) {
    return;
  }

  /* Free the record instance */
  avro_value_decref(&a_record);

  /* Free the generic class instance */
  avro_value_iface_decref(a_class);

  /* Free the schema */
  avro_schema_decref(a_schema);

  if (a_writer_init != 0) {
    close_avro_writer();
  }

  avro_init = 0;
}

/** Cleanup and free state */
static void clean()
{
  if (record != NULL) {
    corsaro_in_free_record(record);
    record = NULL;
  }

  if (corsaro != NULL) {
    corsaro_finalize_input(corsaro);
    corsaro = NULL;
  }

  avro_clean();
}

/** Initialize a corsaro_in object for the given file name */
static int init_corsaro(char *corsarouri)
{
  /* get an corsaro_in object */
  if ((corsaro = corsaro_alloc_input(corsarouri)) == NULL) {
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
  if (corsaro_start_input(corsaro) != 0) {
    fprintf(stderr, "could not start corsaro\n");
    clean();
    return -1;
  }

  return 0;
}

static int init_avro()
{
  const char *schema = NULL;
  int schema_len = 0;
  /* load the schema */
  if (use_compact_schema != 0) {
    schema = (const char *)flowtuple_compact_avsc_json;
    schema_len = flowtuple_compact_avsc_json_len;
  } else {
    schema = (const char *)flowtuple_avsc_json;
    schema_len = flowtuple_avsc_json_len;
  }

  if (avro_schema_from_json_length(schema, schema_len, &a_schema) != 0) {
    fprintf(stderr, "ERROR: Failed to initialize avro schema (%s)\n",
            avro_strerror());
    return -1;
  }

  /* instantiate one instance of a flowtuple record */
  if ((a_class = avro_generic_class_from_schema(a_schema)) == NULL) {
    fprintf(stderr, "ERROR: Failed to create avro record class (%s)\n",
            avro_strerror());
    return -1;
  }

  if (avro_generic_value_new(a_class, &a_record) != 0) {
    fprintf(stderr, "ERROR: Failed to create avro record instance (%s)\n",
            avro_strerror());
    return -1;
  }

  avro_init = 1;

  return 0;
}

static int create_avro_writer(uint32_t time)
{
  char buf[1024];
  char *fname = NULL;

  /* build the file name */
  if ((fname = corsaro_generate_file_name(avro_template, NULL,
                                          buf, time, -1)) == NULL) {
    fprintf(stderr, "ERROR: Could not build file name from template '%s'\n",
            avro_template);
    goto err;
  }
  strcpy(next_done_fname, fname);
  strcat(next_done_fname, ".DONE");

  fprintf(stderr, "INFO: Creating new avro file (%s)\n", fname);

  /* create the avro file writer */
  /* TODO: consider using wandio */
  if (avro_file_writer_create_with_codec(fname, a_schema, &a_writer,
                                         AVRO_CODEC, AVRO_BLOCKSIZE) != 0) {
    fprintf(stderr, "ERROR: Failed to create avro output file %s (%s)\n",
            fname, avro_strerror());
    goto err;
  }

  free(fname);
  a_writer_init = 1;
  current_batch = RECORD_BATCH(time);

  return 0;

 err:
  free(fname);
  return -1;
}

#define SET_BYTES_FIELD(field_idx, buf, len) \
  do {                                 \
    if (avro_value_get_by_index(&a_record, (field_idx), &val, NULL) != 0 || \
        avro_value_set_bytes(&val, (buf), (len)) != 0) {                \
      fprintf(stderr, "ERROR: Could not set value for field %d (%s)\n", \
              (field_idx), avro_strerror());                            \
      goto err;                                                         \
    }                                                                   \
  } while(0)

static int fill_record_compact(corsaro_flowtuple_t *tuple, uint32_t time)
{
  avro_value_t val;
  uint32_t tmp;

  /* populate the record (NETWORK BYTE ORDER) */

  /* time (4) */
  SET_BYTES_FIELD(FIELD_TIME, &time, 4);

  /* src_ip (4) */
  SET_BYTES_FIELD(FIELD_SRC_IP, &tuple->src_ip, 4);

  /* dst_ip (4) */
  tmp = CORSARO_FLOWTUPLE_SIXT_TO_IP(tuple);
  SET_BYTES_FIELD(FIELD_DST_IP, &tmp, 4);

  /* src_port (2) */
  SET_BYTES_FIELD(FIELD_SRC_PORT, &tuple->src_port, 2);

  /* dst_port (2) */
  SET_BYTES_FIELD(FIELD_DST_PORT, &tuple->dst_port, 2);

  /* protocol (1) */
  SET_BYTES_FIELD(FIELD_PROTOCOL, &tuple->protocol, 1);

  /* ttl (1) */
  SET_BYTES_FIELD(FIELD_TTL, &tuple->ttl, 1);

  /* tcp_flags (1) */
  SET_BYTES_FIELD(FIELD_TCP_FLAGS, &tuple->tcp_flags, 1);

  /* ip_len (2) */
  SET_BYTES_FIELD(FIELD_IP_LEN, &tuple->ip_len, 2);

  /* packet_cnt (4) */
  SET_BYTES_FIELD(FIELD_PKT_CNT, &tuple->packet_cnt, 4);

  return 0;

 err:
  return -1;
}

#define SET_FIELD(ftype, field_idx, lval)                               \
  do {                                                                  \
    ftype ltmp = (lval);                                                \
    if (avro_value_get_by_index(&a_record, (field_idx), &val, NULL) != 0 || \
      avro_value_set_##ftype(&val, ltmp) != 0) {                        \
      fprintf(stderr, "ERROR: Could not set value for field %d (%s)\n", \
              (field_idx), avro_strerror());                            \
      goto err;                                                         \
    }                                                                   \
  } while(0)

static int fill_record(corsaro_flowtuple_t *tuple, uint32_t time)
{
  avro_value_t val;

  /* populate the record (NETWORK BYTE ORDER) */

  /* time (long) */
  SET_FIELD(long, FIELD_TIME, time);

  /* src_ip (long) */
  SET_FIELD(long, FIELD_SRC_IP, ntohl(tuple->src_ip));

  /* dst_ip (long) */
  SET_FIELD(long, FIELD_DST_IP, ntohl(CORSARO_FLOWTUPLE_SIXT_TO_IP(tuple)));

  /* src_port (int) */
  SET_FIELD(int, FIELD_SRC_PORT, ntohs(tuple->src_port));

  /* dst_port (int) */
  SET_FIELD(int, FIELD_DST_PORT, ntohs(tuple->dst_port));

  /* protocol (int) */
  SET_FIELD(int, FIELD_PROTOCOL, tuple->protocol);

  /* ttl (int) */
  SET_FIELD(int, FIELD_TTL, tuple->ttl);

  /* tcp_flags (int) */
  SET_FIELD(int, FIELD_TCP_FLAGS, tuple->tcp_flags);

  /* ip_len (int) */
  SET_FIELD(int, FIELD_IP_LEN, ntohs(tuple->ip_len));

  /* packet_cnt (long) */
  SET_FIELD(long, FIELD_PKT_CNT, ntohl(tuple->packet_cnt));

  return 0;

 err:
  return -1;
}

static int write_record(corsaro_flowtuple_t *tuple, uint32_t time)
{
  /* maybe rotate the output file */
  if (a_writer_init != 0 && RECORD_BATCH(time) != current_batch) {
    close_avro_writer();
  }

  if (a_writer_init == 0 &&
      create_avro_writer(time) != 0) {
    goto err;
  }
  assert(a_writer_init != 0);

  /* clear the record (do we need to do this?) */
  if (avro_value_reset(&a_record) != 0) {
    fprintf(stderr, "ERROR: Failed to reset avro record (%s)\n",
            avro_strerror());
    goto err;
  }

  if (use_compact_schema != 0) {
    if (fill_record_compact(tuple, time) != 0) {
      goto err;
    }
  } else {
    if (fill_record(tuple, time) != 0) {
      goto err;
    }
  }

  /* write the record */
  /* hax since libavro file writing really really sucks: */
  errno = 0;
  if (avro_file_writer_append_value(a_writer, &a_record) != 0 || errno != 0) {
    fprintf(stderr, "ERROR: Could not write record to file (%s) (errno:%d)\n",
            avro_strerror(), errno);
    goto err;
  }

  return 0;

 err:
  return -1;
}

static int process_flowtuple_file(char *ftfile)
{
  off_t len = 0;
  corsaro_in_record_type_t type = CORSARO_IN_RECORD_TYPE_NULL;
  corsaro_interval_t *interval;
  uint32_t time;
  corsaro_flowtuple_t *tuple;

  if (init_corsaro(ftfile) != 0) {
    goto err;
  }

  while ((len = corsaro_in_read_record(corsaro, &type, record)) > 0) {
    /* we want to know the current time, so we will watch for interval start
       records */
    switch (type) {
    case CORSARO_IN_RECORD_TYPE_IO_INTERVAL_START:
      interval = (corsaro_interval_t *)corsaro_in_get_record_data(record);
      time = interval->time;
      break;

    case CORSARO_IN_RECORD_TYPE_FLOWTUPLE_CLASS_START:
    case CORSARO_IN_RECORD_TYPE_IO_INTERVAL_END:
    case CORSARO_IN_RECORD_TYPE_FLOWTUPLE_CLASS_END:
      /* just ignore these */
      break;

    case CORSARO_IN_RECORD_TYPE_FLOWTUPLE_FLOWTUPLE:
      tuple = (corsaro_flowtuple_t *)corsaro_in_get_record_data(record);
      if (write_record(tuple, time) != 0) {
        goto err;
      }
      break;

    default:
      fprintf(stderr, "ERROR: Unhandled record type %d\n", type);
      goto err;
    }

    /* reset the type to NULL to get any record type */
    type = CORSARO_IN_RECORD_TYPE_NULL;
  }

  if (len < 0) {
    fprintf(stderr, "ERROR: corsaro_in_read_record failed to read record\n");
    goto err;
  }

  clean();
  return 0;

 err:
  clean();
  return -1;
}

/** Print usage information to stderr */
static void usage()
{
  fprintf(stderr,
          "usage: cors-flowtuple2avro [-cn] -t template ft-file [ft-file ...]\n"
          "Available options are:\n"
          "    -c                 encode using the compact FlowTuple schema\n"
          "    -n <batch-len>    rotate avro file after at n seconds "
          "(default: %d)\n"
          "    -t <template>      Avro file name template (required)\n",
          DEFAULT_ROTATE_SECONDS
  );
  fprintf(stderr,
          "\nNote: Avro file name template should contain '%%N' which will be "
          "replaced\n"
          "  by the batch number. If the file exists, it will be replaced.\n"
  );
}

int main(int argc, char **argv)
{
  int prevoptind;
  char opt;

  char **infiles = NULL;
  int infiles_cnt;

  while (prevoptind = optind,
         (opt = getopt(argc, argv, ":n:t:c?")) >= 0) {
    if (optind == prevoptind + 2 && optarg && *optarg == '-' &&
        *(optarg + 1) != '\0') {
      opt = ':';
      --optind;
    }
    switch (opt) {
    case 'c':
      use_compact_schema = 1;
      break;

    case 'n':
      batch_len = atoi(optarg);
      break;

    case 't':
      avro_template = optarg;
      break;

    case ':':
      fprintf(stderr, "ERROR: Missing option argument for -%c\n", optopt);
      usage();
      return -1;
      break;

    case '?':
    default:
      usage();
      goto err;
      break;
    }
  }

  if (optind >= argc) {
    /* no flowtuple files given */
    fprintf(stderr, "ERROR: No flowtuple file(s) given\n");
    usage();
    goto err;
  }

  infiles = &argv[optind];
  infiles_cnt = argc-optind;

  if (avro_template == NULL) {
    fprintf(stderr, "ERROR: Avro file template must be specified using -t\n");
    usage();
    goto err;
  }

  if (strstr(avro_template, "%s") == NULL) {
    fprintf(stderr, "ERROR: Avro file template must contain '%%s'\n");
    usage();
    goto err;
  }

  if (init_avro() != 0) {
    goto err;
  }

  fprintf(stderr, "INFO: Using '%s' as template for output files\n",
          avro_template);
  fprintf(stderr, "INFO: Will convert %d FlowTuple files\n", infiles_cnt);

  int i;
  for (i=0; i<infiles_cnt; i++) {
    fprintf(stderr, "INFO: Converting %s to Avro\n", infiles[i]);
    if (process_flowtuple_file(infiles[i]) != 0) {
      goto err;
    }
  }

  clean();
  return 0;

 err:
  clean();
  return -1;
}
