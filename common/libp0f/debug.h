/*
   p0f - debug / error handling macros
   -----------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef _HAVE_DEBUG_H
#define _HAVE_DEBUG_H

#include "types.h"
#include "p0f_config.h"

#ifdef P0F_DEBUG_BUILD
#  define DEBUG_P0F(x...) fprintf(stderr, x)
#else
#  define DEBUG_P0F(x...) do {} while (0)
#endif /* ^P0F_DEBUG_BUILD */

#define ERRORF(x...)  fprintf(stderr, x)
#define SAYF(x...)    printf(x)

#define WARN(x...) do { \
    ERRORF("[!] WARNING: " x); \
    ERRORF("\n"); \
  } while (0)

#define FATAL(x...) do { \
    ERRORF("[-] PROGRAM ABORT : " x); \
    ERRORF("\n         Location : %s(), %s:%u\n\n", \
           __FUNCTION__, __FILE__, __LINE__); \
    exit(1); \
  } while (0)

#define ABORT(x...) do { \
    ERRORF("[-] PROGRAM ABORT : " x); \
    ERRORF("\n         Location : %s(), %s:%u\n\n", \
           __FUNCTION__, __FILE__, __LINE__); \
    abort(); \
  } while (0)

#define PFATAL(x...) do { \
    ERRORF("[-] SYSTEM ERROR : " x); \
    ERRORF("\n        Location : %s(), %s:%u\n", \
           __FUNCTION__, __FILE__, __LINE__); \
    perror("      OS message "); \
    ERRORF("\n"); \
    exit(1); \
  } while (0)

#endif /* ! _HAVE_DEBUG_H */
