//
// Created by sachetto on 08/09/2020.
//

#ifndef CWF_DEBUG_HELPER_H
#define CWF_DEBUG_HELPER_H

#define HAVE_ADDR2LINE

/* Bug in gcc prevents from using CPP_DEMANGLE in pure "C" */
#if !defined(__cplusplus) && !defined(NO_CPP_DEMANGLE)
#define NO_CPP_DEMANGLE
#endif

#define _GNU_SOURCE
#include <dlfcn.h>

#include <errno.h>
#include <memory.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef NO_CPP_DEMANGLE
#include <cxxabi.h>
#ifdef __cplusplus
using __cxxabiv1::__cxa_demangle;
#endif
#endif

#include <execinfo.h>
#include <ucontext.h>

void setup_sigsegv();

#endif // CWF_DEBUG_HELPER_H
