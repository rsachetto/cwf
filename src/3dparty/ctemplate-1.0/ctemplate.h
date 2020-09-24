/*
 * C Template Library 1.0
 *
 * Copyright 2009 Stephen C. Losen.  Distributed under the terms
 * of the GNU General Public License (GPL)
 */

#ifndef _CTEMPLATE_H
#define _CTEMPLATE_H

#include "../sds/sds.h"
#include <stdio.h>

typedef struct TMPL_varlist TMPL_varlist;
typedef struct TMPL_loop TMPL_loop;
typedef struct TMPL_fmtlist TMPL_fmtlist;
typedef void (*TMPL_fmtfunc)(const char *, FILE *, sds *);

/*
 * TMPL_fmtlist is a list of format functions, which are passed to
 * a template.  A TMPL_VAR tag can specify a format function for
 * outputting the variable with the fmt="fmtname" attribute.
 */

struct TMPL_fmtlist {
    TMPL_fmtlist *next;   /* next list member */
    TMPL_fmtfunc fmtfunc; /* pointer to format function */
    char name[1];         /* name of format function */
};

/*
 * variables are passed to a template in a tree consisting of
 * TMPL_var, TMPL_varlist and TMPL_loop nodes.
 *
 * TMPL_var is a simple variable (name and value)
 */

typedef struct TMPL_var TMPL_var;

struct TMPL_var {
    TMPL_var *next; /* next simple variable on list */
    const char *name;
    char value[1]; /* value and name stored here */
};

/*
 * TMPL_varlist is a variable list of simple variables and/or
 * loop variables
 */

struct TMPL_varlist {
    TMPL_varlist *next; /* next variable list on a list */
    TMPL_var *var;      /* list of my simple variables */
    TMPL_loop *loop;    /* list of my loop variables */
    TMPL_loop *parent;  /* my parent loop variable (if any) */
};

/* TMPL_loop is a loop variable, which is a list of variable lists */

struct TMPL_loop {
    TMPL_loop *next;       /* next loop variable on a list */
    const char *name;      /* my name */
    TMPL_varlist *varlist; /* list of my variable lists */
    TMPL_varlist *tail;    /* tail of "varlist" */
    TMPL_varlist *parent;  /* my parent variable list */
};

TMPL_varlist *TMPL_add_var(TMPL_varlist *varlist, ...);

TMPL_varlist *TMPL_add_int_var(TMPL_varlist *varlist, char *name, int value);

TMPL_varlist *TMPL_add_float_var(TMPL_varlist *varlist, char *name, float value);

TMPL_varlist *TMPL_add_double_var(TMPL_varlist *varlist, char *name, double value);

TMPL_varlist *TMPL_add_loop(TMPL_varlist *varlist, const char *name, TMPL_loop *loop);

TMPL_loop *TMPL_add_varlist(TMPL_loop *loop, TMPL_varlist *varlist);

void TMPL_free_varlist(TMPL_varlist *varlist);

TMPL_fmtlist *TMPL_add_fmt(TMPL_fmtlist *fmtlist, const char *name, TMPL_fmtfunc fmtfunc);

void TMPL_free_fmtlist(TMPL_fmtlist *fmtlist);

int TMPL_write(const char *filename, const char *tmplstr, const TMPL_fmtlist *fmtlist, const TMPL_varlist *varlist, sds *out_string, FILE *out, FILE *errout);

void TMPL_encode_entity(const char *value, FILE *out, sds *out_str);

void TMPL_encode_url(const char *value, FILE *out, sds *out_str);

TMPL_loop *TMPL_get_loop(TMPL_varlist *varlist);
TMPL_varlist *TMPL_get_loop_varlist(TMPL_loop *loop);
TMPL_varlist *TMPL_get_next_varlist(TMPL_varlist *varlist);
#endif
