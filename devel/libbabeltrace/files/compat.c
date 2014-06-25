/*
 * compat/compat.c
 * a dummy file to ensure that libcompat is not empty
 */

#include <stdlib.h>

/* Some systems, such as Mac OS X, refuse to create static libraries without
 * any object files in them. Without this file, you would get an error like:
 *
 * > libtool: link: ar cru .libs/libcompat.a
 * > ar: no archive members specified
 *
 * Compiling this file, and adding its object file to libcompat, will prevent
 * the static archive for libcompat from being empty. */

#ifdef __sun
/* This declaration ensures that the library will export at least 1 symbol: */
int compat_compat_c_dummy_symbol;
#else
/* This declaration is solely to ensure that, after preprocessing,
 * this file is never empty: */
typedef int compat_compat_c_dummy_t;
#endif /* __sun */

/* EOF */
