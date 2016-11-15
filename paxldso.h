/*
 * Copyright 2003-2016 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2003-2012 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2004-2016 Mike Frysinger  - <vapier@gentoo.org>
 */

#ifndef _PAX_LDSO_H
#define _PAX_LDSO_H

/*
 * ld.so.cache logic
 */

#if !defined(__GLIBC__) && \
    !defined(__UCLIBC__)
# ifdef __ELF__
#  warning Cache support not implemented for your target
# endif
# define PAX_LDSO_CACHE 0
#else
# define PAX_LDSO_CACHE 1
#endif

#if PAX_LDSO_CACHE
extern char *ldso_cache_lookup_lib(elfobj *elf, const char *fname);
#else
static inline char *ldso_cache_lookup_lib(__unused__ elfobj *elf, __unused__ const char *fname)
{
	return NULL;
}
#endif

/*
 * ld.so.conf logic
 */

#if !defined(__GLIBC__) && \
    !defined(__UCLIBC__) && \
    !defined(__NetBSD__) && \
    !defined(__FreeBSD__) && \
    !defined(__DragonFly__)
# ifdef __ELF__
#  warning Cache config support not implemented for your target
# endif
# define PAX_LDSO_CONFIG 0
#else
# define PAX_LDSO_CONFIG 1
#endif

/* Consumers refer to ldpaths directly, so can't hide its def. */
extern array_t *ldpaths;
#if PAX_LDSO_CONFIG
extern int ldso_config_load(const char *fname);
#else
static inline int ldso_config_load(__unused__ const char *fname)
{
	return 0;
}
#endif

#if PAX_LDSO_CACHE || PAX_LDSO_CONFIG
extern void paxldso_cleanup(void);
#else
# define paxldso_cleanup()
#endif

#endif
