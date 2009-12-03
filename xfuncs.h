/*
 * Copyright 2003-2007 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/xfuncs.h,v 1.4 2009/12/03 04:15:54 vapier Exp $
 *
 * Copyright 2003-2007 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2004-2007 Mike Frysinger  - <vapier@gentoo.org>
 */

#ifndef __XFUNCS_H__
#define __XFUNCS_H__

char *xstrdup(const char *s);
void *xmalloc(size_t size);
void *xzalloc(size_t size);
void *xrealloc(void *ptr, size_t size);
void xstrncat(char **dst, const char *src, size_t *curr_len, size_t n);
#define xstrcat(dst,src,curr_len) xstrncat(dst,src,curr_len,0)
void xchrcat(char **dst, const char append, size_t *curr_len);

#endif
