/*
 * Copyright 2003-2012 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2003-2012 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2004-2012 Mike Frysinger  - <vapier@gentoo.org>
 */

#include "paxinc.h"

char *xstrdup(const char *s)
{
	char *ret = strdup(s);
	if (!ret) err("Could not strdup(): %s", strerror(errno));
	return ret;
}

void *xmalloc(size_t size)
{
	void *ret = malloc(size);
	if (!ret) err("Could not malloc() %zu bytes", size);
	return ret;
}

void *xzalloc(size_t size)
{
	return memset(xmalloc(size), 0, size);
}

void *xrealloc(void *ptr, size_t size)
{
	void *ret = realloc(ptr, size);
	if (!ret) err("Could not realloc() %zu bytes", size);
	return ret;
}

void xstrncat(char **dst, const char *src, size_t *curr_len, size_t n)
{
	bool init;
	size_t new_len;

	init = *curr_len ? false : true;
	new_len = (init ? 0 : strlen(*dst)) + strlen(src);
	if (*curr_len <= new_len) {
		*curr_len = new_len + (*curr_len / 2) + 1;
		*dst = realloc(*dst, *curr_len);
		if (!*dst)
			err("could not realloc() %zu bytes", *curr_len);
		if (init)
			*dst[0] = '\0';
	}

	if (n)
		strncat(*dst, src, n);
	else
		strcat(*dst, src);
}

void xchrcat(char **dst, const char append, size_t *curr_len)
{
	static char my_app[2];
	my_app[0] = append;
	my_app[1] = '\0';
	xstrcat(dst, my_app, curr_len);
}

void *xmemdup(const void *src, size_t n)
{
	void *ret = xmalloc(n);
	memcpy(ret, src, n);
	return ret;
}

void xarraypush(array_t *arr, const void *ele, size_t ele_len)
{
	size_t n = arr->num++;
	/* We allocate one excess element so that array_for_each can
	 * always safely fetch the next element.  It's minor memory
	 * wastage to avoid having to do a len check all the time.
	 */
	arr->eles = xrealloc_array(arr->eles, arr->num + 1, sizeof(ele));
	arr->eles[n] = xmemdup(ele, ele_len);
}

void xarrayfree(array_t *arr)
{
	array_t blank = array_init_decl;
	size_t n;

	for (n = 0; n < arr->num; ++n)
		free(arr->eles[n]);
	free(arr->eles);

	*arr = blank;
}

char *array_flatten_str(array_t *array)
{
	size_t n, len = 0;
	char *str, *ret = NULL;

	array_for_each(array, n, str) {
		if (ret)
			xchrcat(&ret, ',', &len);
		xstrcat(&ret, str, &len);
	}

	return ret;
}
