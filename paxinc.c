/*
 * Copyright 2003-2012 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2005-2012 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2005-2012 Mike Frysinger  - <vapier@gentoo.org>
 */

/* stick common symbols here that are needed by paxinc.h */

#define IN_paxinc
#include "paxinc.h"

char do_reverse_endian;

/* some of this ar code was taken from busybox */

#define AR_MAGIC "!<arch>"
#define AR_MAGIC_SIZE (sizeof(AR_MAGIC)-1) /* dont count null byte */
archive_handle *ar_open_fd(const char *filename, int fd, bool verbose)
{
	static archive_handle ret;
	char buf[AR_MAGIC_SIZE];

	ret.filename = filename;
	ret.fd = fd;
	ret.skip = 0;
	ret.extfn = NULL;
	ret.verbose = verbose;

	if (read(ret.fd, buf, AR_MAGIC_SIZE) != AR_MAGIC_SIZE)
		return NULL;
	if (strncmp(buf, AR_MAGIC, AR_MAGIC_SIZE))
		return NULL;

	return &ret;
}
archive_handle *ar_open(const char *filename, bool verbose)
{
	int fd;
	archive_handle *ret;

	if ((fd=open(filename, O_RDONLY)) == -1)
		errp("%s: could not open", filename);

	ret = ar_open_fd(filename, fd, verbose);
	if (ret == NULL)
		close(fd);

	return ret;
}

archive_member *ar_next(archive_handle *ar)
{
	char *s;
	ssize_t len = 0;
	static archive_member ret;

	if (ar->skip && lseek(ar->fd, ar->skip, SEEK_CUR) == -1) {
close_and_ret:
		free(ar->extfn);
		close(ar->fd);
		ar->extfn = NULL;
		ar->fd = -1;
		return NULL;
	}

	if (read(ar->fd, ret.buf.raw, sizeof(ret.buf.raw)) != sizeof(ret.buf.raw))
		goto close_and_ret;

	/* ar header starts on an even byte (2 byte aligned)
	 * '\n' is used for padding */
	if (ret.buf.raw[0] == '\n') {
		memmove(ret.buf.raw, ret.buf.raw+1, 59);
		if (read(ar->fd, ret.buf.raw+59, 1) != 1)
			goto close_and_ret;
	}

	if ((ret.buf.formatted.magic[0] != '`') || (ret.buf.formatted.magic[1] != '\n')) {
		/* When dealing with corrupt or random embedded cross-compilers, they might
		 * be abusing the archive format; only complain when in verbose mode. */
		if (ar->verbose)
			warn("%s: invalid ar entry", ar->filename);
		goto close_and_ret;
	}

	if (ret.buf.formatted.name[0] == '/' && ret.buf.formatted.name[1] == '/') {
		if (ar->extfn != NULL) {
			warn("%s: Duplicate GNU extended filename section", ar->filename);
			goto close_and_ret;
		}
		len = atoi(ret.buf.formatted.size);
		ar->extfn = xmalloc(sizeof(char) * (len + 1));
		if (read(ar->fd, ar->extfn, len) != len)
			goto close_and_ret;
		ar->extfn[len--] = '\0';
		for (; len > 0; len--)
			if (ar->extfn[len] == '\n')
				ar->extfn[len] = '\0';
		ar->skip = 0;
		return ar_next(ar);
	}

	s = ret.buf.formatted.name;
	if (s[0] == '#' && s[1] == '1' && s[2] == '/') {
		/* BSD extended filename, always in use on Darwin */
		len = atoi(s + 3);
		if (len <= (ssize_t)sizeof(ret.buf.formatted.name)) {
			if (read(ar->fd, ret.buf.formatted.name, len) != len)
				goto close_and_ret;
		} else {
			s = alloca(sizeof(char) * len + 1);
			if (read(ar->fd, s, len) != len)
				goto close_and_ret;
			s[len] = '\0';
		}
	} else if (s[0] == '/' && s[1] >= '0' && s[1] <= '9') {
		/* GNU extended filename */
		if (ar->extfn == NULL) {
			warn("%s: GNU extended filename without special data section", ar->filename);
			goto close_and_ret;
		}
		s = ar->extfn + atoi(s + 1);
	}

	snprintf(ret.name, sizeof(ret.name), "%s:%s", ar->filename, s);
	ret.name[sizeof(ret.name) - 1] = '\0';
	if ((s=strchr(ret.name+strlen(ar->filename), '/')) != NULL)
		*s = '\0';
	ret.date = atoi(ret.buf.formatted.date);
	ret.uid = atoi(ret.buf.formatted.uid);
	ret.gid = atoi(ret.buf.formatted.gid);
	ret.mode = strtol(ret.buf.formatted.mode, NULL, 8);
	ret.size = atoi(ret.buf.formatted.size);
	ar->skip = ret.size - len;

	return &ret;
}

/* Convert file perms into octal string */
const char *strfileperms(const char *fname)
{
	struct stat st;
	static char buf[8];

	if (stat(fname, &st) == -1)
		return "";

	snprintf(buf, sizeof(buf), "%o", st.st_mode);

	return buf + 2;
}

/* Color helpers */
#define COLOR(c,b) "\e[" c ";" b "m"
const char *NORM   = COLOR("00", "00");
const char *RED    = COLOR("31", "01");
const char *YELLOW = COLOR("33", "01");

void color_init(bool disable)
{
	if (!disable) {
		const char *nocolor = getenv("NOCOLOR");
		if (nocolor)
			disable = !strcmp(nocolor, "yes") || !strcmp(nocolor, "true");
	}
	if (disable)
		NORM = RED = YELLOW = "";
}

/* File system helpers. */
int root_fd = AT_FDCWD;

FILE *fopenat_r(int dir_fd, const char *path)
{
	int fd = openat(dir_fd, path, O_RDONLY|O_CLOEXEC);
	if (fd == -1)
		return NULL;
	return fdopen(fd, "re");
}

const char *root_rel_path(const char *path)
{
	/*
	 * openat() will ignore the dirfd if path starts with
	 * a /, so consume all of that noise
	 *
	 * XXX: we don't handle relative paths like ../ that
	 * break out of the --root option, but for now, just
	 * don't do that :P.
	 */
	if (root_fd != AT_FDCWD) {
		while (*path == '/')
			++path;
		if (*path == '\0')
			path = ".";
	}

	return path;
}
