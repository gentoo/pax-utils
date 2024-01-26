/*
 * Copyright 2024 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2024 Mike Frysinger  - <vapier@gentoo.org>
 */

/* Fuzz the ar interface. */

const char argv0[] = "fuzz-ar";

#include "paxinc.h"

static int fd;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	fd = memfd_create("fuzz-input.a", MFD_CLOEXEC);
	if (fd == -1)
		errp("memfd_create() failed");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (ftruncate(fd, size) != 0)
		errp("ftruncate(%i, %zu) failed", fd, size);
	if (pwrite(fd, data, size, 0) != (ssize_t)size)
		errp("pwrite() failed");
	if (lseek(fd, 0, SEEK_SET) != 0)
		errp("lseek() failed");

	int afd = dup(fd);
	archive_handle *ar = ar_open_fd("fuzz-input.a", afd, 0);
	if (ar == NULL) {
		close(afd);
		return 0;
	}
	while (ar_next(ar) != NULL)
		continue;

	return 0;
}
