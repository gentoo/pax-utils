/*
 * Copyright 2015 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2015 Mike Frysinger  - <vapier@gentoo.org>
 */

#include "paxinc.h"
#include "seccomp-bpf.h"

#ifdef __linux__

/* Older versions of Linux might not have these. */
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0
#endif
#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0
#endif

#ifndef PR_SET_SECCOMP
#define PR_SET_SECCOMP 22
#endif
#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif

#ifdef __SANITIZE_ADDRESS__
/* ASAN does some weird stuff. */
# define ALLOW_PIDNS 0
# undef WANT_SECCOMP
#else
# define ALLOW_PIDNS 1
#endif

#ifndef SECCOMP_BPF_AVAILABLE
# undef WANT_SECCOMP
#endif

#if PAX_UTILS_LIBFUZZ
# undef WANT_SECCOMP
#endif

static int ns_unshare(int flags)
{
	int flag, ret = 0;

	/* Try to oneshot it.  Maybe we'll get lucky! */
	if (unshare(flags) == 0)
		return flags;
	/* No access at all, so don't waste time below. */
	else if (errno == EPERM)
		return ret;

	/*
	 * We have to run these one permission at a time because if any are
	 * not supported (too old a kernel, or it's disabled), then all of
	 * them will be rejected and we won't know which one is a problem.
	 */

	/* First the ones that work against the current process.  */
	flag = 1;
	while (flags) {
		if (flags & flag) {
			if (unshare(flag) == 0)
				ret |= flag;
			flags &= ~flag;
		}
		flag <<= 1;
	}

	return ret;
}

void security_init_pid(void)
{
	int flags;

	if (!ALLOW_PIDNS || CLONE_NEWPID == 0)
		return;

	flags = ns_unshare(CLONE_NEWPID);
	if (USE_SLOW_SECURITY) {
		if (flags & CLONE_NEWPID)
			if (vfork() == 0)
				_exit(0);
	}
}

void security_init(bool allow_forking)
{
	(void) allow_forking;
	int flags;

	if (!ALLOW_PIDNS)
		allow_forking = true;

	/* Drop all possible caps for us and our children.  */
#ifdef PR_SET_NO_NEW_PRIVS /* New to linux-3.5 */
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
#endif
#ifdef PR_SET_SECUREBITS /* New to linux-2.6.26 */
# ifdef SECBIT_KEEP_CAPS_LOCKED /* New to linux-2.6.33 (all SECBIT_xxx) */
	prctl(PR_SET_SECUREBITS,
		SECBIT_KEEP_CAPS_LOCKED |
		SECBIT_NO_SETUID_FIXUP |
		SECBIT_NO_SETUID_FIXUP_LOCKED |
		SECBIT_NOROOT |
		SECBIT_NOROOT_LOCKED, 0, 0, 0);
# endif
#endif

	/* None of the pax tools need access to these features. */
	flags = CLONE_NEWIPC | CLONE_NEWUTS;
	/* Would be nice to leverage mount/net ns, but they're just way too slow. */
	if (USE_SLOW_SECURITY)
		flags |= CLONE_NEWNET | CLONE_NEWNS;
	if (!allow_forking)
		flags |= CLONE_NEWPID;
	flags = ns_unshare(flags);

	if (USE_SLOW_SECURITY) {
		/* We spawn one child and kill it so the kernel will fail in the future. */
		if (flags & CLONE_NEWPID)
			if (vfork() == 0)
				_exit(0);
	}

#ifdef WANT_SECCOMP
	{
	int ret;

	if (allow_forking)
		ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &seccomp_bpf_program_fork);
	else
		ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &seccomp_bpf_program_base);

	if (ret)
		warn("enabling seccomp failed");
	}
#endif
}

#endif
