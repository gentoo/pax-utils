/*
 * Copyright 2015 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2015 Mike Frysinger  - <vapier@gentoo.org>
 */

#include "paxinc.h"

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

#ifdef __SANITIZE_ADDRESS__
/* ASAN does some weird stuff. */
# define ALLOW_PIDNS 0
#else
# define ALLOW_PIDNS 1
#endif

#ifdef WANT_SECCOMP
# include <seccomp.h>

/* Simple helper to add all of the syscalls in an array. */
static int pax_seccomp_rules_add(scmp_filter_ctx ctx, int syscalls[], size_t num)
{
	static uint8_t prio;
	size_t i;
	for (i = 0; i < num; ++i) {
		if (syscalls[i] < 0)
			continue;

		if (seccomp_syscall_priority(ctx, syscalls[i], prio++) < 0) {
			warnp("seccomp_syscall_priority failed");
			return -1;
		}
		if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscalls[i], 0) < 0) {
			warnp("seccomp_rule_add failed");
			return -1;
		}
	}
	return 0;
}
#define pax_seccomp_rules_add(ctx, syscalls) pax_seccomp_rules_add(ctx, syscalls, ARRAY_SIZE(syscalls))

static void
pax_seccomp_sigal(__unused__ int signo, siginfo_t *info, __unused__ void *context)
{
#ifdef si_syscall
	warn("seccomp violated: syscall %i", info->si_syscall);
	fflush(stderr);
	warn("  syscall = %s",
		seccomp_syscall_resolve_num_arch(seccomp_arch_native(), info->si_syscall));
	fflush(stderr);
#else
	warn("seccomp violated: syscall unknown (no si_syscall)");
#endif
	kill(getpid(), SIGSYS);
	_exit(1);
}

static void pax_seccomp_signal_init(void)
{
	struct sigaction act;
	sigemptyset(&act.sa_mask);
	act.sa_sigaction = pax_seccomp_sigal,
	act.sa_flags = SA_SIGINFO | SA_RESETHAND;
	sigaction(SIGSYS, &act, NULL);
}

static void pax_seccomp_init(bool allow_forking)
{
	/* Order determines priority (first == lowest prio).  */
	int base_syscalls[] = {
		/* We write the most w/scanelf.  */
		SCMP_SYS(write),
		SCMP_SYS(writev),
		SCMP_SYS(pwrite64),
		SCMP_SYS(pwritev),

		/* Then the stat family of functions.  */
		SCMP_SYS(newfstatat),
		SCMP_SYS(fstat),
		SCMP_SYS(fstat64),
		SCMP_SYS(fstatat64),
		SCMP_SYS(lstat),
		SCMP_SYS(lstat64),
		SCMP_SYS(stat),
		SCMP_SYS(stat64),

		/* Then the fd close func.  */
		SCMP_SYS(close),

		/* Then fd open family of functions.  */
		SCMP_SYS(open),
		SCMP_SYS(openat),

		/* Then the memory mapping functions.  */
		SCMP_SYS(mmap),
		SCMP_SYS(mmap2),
		SCMP_SYS(munmap),

		/* Then the directory reading functions.  */
		SCMP_SYS(getdents),
		SCMP_SYS(getdents64),

		/* Then the file reading functions.  */
		SCMP_SYS(pread64),
		SCMP_SYS(read),
		SCMP_SYS(readv),
		SCMP_SYS(preadv),

		/* Then the fd manipulation functions.  */
		SCMP_SYS(fcntl),
		SCMP_SYS(fcntl64),

		/* After this point, just sort the list alphabetically.  */
		SCMP_SYS(access),
		SCMP_SYS(brk),
		SCMP_SYS(capget),
		SCMP_SYS(chdir),
		SCMP_SYS(dup),
		SCMP_SYS(dup2),
		SCMP_SYS(dup3),
		SCMP_SYS(exit),
		SCMP_SYS(exit_group),
		SCMP_SYS(faccessat),
		SCMP_SYS(fchdir),
		SCMP_SYS(getpid),
		SCMP_SYS(gettid),
		SCMP_SYS(ioctl),
		SCMP_SYS(lseek),
		SCMP_SYS(_llseek),
		SCMP_SYS(mprotect),

		/* Syscalls listed because of compiler settings.  */
		SCMP_SYS(futex),

		/* Syscalls listed because of sandbox.  */
		SCMP_SYS(readlink),
		SCMP_SYS(readlinkat),
		SCMP_SYS(getcwd),

		/* Syscalls listed because of fakeroot.  */
		SCMP_SYS(msgget),
		SCMP_SYS(msgrcv),
		SCMP_SYS(msgsnd),
		SCMP_SYS(semget),
		SCMP_SYS(semop),
	};
	int fork_syscalls[] = {
		SCMP_SYS(clone),
		SCMP_SYS(execve),
		SCMP_SYS(fork),
		SCMP_SYS(rt_sigaction),
		SCMP_SYS(rt_sigprocmask),
		SCMP_SYS(unshare),
		SCMP_SYS(vfork),
		SCMP_SYS(wait4),
		SCMP_SYS(waitid),
		SCMP_SYS(waitpid),
	};
	scmp_filter_ctx ctx = seccomp_init(USE_DEBUG ? SCMP_ACT_TRAP : SCMP_ACT_KILL);
	if (!ctx) {
		warnp("seccomp_init failed");
		return;
	}

	if (pax_seccomp_rules_add(ctx, base_syscalls) < 0)
		goto done;

	if (allow_forking)
		if (pax_seccomp_rules_add(ctx, fork_syscalls) < 0)
			goto done;

	/* We already called prctl. */
	seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0);

	if (USE_DEBUG)
		pax_seccomp_signal_init();

#ifndef __SANITIZE_ADDRESS__
	/* ASAN does some weird stuff. */
	if (seccomp_load(ctx) < 0) {
		/* We have to assume that EINVAL == CONFIG_SECCOMP is disabled. */
		if (errno != EINVAL)
			warnp("seccomp_load failed");
	}
#endif

 done:
	seccomp_release(ctx);
}

#else
# define pax_seccomp_init(allow_forking)
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

	pax_seccomp_init(allow_forking);
}

#endif
