/*
 * Generate the bpf rules ahead of time to speed up runtime.
 *
 * Copyright 2015 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2015 Mike Frysinger  - <vapier@gentoo.org>
 */

const char argv0[] = "seccomp-bpf";

#include <err.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <seccomp.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static const struct {
	const char *name;
	uint32_t arch;
	const char *ifdef;
} gen_seccomp_arches[] = {
#define A(arch, ifdef) { #arch, SCMP_ARCH_##arch, ifdef }
	A(AARCH64,     "defined(__aarch64__)"),
	A(ARM,         "defined(__arm__)"),
	A(MIPS,        "defined(__mips__) && defined(__MIPSEB__) && (_MIPS_SIM == _ABIO32)"),
	A(MIPS64,      "defined(__mips__) && defined(__MIPSEB__) && (_MIPS_SIM == _ABI64)"),
	A(MIPS64N32,   "defined(__mips__) && defined(__MIPSEB__) && (_MIPS_SIM == _ABIN32)"),
	A(MIPSEL,      "defined(__mips__) && defined(__MIPSEL__) && (_MIPS_SIM == _ABIO32)"),
	A(MIPSEL64,    "defined(__mips__) && defined(__MIPSEL__) && (_MIPS_SIM == _ABI64)"),
	A(MIPSEL64N32, "defined(__mips__) && defined(__MIPSEL__) && (_MIPS_SIM == _ABIN32)"),
	A(PARISC,      "defined(__hppa__) && !defined(__hppa64__)"),
	A(PARISC64,    "defined(__hppa__) &&  defined(__hppa64__)"),
	A(PPC,         "defined(__powerpc__) && !defined(__powerpc64__) &&  defined(__BIG_ENDIAN__)"),
	A(PPC64,       "defined(__powerpc__) &&  defined(__powerpc64__) &&  defined(__BIG_ENDIAN__)"),
	A(PPC64LE,     "defined(__powerpc__) &&  defined(__powerpc64__) && !defined(__BIG_ENDIAN__)"),
	A(RISCV64,     "defined(__riscv) && __riscv_xlen == 64"),
	A(S390,        "defined(__s390__) && !defined(__s390x__)"),
	A(S390X,       "defined(__s390__) &&  defined(__s390x__)"),
	A(X86,         "defined(__i386__)"),
	A(X32,         "defined(__x86_64__) &&  defined(__ILP32__)"),
	A(X86_64,      "defined(__x86_64__) && !defined(__ILP32__)"),
#undef A
};

/* Simple helper to add all of the syscalls in an array. */
static int gen_seccomp_rules_add(scmp_filter_ctx ctx, const int syscalls[], size_t num)
{
	static uint8_t prio;
	size_t i;
	for (i = 0; i < num; ++i) {
		if (seccomp_syscall_priority(ctx, syscalls[i], prio++) < 0) {
			warn("seccomp_syscall_priority failed");
			return -1;
		}
		if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscalls[i], 0) < 0) {
			warn("seccomp_rule_add failed");
			return -1;
		}
	}
	return 0;
}
#define gen_seccomp_rules_add(ctx, syscalls) gen_seccomp_rules_add(ctx, syscalls, ARRAY_SIZE(syscalls))

static void gen_seccomp_dump(scmp_filter_ctx ctx, const char *name)
{
	unsigned char buf[32768 * 8];
	ssize_t i, len;
	int fd;

	fd = memfd_create("bpf", MFD_CLOEXEC);
	if (fd < 0)
		err(1, "memfd_create failed");
	if (seccomp_export_bpf(ctx, fd) < 0)
		err(1, "seccomp_export_bpf_mem failed");
	if (lseek(fd, 0, SEEK_SET) != 0)
		err(1, "seek failed");
	len = read(fd, buf, sizeof(buf));
	if (len <= 0)
		err(1, "read failed");

	printf("static const unsigned char seccomp_bpf_blks_%s[] = {\n\t", name);
	for (i = 0; i < len; ++i)
		printf("%u,", buf[i]);
	printf("\n};\n");
}

static void gen_seccomp_program(const char *name)
{
	printf(
		"static const seccomp_bpf_program_t seccomp_bpf_program_%s = {\n"
		"	.cnt = sizeof(seccomp_bpf_blks_%s) / 8,\n"
		"	.bpf = seccomp_bpf_blks_%s,\n"
		"};\n", name, name, name);
}

int main(void)
{
	/* Order determines priority (first == lowest prio).  */
	static const int base_syscalls[] = {
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
		SCMP_SYS(statx),

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
#ifndef __SNR_faccessat2
/* faccessat2 is not yet defined in libseccomp-2.5.1 */
# define __SNR_faccessat2 __NR_faccessat2
#endif
		SCMP_SYS(faccessat2),
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
		SCMP_SYS(semtimedop),
		/*
		 * Some targets (e.g. ppc & i386) implement the above functions
		 * as ipc() subcalls.  #675378
		 */
		SCMP_SYS(ipc),

		/* glibc-2.34+ uses it as part of mem alloc functions. */
		SCMP_SYS(getrandom),

		/* glibc-2.35+ uses it when GLIBC_TUNABLES=glibc.malloc.hugetlb=1. */
		SCMP_SYS(madvise),
	};
	static const int fork_syscalls[] = {
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

	/* TODO: Handle debug and KILL vs TRAP. */

	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
	if (!ctx)
		err(1, "seccomp_init failed");

	printf("/* AUTO GENERATED FILE. To regenerate run:\n");
	printf(" *   $ $EDITOR seccomp-bpf.c\n");
	printf(" *   $ make seccomp-bpf.h\n");
	printf(" * See seccomp-bpf.c for details. */\n");
	printf("#undef SECCOMP_BPF_AVAILABLE\n");

	if (seccomp_arch_remove(ctx, seccomp_arch_native()) < 0)
		err(1, "seccomp_arch_remove failed");

	for (size_t i = 0; i < ARRAY_SIZE(gen_seccomp_arches); ++i) {
		uint32_t arch = gen_seccomp_arches[i].arch;

		seccomp_reset(ctx, SCMP_ACT_KILL);

		if (arch != seccomp_arch_native()) {
			if (seccomp_arch_remove(ctx, seccomp_arch_native()) < 0)
				err(1, "seccomp_arch_remove failed");
			if (seccomp_arch_add(ctx, arch) < 0)
				err(1, "seccomp_arch_add failed");
		}

		printf("\n#if %s\n", gen_seccomp_arches[i].ifdef);
		printf("/* %s */\n", gen_seccomp_arches[i].name);
		printf("#define SECCOMP_BPF_AVAILABLE\n");

		if (gen_seccomp_rules_add(ctx, base_syscalls) < 0)
			err(1, "seccomp_rules_add failed");
		gen_seccomp_dump(ctx, "base");

		if (gen_seccomp_rules_add(ctx, fork_syscalls) < 0)
			err(1, "seccomp_rules_add failed");
		gen_seccomp_dump(ctx, "fork");

		if (0) {
			printf("/*\n");
			fflush(stdout);
			seccomp_export_pfc(ctx, 1);
			fflush(stdout);
			printf("*/\n");
		}

		printf("#endif\n");
	}

	printf(
		"\n"
		"#ifdef SECCOMP_BPF_AVAILABLE\n"
		"typedef struct {\n"
		"	uint16_t cnt;\n"
		"	const void *bpf;\n"
		"} seccomp_bpf_program_t;\n");
	gen_seccomp_program("base");
	gen_seccomp_program("fork");
	printf("#endif\n");

	seccomp_release(ctx);

	return 0;
}
