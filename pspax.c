/******************************************************************************/
/* THE BEER-WARE LICENSE   (Revision 42):                                     */
/*  As long as you retain this notice you can do whatever you want with this  */
/*   stuff. If we meet some day, and you think this stuff is worth it,        */
/*   you can buy me a beer in return.    Ned Ludd. --solarx                   */
/******************************************************************************/

/*
 * normal compile.
 *  cc -o pspax pspax.c
 * or with libcap.
 *  cc -o pspax pspax.c -DWANT_SYSCAP -lcap
 */

const char argv0[] = "pspax";

#include "paxinc.h"
#include <grp.h>

#ifdef WANT_SYSCAP
# undef _POSIX_SOURCE
# include <sys/capability.h>
# define WRAP_SYSCAP(x) x
#else
# define WRAP_SYSCAP(x)
#endif

#define PROC_DIR "/proc"

/* variables to control behavior */
static char show_all = 0;
static char verbose = 0;
static char show_banner = 1;
static char show_phdr = 0;
static char show_addr = 0;
static char noexec = 1;
static char writeexec = 1;
static char wide_output = 0;
static pid_t show_pid = 0;
static uid_t show_uid = (uid_t)-1;
static gid_t show_gid = (gid_t)-1;

static elfobj *proc_readelf(int pfd)
{
	int fd;
	elfobj *elf;

	fd = openat(pfd, "exe", O_RDONLY|O_CLOEXEC);
	if (fd == -1)
		return NULL;

	elf = readelf_fd("proc/exe", fd, 0);
	close(fd);
	return elf;
}

static const char *get_proc_name_cmdline(int pfd)
{
	FILE *fp;
	static char str[1024];

	fp = fopenat_r(pfd, "cmdline");
	if (fp == NULL)
		return NULL;

	if (fscanf(fp, "%1023s", str) != 1) {
		fclose(fp);
		return NULL;
	}
	fclose(fp);

	return (str);
}

static const char *get_proc_name(int pfd)
{
	FILE *fp;
	/*
	 * The stat file says process names are truncated to TASK_COMM_LEN (16) bytes.
	 * That includes the trailing NUL (\0) byte.  This is true for userspace, but
	 * kernel processes seem to be unlimited.  We don't care about those in this
	 * program though, so truncating them all the time is fine.
	 */
	static char str[16];

	if (wide_output)
		return get_proc_name_cmdline(pfd);

	fp = fopenat_r(pfd, "stat");
	if (fp == NULL)
		return NULL;

	/*
	 * The format is:
	 *   <pid> (<name>) ...more fields...
	 * For example:
	 *   1234 (bash) R ...
	 *
	 * Match the leading (, then read 15 bytes (since scanf writes, but doesn't count,
	 * NUL bytes, so it will write up to 16 bytes to str).  Ignore the rest rather than
	 * look for closing ) since kernel processes can be longer.
	 */
	if (fscanf(fp, "%*d (%15s", str) != 1) {
		fclose(fp);
		return NULL;
	}

	if (*str) {
		/* Discard trailing ) if it exists. */
		size_t len = strlen(str);
		if (str[len - 1] == ')')
			str[len - 1] = '\0';
	}
	fclose(fp);

	return str;
}

static int get_proc_maps(int pfd)
{
	FILE *fp;
	static char *str = NULL;
	static size_t len = 0;

	if ((fp = fopenat_r(pfd, "maps")) == NULL)
		return -1;

	while (getline(&str, &len, fp) != -1) {
		char *p;
		if ((p = strchr(str, ' ')) != NULL) {
			if (strlen(p) < 6)
				continue;
			/* 0x0-0x0 rwxp fffff000 00:00 0 */
			/* 0x0-0x0 R+W+XP fffff000 00:00 0 */
			++p; /* ' ' */
			++p; /*  r  */
			if (*p == '+')
				++p;
			/* FIXME: all of wx, w+, +x, ++ indicate w|x */
			if (tolower(*p) == 'w') {
				++p;
				if (*p == '+')
					++p;
				if (tolower(*p) == 'x') {
					fclose(fp);
					return 1;
				}
			}
		}
	}
	fclose(fp);

	return 0;
}

static int print_executable_mappings(int pfd)
{
	FILE *fp;
	static char *str = NULL;
	static size_t len = 0;

	if ((fp = fopenat_r(pfd, "maps")) == NULL)
		return -1;

	while (getline(&str, &len, fp) != -1) {
		char *p;
		if ((p = strchr(str, ' ')) != NULL) {
			if (strlen(p) < 6)
				continue;
			/* 0x0-0x0 rwxp fffff000 00:00 0 */
			/* 0x0-0x0 R+W+XP fffff000 00:00 0 */
			++p; /* ' ' */
			++p; /*  r  */
			if (*p == '+')
				++p;
			/* FIXME: all of wx, w+, +x, ++ indicate w|x */
			if (tolower(*p) == 'w') {
				++p;
				if (*p == '+')
					++p;
				if (tolower(*p) == 'x')
					printf(" %s", str);
			}
		}
	}
	fclose(fp);

	return 0;
}

static const struct passwd *get_proc_passwd(int pfd)
{
	struct stat st;
	const struct passwd *pwd = NULL;

	if (fstatat(pfd, "stat", &st, AT_SYMLINK_NOFOLLOW) != -1)
		pwd = getpwuid(st.st_uid);

	return pwd;
}

static const char *get_proc_status(int pfd, const char *name)
{
	FILE *fp;
	size_t name_len;
	static char *str = NULL;
	static size_t len = 0;

	if ((fp = fopenat_r(pfd, "status")) == NULL)
		return NULL;

	name_len = strlen(name);
	while (getline(&str, &len, fp) != -1) {
		if (strncasecmp(str, name, name_len) != 0)
			continue;
		if (str[name_len] == ':') {
			fclose(fp);
			str[strlen(str) - 1] = 0;
			return (str + name_len + 2);
		}
	}
	fclose(fp);

	return NULL;
}

static const char *get_pid_attr(int pfd)
{
	FILE *fp;
	char *p;
	static char *buf = NULL;
	static size_t len = 0;

	if ((fp = fopenat_r(pfd, "attr/current")) == NULL)
		return NULL;

	if (getline(&buf, &len, fp) == -1) {
		fclose(fp);
		return NULL;
	}

	if ((p = strchr(buf, '\n')) != NULL)
		*p = 0;

	fclose(fp);

	return buf;
}

static const char *get_pid_addr(int pfd)
{
	FILE *fp;
	char *p;
	static char *buf = NULL;
	static size_t len = 0;

	if ((fp = fopenat_r(pfd, "ipaddr")) == NULL)
		return NULL;

	if (getline(&buf, &len, fp) == -1) {
		fclose(fp);
		return NULL;
	}

	if ((p = strchr(buf, '\n')) != NULL)
		*p = 0;

	fclose(fp);

	return buf;
}

static const char *get_proc_type(int pfd)
{
	elfobj *elf;
	const char *ret;

	elf = proc_readelf(pfd);
	if (elf == NULL)
		return NULL;

	ret = get_elfetype(elf);
	unreadelf(elf);
	return ret;
}

static const char *scanelf_file_phdr(elfobj *elf)
{
	static char ret[8];
	unsigned long i, off, multi_stack, multi_load;

	memcpy(ret, "--- ---\0", 8);

	multi_stack = multi_load = 0;

	if (elf->phdr) {
	uint32_t flags;
#define SHOW_PHDR(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
	const Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
	const Elf ## B ## _Phdr *phdr = PHDR ## B (elf->phdr); \
	for (i = 0; i < EGET(ehdr->e_phnum); i++) { \
		if (EGET(phdr[i].p_type) == PT_GNU_STACK) { \
			if (multi_stack++) warnf("%s: multiple PT_GNU_STACK's !?", elf->filename); \
			off = 0; \
		} else if (EGET(phdr[i].p_type) == PT_LOAD) { \
			off = 4; \
		} else \
			continue; \
		flags = EGET(phdr[i].p_flags); \
		memcpy(ret+off, gnu_short_stack_flags(flags), 3); \
	} \
	}
	SHOW_PHDR(32)
	SHOW_PHDR(64)
	}

	return ret;
}
/* we scan the elf file two times when the -e flag is given. But we don't need -e very often so big deal */
static const char *get_proc_phdr(int pfd)
{
	elfobj *elf;
	const char *ret;

	elf = proc_readelf(pfd);
	if (elf == NULL)
		return NULL;

	ret = scanelf_file_phdr(elf);
	unreadelf(elf);
	return ret;
}

static void pspax(const char *find_name)
{
	register DIR *dir;
	register struct dirent *de;
	pid_t pid;
	pid_t ppid = show_pid;
	int have_attr, have_addr, wx;
	const struct passwd *pwd;
	const char *pax, *type, *name, *attr, *addr;
	char *caps;
	int pfd;
	WRAP_SYSCAP(ssize_t length; cap_t cap_d;)

	dir = opendir(PROC_DIR);
	if (dir == NULL || chdir(PROC_DIR))
		errp(PROC_DIR);

	if (access("/proc/self/attr/current", R_OK) != -1)
		have_attr = 1;
	else
		have_attr = 0;

	if ((access("/proc/self/ipaddr", R_OK) != -1) && show_addr)
		have_addr = 1;
	else
		have_addr = 0;

	if (show_banner)
		printf("%-8s %-6s %-6s %-4s %-10s %-16s %-4s %-4s %s %s\n",
		       "USER", "PID", "PAX", "MAPS", "ETYPE", "NAME", "CAPS", have_attr ? "ATTR" : "",
			have_addr ? "IPADDR" : "", show_phdr ? "STACK LOAD" : "");

	while ((de = readdir(dir))) {
		/* Check the name first if it's an int as it's faster. */
		pid = atoi(de->d_name);
		if (pid == 0)
			continue;

		/* Get an open handle so the kernel won't reap on us later. */
		pfd = open(de->d_name, O_RDONLY|O_CLOEXEC|O_PATH|O_DIRECTORY);
		if (pfd == -1)
			continue;

		if (find_name && pid) {
			const char *str = get_proc_name(pfd);
			if (!str)
				goto next_pid;
			if (strcmp(str, find_name) != 0)
				pid = 0;
		}
		if (ppid > 0 && pid != ppid)
			goto next_pid;

		wx = get_proc_maps(pfd);

		if (noexec != writeexec) {
			if (wx == 1 && writeexec != wx)
				goto next_pid;

			if (wx == 0 && writeexec)
				goto next_pid;
		}

		pwd  = get_proc_passwd(pfd);
		pax  = get_proc_status(pfd, "PAX");
		type = get_proc_type(pfd);
		name = get_proc_name(pfd);
		attr = (have_attr ? get_pid_attr(pfd) : NULL);
		addr = (have_addr ? get_pid_addr(pfd) : NULL);

		if (pwd) {
			if (show_uid != (uid_t)-1)
				if (pwd->pw_uid != show_uid)
					goto next_pid;

			if (show_gid != (gid_t)-1)
				if (pwd->pw_gid != show_gid)
					goto next_pid;
		}

		/* this is a non-POSIX function */
		caps = NULL;
		WRAP_SYSCAP(cap_d = cap_get_pid(pid));
		WRAP_SYSCAP(caps = cap_to_text(cap_d, &length));

		if (pwd && strlen(pwd->pw_name) >= 8)
			pwd->pw_name[8] = 0;

		if (show_all || type) {
			printf("%-8s %-6d %-6s %-4s %-10s %-16s %-4s %s %s %s\n",
			       pwd  ? pwd->pw_name : "--------",
			       pid,
			       pax  ? pax  : "---",
			       (wx == 1) ? "w|x" : (wx == -1) ? "---" : "w^x",
			       type ? type : "-------",
			       name ? name : "-----",
			       caps ? caps : " = ",
			       attr ? attr : "",
			       addr ? addr : "",
			       show_phdr ? get_proc_phdr(pfd) : "");
			if (verbose && wx)
				print_executable_mappings(pfd);
		}

		WRAP_SYSCAP(cap_free(cap_d));
		WRAP_SYSCAP(cap_free(caps));

 next_pid:
		close(pfd);
	}
	closedir(dir);
}

/* usage / invocation handling functions */
#define PARSE_FLAGS "aeip:u:g:nwWvCBhV"
static struct option const long_opts[] = {
	{"all",       no_argument, NULL, 'a'},
	{"header",    no_argument, NULL, 'e'},
	{"ipaddr",    no_argument, NULL, 'i'},
	{"pid",        a_argument, NULL, 'p'},
	{"user",       a_argument, NULL, 'u'},
	{"group",      a_argument, NULL, 'g'},
	{"nx",        no_argument, NULL, 'n'},
	{"wx",        no_argument, NULL, 'w'},
	{"wide",      no_argument, NULL, 'W'},
	{"verbose",   no_argument, NULL, 'v'},
	{"nocolor",   no_argument, NULL, 'C'},
	{"nobanner",  no_argument, NULL, 'B'},
	{"help",      no_argument, NULL, 'h'},
	{"version",   no_argument, NULL, 'V'},
	{NULL,        no_argument, NULL, 0x0}
};

static const char * const opts_help[] = {
	"Show all processes",
	"Print GNU_STACK/PT_LOAD markings",
	"Print ipaddr info if supported",
	"Process ID/pid #",
	"Process user/uid #",
	"Process group/gid #",
	"Only display w^x processes",
	"Only display w|x processes",
	"Wide output display of cmdline",
	"Be verbose about executable mappings",
	"Don't emit color in output",
	"Don't display the header",
	"Print this help and exit",
	"Print version and exit",
	NULL
};

/* display usage and exit */
static void usage(int status)
{
	pax_usage(
		"List ELF/PaX information about running processes",
		"",
		PARSE_FLAGS,
		long_opts,
		opts_help,
		status);
}

/* parse command line arguments and perform needed actions */
static void parseargs(int argc, char *argv[])
{
	int flag;
	const struct passwd *pwd = NULL;
	const struct  group *gwd = NULL;

	opterr = 0;
	while ((flag=getopt_long(argc, argv, PARSE_FLAGS, long_opts, NULL)) != -1) {
		switch (flag) {

		case 'V':                        /* version info */
			printf("pax-utils-%s: %s\n"
			       "%s written for Gentoo by <solar and vapier @ gentoo.org>\n",
			       VERSION, VCSID, argv0);
			exit(EXIT_SUCCESS);
			break;
		case 'h': usage(EXIT_SUCCESS); break;

		case 'C': color_init(true); break;
		case 'B': show_banner = 0; break;
		case 'a': show_all = 1; break;
		case 'e': show_phdr = 1; break;
		case 'i': show_addr = 1; break;
		case 'p': show_pid = atoi(optarg); break;
		case 'n': noexec = 1; writeexec = 0; break;
		case 'w': noexec = 0; writeexec = 1; break;
		case 'W': wide_output = 1; break;
		case 'v': verbose++; break;
		case 'u':
			show_uid = atoi(optarg);
			if (show_uid == 0 && (strcmp(optarg, "0") != 0)) {
				pwd = getpwnam(optarg);
				if (pwd)
					show_uid = pwd->pw_uid;
				else
					err("unknown uid");
			}
			break;
		case 'g':
			show_gid = atoi(optarg);
			if (show_gid == 0 && (strcmp(optarg, "0") != 0)) {
				gwd = getgrnam(optarg);
				if (gwd)
					show_gid = gwd->gr_gid;
				else
					err("unknown gid");
			}
			break;
		case ':':
		case '?':
			warn("Unknown option or missing parameter");
			usage(EXIT_FAILURE);
			break;
		default:
			err("Unhandled option '%c'", flag);
			break;
		}
	}
}

int main(int argc, char *argv[])
{
	const char *name = NULL;

	/* We unshare pidns but don't actually enter it.  That means
	 * we still get to scan /proc, but just not fork children.  */
	security_init(false);

	color_init(false);
	parseargs(argc, argv);

	if ((optind < argc) && (show_pid == 0))
		name = argv[optind];

	pspax(name);

	return EXIT_SUCCESS;
}
