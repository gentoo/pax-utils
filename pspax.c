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

static const char *rcsid = "$Id: pspax.c,v 1.38 2007/08/20 09:54:15 vapier Exp $";
const char * const argv0 = "pspax";

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
static char noexec = 1;
static char writeexec = 1;

static pid_t show_pid = 0;
static uid_t show_uid = -1;
static gid_t show_gid = -1;

static char *get_proc_name(pid_t pid)
{
	FILE *fp;
	static char str[__PAX_UTILS_PATH_MAX];
	memset(&str, 0, sizeof(str));

	snprintf(str, sizeof(str), PROC_DIR "/%u/stat", pid);
	if ((fp = fopen(str, "r")) == NULL)
		return NULL;

	memset(&str, 0, sizeof(str));

	fscanf(fp, "%*d %s.16", str);
	if (*str) {
		str[strlen(str) - 1] = '\0';
		str[16] = 0;
	}
	fclose(fp);
	return (str+1);
}

static int get_proc_maps(pid_t pid)
{
	static char str[__PAX_UTILS_PATH_MAX];
	FILE *fp;

	snprintf(str, sizeof(str), PROC_DIR "/%u/maps", pid);

	if ((fp = fopen(str, "r")) == NULL)
		return -1;

	while (fgets(str, sizeof(str), fp)) {
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

static int print_executable_mappings(pid_t pid)
{
	static char str[__PAX_UTILS_PATH_MAX];
	FILE *fp;

	snprintf(str, sizeof(str), PROC_DIR "/%u/maps", pid);

	if ((fp = fopen(str, "r")) == NULL)
		return -1;

	while (fgets(str, sizeof(str), fp)) {
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

#ifdef __BOUNDS_CHECKING_ON
# define NOTE_TO_SELF warn( \
	"This is bullshit but getpwuid() is leaking memory and I wasted a few hrs 1 day tracking it down in pspax\n" \
	"Later on I forgot I tracked it down before and saw pspax leaking memory so I tracked it down all over again (silly me)\n" \
	"Hopefully the getpwuid()/nis/nss/pam or whatever wont suck later on in the future.")
#else
# define NOTE_TO_SELF
#endif

static struct passwd *get_proc_passwd(pid_t pid)
{
	struct stat st;
	struct passwd *pwd;
	static char str[__PAX_UTILS_PATH_MAX];

	snprintf(str, sizeof(str), PROC_DIR "/%u/stat", pid);

	if ((stat(str, &st)) != (-1))
		if ((pwd = getpwuid(st.st_uid)) != NULL)
			return pwd;
	return NULL;
}

static char *get_proc_status(pid_t pid, const char *name)
{
	FILE *fp;
	size_t len;
	static char str[__PAX_UTILS_PATH_MAX];

	snprintf(str, sizeof(str), PROC_DIR "/%u/status", pid);
	if ((fp = fopen(str, "r")) == NULL)
		return NULL;

	len = strlen(name);
	while (fgets(str, sizeof(str), fp)) {
		if (strncasecmp(str, name, len) != 0)
			continue;
		if (str[len] == ':') {
			fclose(fp);
			str[strlen(str) - 1] = 0;
			return (str + len + 2);
		}
	}
	fclose(fp);
	return NULL;
}

static char *get_pid_attr(pid_t pid)
{
	FILE *fp;
	char *p;
	char str[32];
	static char buf[BUFSIZ];

	memset(buf, 0, sizeof(buf));

	snprintf(str, sizeof(str), PROC_DIR "/%u/attr/current", pid);
	if ((fp = fopen(str, "r")) == NULL)
		return NULL;
	if (fgets(buf, sizeof(buf), fp) != NULL)
		if ((p = strchr(buf, '\n')) != NULL)
			*p = 0;
	fclose(fp);
	return buf;
}

static const char *get_proc_type(pid_t pid)
{
	char fname[32];
	elfobj *elf = NULL;
	char *ret = NULL;

	snprintf(fname, sizeof(fname), PROC_DIR "/%u/exe", pid);
	if ((elf = readelf(fname)) == NULL)
		return ret;
	ret = (char *)get_elfetype(elf);
	unreadelf(elf);
	return ret;
}

static char *scanelf_file_phdr(elfobj *elf)
{
	static char ret[8];
	unsigned long i, off, multi_stack, multi_load;
	int max_pt_load;

	memcpy(ret, "--- ---\0", 8);

	multi_stack = multi_load = 0;
	max_pt_load = elf_max_pt_load(elf);

	if (elf->phdr) {
	uint32_t flags;
#define SHOW_PHDR(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
	Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
	Elf ## B ## _Phdr *phdr = PHDR ## B (elf->phdr); \
	for (i = 0; i < EGET(ehdr->e_phnum); i++) { \
		if (EGET(phdr[i].p_type) == PT_GNU_STACK) { \
			if (multi_stack++) warnf("%s: multiple PT_GNU_STACK's !?", elf->filename); \
			off = 0; \
		} else if (EGET(phdr[i].p_type) == PT_LOAD) { \
			if (multi_load++ > max_pt_load) warnf("%s: more than %i PT_LOAD's !?", elf->filename, max_pt_load); \
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
static const char *get_proc_phdr(pid_t pid)
{
	char fname[32];
	elfobj *elf = NULL;
	char *ret = NULL;

	snprintf(fname, sizeof(fname), PROC_DIR "/%u/exe", pid);
	if ((elf = readelf(fname)) == NULL)
		return ret;
	ret = (char *) scanelf_file_phdr(elf);
	unreadelf(elf);
	return ret;
}


static void pspax(const char *find_name)
{
	register DIR *dir;
	register struct dirent *de;
	pid_t pid;
	pid_t ppid = show_pid;
	int have_attr, wx;
	struct passwd *pwd;
	struct stat st;
	const char *pax, *type, *name, *caps, *attr;
	WRAP_SYSCAP(ssize_t length; cap_t cap_d;);

	WRAP_SYSCAP(cap_d = cap_init());

	caps = NULL;

	chdir(PROC_DIR);
	if (!(dir = opendir(PROC_DIR))) {
		perror(PROC_DIR);
		exit(EXIT_FAILURE);
	}

	if (access("/proc/self/attr/current", R_OK) != (-1))
		have_attr = 1;
	else
		have_attr = 0;

	if (show_banner)
		printf("%-8s %-6s %-6s %-4s %-10s %-16s %-4s %-4s %s\n",
		       "USER", "PID", "PAX", "MAPS", "ETYPE", "NAME", "CAPS", "ATTR", show_phdr ? "STACK LOAD" : "");

	while ((de = readdir(dir))) {
		errno = 0;
		stat(de->d_name, &st);
		if ((errno != ENOENT) && (errno != EACCES)) {
			pid = (pid_t) atoi((char *) basename((char *) de->d_name));
			if (find_name && pid) {
				char *str = get_proc_name(pid);
	                        if (!str) continue;
				if (strcmp(str, find_name) != 0)
					pid = 0;
			}
			if (((ppid > 0) && (pid != ppid)) || (!pid))
				continue;

			wx = get_proc_maps(pid);

			if (noexec != writeexec) {
				if ((wx == 1) && (writeexec != wx))
					goto next_pid;

				if ((wx == 0) && (writeexec))
					goto next_pid;
			}

			pwd  = get_proc_passwd(pid);
			pax  = get_proc_status(pid, "PAX");
			type = get_proc_type(pid);
			name = get_proc_name(pid);
			attr = (have_attr ? get_pid_attr(pid) : NULL);

			if (show_uid != (-1) && pwd)
				if (pwd->pw_uid != show_uid)
					continue;

			if (show_gid != (-1) && pwd)
				if (pwd->pw_gid != show_gid)
					continue;

			/* this is a non-POSIX function */
			WRAP_SYSCAP(capgetp(pid, cap_d));
			WRAP_SYSCAP(caps = cap_to_text(cap_d, &length));

			if (show_all || type) {
				printf("%-8s %-6d %-6s %-4s %-10s %-16s %-4s %s %s\n",
				       pwd  ? pwd->pw_name : "--------",
				       pid,
				       pax  ? pax  : "---",
				       (wx == 1) ? "w|x" : (wx == -1) ? "---" : "w^x",
				       type ? type : "-------",
				       name ? name : "-----",
				       caps ? caps : " = ",
				       attr ? attr : "-", show_phdr ? get_proc_phdr(pid) : "");
				if (verbose && wx)
					print_executable_mappings(pid);
			}

			WRAP_SYSCAP(if (caps) cap_free((void *)caps));

		next_pid:
			continue;
		}
	}
	closedir(dir);
}



/* usage / invocation handling functions */
#define PARSE_FLAGS "aep:u:g:nwvBhV"
#define a_argument required_argument
static struct option const long_opts[] = {
	{"all",       no_argument, NULL, 'a'},
	{"header",    no_argument, NULL, 'e'},
	{"pid",        a_argument, NULL, 'p'},
	{"user",       a_argument, NULL, 'u'},
	{"group",      a_argument, NULL, 'g'},
	{"nx",        no_argument, NULL, 'n'},
	{"wx",        no_argument, NULL, 'w'},
	{"verbose",   no_argument, NULL, 'v'},
	{"nobanner",  no_argument, NULL, 'B'},
	{"help",      no_argument, NULL, 'h'},
	{"version",   no_argument, NULL, 'V'},
	{NULL,        no_argument, NULL, 0x0}
};
static const char *opts_help[] = {
	"Show all processes",
	"Print GNU_STACK/PT_LOAD markings",
	"Process ID/pid #",
	"Process user/uid #",
	"Process group/gid #",
	"Only display w^x processes",
	"Only display w|x processes",
	"Be verbose about executable mappings",
	"Don't display the header",
	"Print this help and exit",
	"Print version and exit",
	NULL
};

/* display usage and exit */
static void usage(int status)
{
	int i;
	printf("* List ELF/PaX information about running processes\n\n"
	       "Usage: %s [options]\n\n", argv0);
	fputs("Options:\n", stdout);
	for (i = 0; long_opts[i].name; ++i)
		printf("  -%c, --%-12s* %s\n", long_opts[i].val,
		       long_opts[i].name, opts_help[i]);
#ifdef MANLYPAGE
	for (i = 0; long_opts[i].name; ++i)
		printf(".TP\n\\fB\\-%c, \\-\\-%s\\fR\n%s\n", long_opts[i].val,
		       long_opts[i].name, opts_help[i]);
#endif
	exit(status);
}

/* parse command line arguments and preform needed actions */
static void parseargs(int argc, char *argv[])
{
	int flag;
	struct passwd *pwd = NULL;
	struct  group *gwd = NULL;

	opterr = 0;
	while ((flag=getopt_long(argc, argv, PARSE_FLAGS, long_opts, NULL)) != -1) {
		switch (flag) {

		case 'V':                        /* version info */
			printf("pax-utils-%s: %s compiled %s\n%s\n"
			       "%s written for Gentoo by <solar and vapier @ gentoo.org>\n",
			       VERSION, __FILE__, __DATE__, rcsid, argv0);
			exit(EXIT_SUCCESS);
			break;
		case 'h': usage(EXIT_SUCCESS); break;

		case 'B': show_banner = 0; break;
		case 'a': show_all = 1; break;
		case 'e': show_phdr = 1; break;
		case 'p': show_pid = atoi(optarg); break;
		case 'n': noexec = 1; writeexec = 0; break;
		case 'w': noexec = 0; writeexec = 1; break;
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
	char *name = NULL;

	parseargs(argc, argv);

	if ((optind < argc) && (show_pid == 0))
		name = argv[optind];

	pspax(name);

	NOTE_TO_SELF;
	return EXIT_SUCCESS;
}
