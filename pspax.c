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
 *
 */

#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <libgen.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <pwd.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <getopt.h>

#include "paxelf.h"

#ifdef WANT_SYSCAP
#undef _POSIX_SOURCE
#include <sys/capability.h>
#endif

#define PROC_DIR "/proc"

static const char *rcsid = "$Id: pspax.c,v 1.6 2005/04/02 03:25:04 vapier Exp $";


/* helper functions for showing errors */
#define argv0 "pspax" /*((*argv != NULL) ? argv[0] : __FILE__ "\b\b")*/
#define warn(fmt, args...) \
	fprintf(stderr, "%s: " fmt "\n", argv0, ## args)
#define err(fmt, args...) \
	do { \
	warn(fmt, ## args); \
	exit(EXIT_FAILURE); \
	} while (0)



/* variables to control behavior */
static char show_all = 0;
static char show_banner = 1;



static char *get_proc_name(pid_t pid)
{
	FILE *fp;
	static char buf[PATH_MAX];
	memset(&buf, 0, sizeof(buf));

	snprintf(buf, sizeof(buf), PROC_DIR "/%d/stat", (int) pid);
	if ((fp = fopen(buf, "r")) == NULL)
		return NULL;

	fscanf(fp, "%*d %s.16", buf);
	if (*buf) {
		buf[strlen(buf) - 1] = '\0';
		buf[16] = 0;
	}
	fclose(fp);
	return (buf+1);
}

static struct passwd *get_proc_uid(pid_t pid)
{
	struct passwd *pwd;
	struct stat st;
	static char s[PATH_MAX];

	snprintf(s, sizeof(s), PROC_DIR "/%d/stat", (int) pid);
	if ((stat(s, &st)) != (-1))
		if ((pwd = getpwuid(st.st_uid)) != NULL)
			return pwd;
	return NULL;
}

static char *get_proc_status(pid_t pid, char *name)
{
	FILE *fp;
	int len;
	static char s[PATH_MAX];

	snprintf(s, sizeof(s), PROC_DIR "/%d/status", (int) pid);
	if ((fp = fopen(s, "r")) == NULL)
		return NULL;

	len = strlen(name);
	while (fgets(s, sizeof(s), fp)) {
		if (strncasecmp(s, name, len) == 0) {
			if (s[len] == ':') {
				fclose(fp);
				s[strlen(s) - 1] = 0;
				return (s + len + 2);
			}
		}
	}
	fclose(fp);
	return NULL;
}

static char *get_pid_attr(int pid)
{
	FILE *fp;
	char *p;
	char s[32];
	static char buf[BUFSIZ];
	memset(buf, 0, sizeof(buf));
	snprintf(s, sizeof(s), PROC_DIR "/%d/attr/current", pid);
	if ((fp = fopen(s, "r")) == NULL)
		return NULL;
	if (fgets(buf, sizeof(buf), fp) != NULL)
		if ((p = strchr(buf, '\n')) != NULL)
			*p = 0;
	fclose(fp);
	return buf;
}

static const char *get_pid_type(int pid)
{
	char fname[32];
	elfobj *elf = NULL;
	char *ret = NULL;

	snprintf(fname, sizeof(fname), PROC_DIR "/%d/exe", pid);
	if ((elf = readelf(fname)) == NULL)
		return ret;
	if (!check_elf_header(elf->ehdr) && IS_ELF(elf))
		ret = (char *)get_elfetype(elf->ehdr->e_type);
	unreadelf(elf);
	return ret;
}

static void pspax()
{
	register DIR *dir;
	register struct dirent *de;
	pid_t pid;
	struct passwd *uid;
	struct stat st;
	const char *pax, *type, *name, *caps, *attr;
#ifdef WANT_SYSCAP
	ssize_t length;
	cap_t cap_d;
	cap_d = cap_init();
#else
	caps = NULL;
#endif

	chdir(PROC_DIR);
	if (!(dir = opendir(PROC_DIR))) {
		perror(PROC_DIR);
		exit(EXIT_FAILURE);
	}
	if (show_banner)
		printf("%-8s %-6s %-6s %-10s %-16s %-4s %-4s\n",
		       "USER", "PID", "PAX", "ELF_TYPE", "NAME", "CAPS", "ATTR");

	while ((de = readdir(dir))) {
		errno = 0;
		stat(de->d_name, &st);
		if ((errno != ENOENT) && (errno != EACCES)) {
			pid = (pid_t) atoi((char *) basename((char *) de->d_name));
			if (!pid)
				continue;

#ifdef WANT_SYSCAP
			/* this is a non-POSIX function */
			capgetp(pid, cap_d);
			caps = cap_to_text(cap_d, &length);
#endif

			uid = get_proc_uid(pid);
			pax = get_proc_status(pid, "PAX");
			type = get_pid_type(pid);
			name = get_proc_name(pid);
			attr = get_pid_attr(pid);

			if (show_all || type)
				printf("%-8s %-6d %-6s %-10s %-16s %-4s %s\n",
				       uid  ? uid->pw_name : "--------",
				       pid,
				       pax  ? pax  : "---",
				       type ? type : "-------",
				       name ? name : "-----",
				       caps ? caps : " = ",
				       attr ? attr : "-");
#ifdef WANT_SYSCAP
			if (caps)
				cap_free(caps);
#endif
		}
	}
	closedir(dir);
}



/* usage / invocation handling functions */
#define PARSE_FLAGS "aBhv"
static struct option const long_opts[] = {
	{"all",       no_argument, NULL, 'a'},
	{"nobanner",  no_argument, NULL, 'B'},
	{"help",      no_argument, NULL, 'h'},
	{"version",   no_argument, NULL, 'V'},
	{NULL,        no_argument, NULL, 0x0}
};
static char *opts_help[] = {
	"Show all processes\n",
	"Don't display the header",
	"Print this help and exit",
	"Print version and exit",
	NULL
};

/* display usage and exit */
static void usage(int status)
{
	int i;
	printf("¤ List ELF/PaX information about running processes\n\n"
	       "Usage: %s [options]\n\n", argv0);
	fputs("Options:\n", stdout);
	for (i = 0; long_opts[i].name; ++i)
		printf("  -%c, --%-12s× %s\n", long_opts[i].val, 
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

	opterr = 0;
	while ((flag=getopt_long(argc, argv, PARSE_FLAGS, long_opts, NULL)) != -1) {
		switch (flag) {

		case 'V':                        /* version info */
			printf("%s compiled %s\n"
			       "%s written for Gentoo Linux by <solar and vapier @ gentoo.org>\n"
			       "%s\n",
			       __FILE__, __DATE__, argv0, rcsid);
			exit(EXIT_SUCCESS);
			break;
		case 'h': usage(EXIT_SUCCESS); break;

		case 'B': show_banner = 0; break;
		case 'a': show_all = 1; break;

		case ':':
			warn("Option missing parameter");
			usage(EXIT_FAILURE);
			break;
		case '?':
			warn("Unknown option");
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
	parseargs(argc, argv);
	pspax();
	return EXIT_SUCCESS;
}
