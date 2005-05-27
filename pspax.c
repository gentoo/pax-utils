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

static const char *rcsid = "$Id: pspax.c,v 1.16 2005/05/27 02:57:09 vapier Exp $";
#define argv0 "pspax"



/* variables to control behavior */
static char show_all = 0;
static char show_banner = 1;



static char *get_proc_name(pid_t pid)
{
	FILE *fp;
	static char str[_POSIX_PATH_MAX];
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

int get_proc_maps(pid_t pid) {
	static char str[_POSIX_PATH_MAX];
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
			++p; // ' '
			++p; // r
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

static struct passwd *get_proc_uid(pid_t pid)
{
	struct stat st;
	struct passwd *pwd;
	static char str[_POSIX_PATH_MAX];

	snprintf(str, sizeof(str), PROC_DIR "/%u/stat", pid);

	/* this is bullshit but getpwuid() is leaking memory
	 * and I've wasted a few hrs 1 day tracking it down.
	 * I forgot I tracked it down before and saw pspax leaking
	 * memory so I tracked it down again (silly me)
	 * anyway.. please leave this comment here so I don't waste my
	 * time again the next time I forget.
	 * and till such time as getpwuid()/nis/nss/pam or whatever does not suck.
	 */
	if ((stat(str, &st)) != (-1))
		if ((pwd = getpwuid(st.st_uid)) != NULL)
			return pwd;
	return NULL;
}

static char *get_proc_status(pid_t pid, char *name)
{
	FILE *fp;
	size_t len;
	static char str[_POSIX_PATH_MAX];

	snprintf(str, sizeof(str), PROC_DIR "/%u/status", pid);
	if ((fp = fopen(str, "r")) == NULL)
		return NULL;

	len = strlen(name);
	while (fgets(str, sizeof(str), fp)) {
		if (strncasecmp(str, name, len) == 0) {
			if (str[len] == ':') {
				fclose(fp);
				str[strlen(str) - 1] = 0;
				return (str + len + 2);
			}
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

static void pspax(void)
{
	register DIR *dir;
	register struct dirent *de;
	pid_t pid;
	int have_attr, wx;
	struct passwd *uid;
	struct stat st;
	const char *pax, *type, *name, *caps, *attr;
#ifdef WANT_SYSCAP
	ssize_t length;
	cap_t cap_d;

	cap_d = cap_init();
#endif

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
		printf("%-8s %-6s %-6s %-4s %-10s %-16s %-4s %-4s\n",
		       "USER", "PID", "PAX", "MAPS", "ELF_TYPE", "NAME", "CAPS", "ATTR");

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
			wx  = get_proc_maps(pid);
			type = get_proc_type(pid);
			name = get_proc_name(pid);
			attr = (have_attr ? get_pid_attr(pid) : NULL);

			if (show_all || type)
				printf("%-8s %-6d %-6s %-4s %-10s %-16s %-4s %s\n",
				       uid  ? uid->pw_name : "--------",
				       pid,
				       pax  ? pax  : "---",
				       (wx == 1) ? "w|x" : (wx == -1) ? "---" : "w^x",
				       type ? type : "-------",
				       name ? name : "-----",
				       caps ? caps : " = ",
				       attr ? attr : "-");
#ifdef WANT_SYSCAP
			if (caps)
				cap_free((void *)caps);
#endif
		}
	}
	closedir(dir);
}



/* usage / invocation handling functions */
#define PARSE_FLAGS "aBhV"
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
			printf("%s compiled %s\n%s\n"
			       "%s written for Gentoo Linux by <solar and vapier @ gentoo.org>\n",
			       __FILE__, __DATE__, rcsid, argv0);
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
