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


#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <pwd.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
// #include <dlfcn.h>

#ifdef __linux__
#include <elf.h>
#include <asm/elf.h>
#else
#include <sys/elf_common.h>
#endif

#ifdef WANT_SYSCAP
#undef _POSIX_SOURCE
#include <sys/capability.h>
#endif

#define PROC_DIR "/proc"

#ifndef ELF_CLASS
#error "UNABLE TO DETECT ELF_CLASS"
#endif

#if (ELF_CLASS == ELFCLASS32)
#define Elf_Ehdr        Elf32_Ehdr
#define Elf_Phdr        Elf32_Phdr
#define Elf_Shdr	Elf32_Shdr
#define Elf_Dyn		Elf32_Dyn
#endif

#if (ELF_CLASS == ELFCLASS64)
#define Elf_Ehdr        Elf64_Ehdr
#define Elf_Phdr        Elf64_Phdr
#define Elf_Shdr	Elf64_Shdr
#define Elf_Dyn		Elf64_Dyn
#endif

struct Elf_File {
   Elf_Ehdr *ehdr;
   Elf_Phdr *phdr;
   Elf_Shdr *shdr;
   Elf_Dyn *dyn;
   char *data;
   int len;
};


typedef struct Elf_File elfobj;

#define IS_ELF(elf) ((elf->ehdr->e_ident[EI_CLASS] == ELFCLASS32 || elf->ehdr->e_ident[EI_CLASS] == ELFCLASS64))
#define IS_ELF_TYPE(elf, type) ((elf->ehdr->e_type == type) && IS_ELF(elf))
#define IS_ELF_ET_EXEC(elf) IS_ELF_TYPE(elf, ET_EXEC)
#define IS_ELF_ET_DYN(elf)  IS_ELF_TYPE(elf, ET_DYN)

#define QUERY(n) { #n, n }

struct elf_etypes {
   const char *str;
   int value;
} elf_etypes[] = {
   QUERY(ET_NONE),
       QUERY(ET_REL),
       QUERY(ET_EXEC),
       QUERY(ET_DYN),
       QUERY(ET_CORE),
       QUERY(ET_NUM),
       QUERY(ET_LOOS),
       QUERY(ET_HIOS),
       QUERY(ET_LOPROC),
       QUERY(ET_HIPROC)
};

extern char *basename();

char *get_proc_name(pid_t pid)
{
   FILE *fp;
   static char buf[PATH_MAX];

   memset(&buf, 0, sizeof(buf));

   snprintf(buf, sizeof(buf), "/proc/%d/stat", (int) pid);

   fp = fopen(buf, "r");

   if (fp == NULL)
      return "-----";

   fscanf(fp, "%*d %s.16", buf);

   if (*buf) {
      buf[strlen(buf) - 1] = '\0';
      buf[16] = 0;
      strcpy(buf, &buf[1]);
   }
   fclose(fp);
   return buf;
}

struct passwd *get_proc_uid(pid_t pid)
{
   struct passwd *pwd;
   struct stat st;
   static char s[PATH_MAX];

   snprintf(s, sizeof(s), "/proc/%d/stat", (int) pid);

   if ((stat(s, &st)) != (-1)) {
      if ((pwd = getpwuid(st.st_uid)) != NULL)
	 return pwd;
   }
   return NULL;
}

static char *get_proc_status(pid_t pid, char *name)
{
   FILE *fp;
   int len;
   static char s[PATH_MAX];

   snprintf(s, sizeof(s), "/proc/%d/status", (int) pid);
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
   snprintf(s, sizeof(s), "/proc/%d/attr/current", pid);
   if ((fp = fopen(s, "r")) == NULL)
      return "-";
   if (fgets(buf, sizeof(buf), fp) != NULL)
      if ((p = strchr(buf, '\n')) != NULL)
	 *p = 0;
   fclose(fp);
   return (char *) buf;
}

/* check the elf header */
int check_elf_header(Elf_Ehdr const *const ehdr)
{
   if (!ehdr || strncmp((void *) ehdr, ELFMAG, SELFMAG) != 0 ||
       (ehdr->e_ident[EI_CLASS] != ELFCLASS32
	&& ehdr->e_ident[EI_CLASS] != ELFCLASS64)
       || ehdr->e_ident[EI_VERSION] != EV_CURRENT) {
      return 1;
   }
   return 0;
}

/* Read an elf file into memory and map headers */
elfobj *readelf(char *filename)
{
   struct stat st;
   elfobj *elf;
   int fd;

   if (stat(filename, &st) == -1)
      return NULL;

   if ((fd = open(filename, O_RDONLY)) == -1)
      return NULL;

   if (st.st_size <= 0)
      return NULL;

   elf = NULL;
   elf = (void *) malloc(sizeof(elfobj));
   if (elf == NULL)
      return NULL;
   elf->len = st.st_size;
   elf->data =
       (char *) mmap(0, elf->len, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_DENYWRITE, fd, 0);

   if (elf->data == (char *) MAP_FAILED) {
      free(elf);
      return NULL;
   }

   elf->ehdr = (void *) elf->data;
   elf->phdr = (void *) (elf->data + elf->ehdr->e_phoff);
   elf->shdr = (void *) (elf->data + elf->ehdr->e_shoff);

   /* elf->fd = fd; */
   /* do we want to keep the fd open? */
   close(fd);
   return elf;
}

const char *get_elfetype(int type)
{
   int i;
   for (i = 0; i < sizeof(elf_etypes) / sizeof(elf_etypes[0]); i++)
      if (type == elf_etypes[i].value)
	 return elf_etypes[i].str;
   return "INVALID";
}

static char *get_pid_type(int pid)
{
   char fname[32];
   elfobj *elf = NULL;
   static char *ret;

   ret = "-------";

   snprintf(fname, sizeof(fname), "/proc/%d/exe", pid);
   if ((elf = readelf(fname)) == NULL)
      return ret;
   if (!check_elf_header(elf->ehdr))
      if (IS_ELF(elf))
	 ret = (char *) get_elfetype(elf->ehdr->e_type);
   munmap(elf->data, elf->len);
   free(elf);
   return ret;
}

void pspax()
{
   register DIR *dir;
   register struct dirent *de;
   pid_t pid;
   struct passwd *pwd;
   struct stat st;
   char *p, *result;

#ifdef WANT_SYSCAP
   ssize_t length;
   cap_t cap_d;
   cap_d = cap_init();
#endif

   chdir(PROC_DIR);
   if (!(dir = opendir(PROC_DIR))) {
      perror(PROC_DIR);
      exit(EXIT_FAILURE);
   }
   fprintf(stdout, "%8s %-6s %-6s %-10s %-16s %s\n",
	   "USER", "PID", "PAX", "ELF_TYPE", "NAME", "CAPS");

   while ((de = readdir(dir))) {
      errno = 0;
      stat(de->d_name, &st);
      if ((errno != ENOENT) && (errno != EACCES)) {
	 pid = (pid_t) atoi((char *) basename((char *) de->d_name));
	 if (!pid)
	    continue;
	 {
	    result = "=";
#ifdef WANT_SYSCAP
	    /* this is a non-POSIX function */
	    capgetp(pid, cap_d);
	    result = cap_to_text(cap_d, &length);
#endif
	    pwd = get_proc_uid(pid);
	    fprintf(stdout, "%-8s %-6d %-6s %-10s %-16s %s %s\n",
		    (pwd != NULL) ? pwd->pw_name : "-----",
		    pid,
		    (p =
		     get_proc_status(pid, "PAX")) ? p : "------",
		    get_pid_type(pid), get_proc_name(pid), result,
		    get_pid_attr(pid));
#ifdef WANT_SYSCAP
	    if (result)
	       cap_free(result);
#endif
	 }
      }
   }
   closedir(dir);
}

int main(int argc, char **argv)
{
   pspax();
   return 0;
}
