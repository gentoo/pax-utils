/*
 *	Jan 14 2004	- solar@gentoo
 *
 *	find RWX STACK segments.
 * ./pttool /{usr/{local/,},}{s,}bin/globstar > /dev/null
 */


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "paxelf.h"

void scan_program_header(const char *filename)
{
	int i;
	elfobj *elf = NULL;

	if ((elf = readelf((char *) filename)) == NULL)
		return;
	if (check_elf_header(elf->ehdr))
		goto bail;
	if (!(IS_ELF(elf) && (IS_ELF_ET_DYN(elf) || IS_ELF_ET_EXEC(elf))))
		goto bail;

	// printf("Entry point 0x%08X '%c' %s\n",
	//   elf->ehdr->e_entry,
	//   IS_ELF_ET_DYN(elf) ? '*' : '&', filename);
	for (i = 0; i < elf->ehdr->e_phnum; i++) {
		switch (elf->phdr[i].p_type) {
		case PT_LOAD:
			// printf("LOAD it's only one 0x%X\n", elf->phdr[i].p_flags);
			break;
		case PT_DYNAMIC:
			//has_textrel(elf);
			break;
		case PT_PAX_FLAGS:
			printf("--- %s %s %s\n", "PT_PAX_FLAGS",
			       pax_short_pf_flags(elf->phdr[i].p_flags),
			       filename);
			break;
		case PT_GNU_STACK:
		case PT_GNU_RELRO:
			if (elf->phdr[i].p_flags & PF_R || \
			    elf->phdr[i].p_flags & PF_W || \
			    elf->phdr[i].p_flags & PF_X)
			{
				printf("%c%c%c %s %-12s %s\n",
				       (elf->phdr[i].p_flags & PF_R ? 'R' : '-'),
				       (elf->phdr[i].p_flags & PF_W ? 'W' : '-'),
				       (elf->phdr[i].p_flags & PF_X ? 'X' : '-'),
				       get_elfptype(elf->phdr[i].p_type),
				       pax_short_hf_flags(PAX_FLAGS(elf)),
				       filename);
				if (elf->phdr[i].p_flags == (PF_W | PF_X))
					fprintf(stderr,
					        "WARN: %s has %s writable and executable memory segment\n",
					        filename,
					        get_elfptype(elf->phdr[i].p_type));
			}
		default:
			break;
		}
	}
bail:
	unreadelf(elf);
}

void usage(int status)
{
	printf("Usage: pttool <file1> [file2 file3 ...]\n");
	exit(status);
}

int main(int argc, char *argv[])
{
	int i;

	if (argc <= 1)
		usage(EXIT_FAILURE);

	for (i=1; argv[i]; ++i)
		scan_program_header(argv[i]);

	return 0;
}
