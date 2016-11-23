/*
 * Copyright 2005-2012 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2005-2012 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2005-2012 Mike Frysinger  - <vapier@gentoo.org>
 */

const char argv0[] = "dumpelf";

#include "paxinc.h"

/* prototypes */
static void dumpelf(const char *filename, size_t file_cnt);
static void dump_ehdr(elfobj *elf, const void *ehdr);
static void dump_phdr(elfobj *elf, const void *phdr, size_t phdr_cnt);
static void dump_shdr(elfobj *elf, const void *shdr, size_t shdr_cnt, const char *section_name);
static void dump_dyn(elfobj *elf, const void *dyn, size_t dyn_cnt);
#if 0
static void dump_sym(elfobj *elf, const void *sym);
static void dump_rel(elfobj *elf, const void *rel);
static void dump_rela(elfobj *elf, const void *rela);
#endif
static void usage(int status);
static void parseargs(int argc, char *argv[]);

/* variables to control behavior */
static char be_verbose = 0;

/* misc dynamic tag caches */
static const void *phdr_dynamic_void;

/* dump all internal elf info */
static void dumpelf(const char *filename, size_t file_cnt)
{
	elfobj *elf;
	size_t i, b;

	/* verify this is real ELF */
	if ((elf = readelf(filename)) == NULL)
		return;

	phdr_dynamic_void = NULL;

	printf("#include <elf.h>\n");

	printf(
		"\n"
		"/*\n"
		" * ELF dump of '%s'\n"
		" *     %ji (0x%jX) bytes\n"
		" */\n\n",
		filename, elf->len, elf->len);

	/* setup the struct to namespace this elf */
#define MAKE_STRUCT(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
	Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
	b = B; \
	printf( \
		"Elf%1$i_Dyn dumpedelf_dyn_%2$zu[];\n" \
		"struct {\n" \
		"\tElf%1$i_Ehdr ehdr;\n" \
		"\tElf%1$i_Phdr phdrs[%3$u];\n" \
		"\tElf%1$i_Shdr shdrs[%4$u];\n" \
		"\tElf%1$i_Dyn *dyns;\n" \
		"} dumpedelf_%2$zu = {\n\n", \
		B, file_cnt, \
		(uint16_t)EGET(ehdr->e_phnum), \
		(uint16_t)EGET(ehdr->e_shnum) \
	); \
	}
	MAKE_STRUCT(32)
	MAKE_STRUCT(64)

	/* dump the elf header */
	dump_ehdr(elf, elf->ehdr);

	/* dump the program headers */
	printf("\n.phdrs = {\n");
	if (elf->phdr) {
#define DUMP_PHDRS(B) \
		if (elf->elf_class == ELFCLASS ## B) { \
		const Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
		const Elf ## B ## _Phdr *phdr = PHDR ## B (elf->phdr); \
		uint16_t phnum = EGET(ehdr->e_phnum); \
		for (i = 0; i < phnum; ++i, ++phdr) \
			dump_phdr(elf, phdr, i); \
		}
		DUMP_PHDRS(32)
		DUMP_PHDRS(64)
	} else {
		printf(" /* no program headers ! */ ");
	}
	printf("},\n");

	/* dump the section headers */
	printf("\n.shdrs = {\n");
	if (elf->shdr) {
#define DUMP_SHDRS(B) \
		if (elf->elf_class == ELFCLASS ## B) { \
		const Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
		const Elf ## B ## _Shdr *shdr = SHDR ## B (elf->shdr); \
		uint16_t shstrndx = EGET(ehdr->e_shstrndx); \
		const Elf ## B ## _Shdr *strtbl = shdr + shstrndx; \
		Elf ## B ## _Off offset; \
		uint16_t shnum = EGET(ehdr->e_shnum); \
		if (shstrndx >= shnum || !VALID_SHDR(elf, strtbl)) { \
			printf(" /* corrupt section header strings table ! */ "); \
			goto break_out_shdr; \
		} \
		offset = EGET(strtbl->sh_offset); \
		for (i = 0; i < shnum; ++i, ++shdr) \
			/* Don't use VALID_SHDR as we want to decode the fields */ \
			dump_shdr(elf, shdr, i, elf->vdata + offset + EGET(shdr->sh_name)); \
		}
		DUMP_SHDRS(32)
		DUMP_SHDRS(64)
	} else {
		printf(" /* no section headers ! */ ");
	}
 break_out_shdr:
	printf("},\n");

	/* finish the namespace struct and start the abitrary ones */
	printf("\n.dyns = dumpedelf_dyn_%zu,\n", file_cnt);
	printf("};\n");

	/* start the arbitrary structs */
	printf("Elf%zu_Dyn dumpedelf_dyn_%zu[] = {\n", b, file_cnt);
	if (phdr_dynamic_void) {
#define DUMP_DYNS(B) \
		if (elf->elf_class == ELFCLASS ## B) { \
		const Elf ## B ## _Phdr *phdr = phdr_dynamic_void; \
		const Elf ## B ## _Dyn *dyn = elf->vdata + EGET(phdr->p_offset); \
		i = 0; \
		do { \
			if ((void *)dyn >= elf->data_end - sizeof(*dyn)) { \
				printf(" /* invalid dynamic tags ! */ "); \
				break; \
			} \
			dump_dyn(elf, dyn++, i++); \
		} while (EGET(dyn->d_tag) != DT_NULL); \
		}
		DUMP_DYNS(32)
		DUMP_DYNS(64)
	} else {
		printf(" /* no dynamic tags ! */ ");
	}
	printf("};\n");

	/* get out of here */
	unreadelf(elf);
}

static void dump_ehdr(elfobj *elf, const void *ehdr_void)
{
#define DUMP_EHDR(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
	const Elf ## B ## _Ehdr *ehdr = EHDR ## B (ehdr_void); \
	printf(".ehdr = {\n"); \
	printf("\t.e_ident = { /* (EI_NIDENT bytes) */\n" \
	       "\t\t/* [%i] EI_MAG:        */ 0x%X,'%c','%c','%c',\n" \
	       "\t\t/* [%i] EI_CLASS:      */ %u , /* (%s) */\n" \
	       "\t\t/* [%i] EI_DATA:       */ %u , /* (%s) */\n" \
	       "\t\t/* [%i] EI_VERSION:    */ %u , /* (%s) */\n" \
	       "\t\t/* [%i] EI_OSABI:      */ %u , /* (%s) */\n" \
	       "\t\t/* [%i] EI_ABIVERSION: */ %u ,\n" \
	       "\t\t/* [%i-%i] EI_PAD:     */ 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X,\n" \
	       "\t},\n", \
	       EI_MAG0, ehdr->e_ident[EI_MAG0], ehdr->e_ident[EI_MAG1], ehdr->e_ident[EI_MAG2], ehdr->e_ident[EI_MAG3], \
	       EI_CLASS, ehdr->e_ident[EI_CLASS], get_elfeitype(EI_CLASS, ehdr->e_ident[EI_CLASS]), \
	       EI_DATA, ehdr->e_ident[EI_DATA], get_elfeitype(EI_DATA, ehdr->e_ident[EI_DATA]), \
	       EI_VERSION, ehdr->e_ident[EI_VERSION], get_elfeitype(EI_VERSION, ehdr->e_ident[EI_VERSION]), \
	       EI_OSABI, ehdr->e_ident[EI_OSABI], get_elfeitype(EI_OSABI, ehdr->e_ident[EI_OSABI]), \
	       EI_ABIVERSION, ehdr->e_ident[EI_ABIVERSION], \
	       EI_PAD, EI_NIDENT - 1, \
	         ehdr->e_ident[EI_PAD + 0], \
	         ehdr->e_ident[EI_PAD + 1], \
	         ehdr->e_ident[EI_PAD + 2], \
	         ehdr->e_ident[EI_PAD + 3], \
	         ehdr->e_ident[EI_PAD + 4], \
	         ehdr->e_ident[EI_PAD + 5], \
	         ehdr->e_ident[EI_PAD + 6] \
	); \
	printf("\t.e_type      = %-10u , /* (%s) */\n", (uint16_t)EGET(ehdr->e_type), get_elfetype(elf)); \
	printf("\t.e_machine   = %-10u , /* (%s) */\n", (uint16_t)EGET(ehdr->e_machine), get_elfemtype(elf)); \
	printf("\t.e_version   = %-10u , /* (%s) */\n", (uint32_t)EGET(ehdr->e_version), get_elfeitype(EI_VERSION, EGET(ehdr->e_version))); \
	printf("\t.e_entry     = 0x%-8"PRIX64" , /* (start address at runtime) */\n", EGET(ehdr->e_entry)); \
	printf("\t.e_phoff     = %-10"PRIi64" , /* (bytes into file) */\n", EGET(ehdr->e_phoff)); \
	printf("\t.e_shoff     = %-10"PRIi64" , /* (bytes into file) */\n", EGET(ehdr->e_shoff)); \
	printf("\t.e_flags     = 0x%-8X ,\n", (uint32_t)EGET(ehdr->e_flags)); \
	printf("\t.e_ehsize    = %-10u , /* (bytes) */\n", (uint16_t)EGET(ehdr->e_ehsize)); \
	printf("\t.e_phentsize = %-10u , /* (bytes) */\n", (uint16_t)EGET(ehdr->e_phentsize)); \
	/* TODO: Handle PN_XNUM */ \
	printf("\t.e_phnum     = %-10u , /* (program headers) */\n", (uint16_t)EGET(ehdr->e_phnum)); \
	printf("\t.e_shentsize = %-10u , /* (bytes) */\n", (uint16_t)EGET(ehdr->e_shentsize)); \
	printf("\t.e_shnum     = %-10u , /* (section headers) */\n", (uint16_t)EGET(ehdr->e_shnum)); \
	printf("\t.e_shstrndx  = %-10u\n", (uint16_t)EGET(ehdr->e_shstrndx)); \
	printf("},\n"); \
	}
	DUMP_EHDR(32)
	DUMP_EHDR(64)
}

static void dump_notes(elfobj *elf, size_t B, const void *memory, const void *memory_end)
{
	/* While normally we'd worry about Elf32_Nhdr vs Elf64_Nhdr, in the ELF
	 * world, the two structs are exactly the same.  So avoid ugly CPP.
	 */
	size_t i;
	const void *ndata = memory;
	const char *name;
	const unsigned char *desc;
	uint32_t namesz, descsz;
	const Elf32_Nhdr *note;
	/* The first few bytes are the same between 32 & 64 bit ELFs. */
	uint16_t e_type = EGET(((const Elf32_Ehdr *)elf->ehdr)->e_type);

	if (memory_end > elf->data_end) {
		printf("\n\t/%c note section is corrupt */\n", '*');
		return;
	}

	printf("\n\t/%c note section dump:\n", '*');
	for (i = 0; ndata < memory_end; ++i) {
		note = ndata;
		namesz = EGET(note->n_namesz);
		descsz = EGET(note->n_descsz);
		name = namesz ? ndata + sizeof(*note) : "";
		desc = descsz ? ndata + sizeof(*note) + ALIGN_UP(namesz, 4) : "";
		ndata += sizeof(*note) + ALIGN_UP(namesz, 4) + ALIGN_UP(descsz, 4);

		if (ndata > memory_end) {
			printf("\tNote is corrupt\n");
			break;
		}

		printf("\t * Elf%zu_Nhdr note%zu = {\n", B, i);
		printf("\t * \t.n_namesz = %u, (bytes) [%s]\n", namesz, name);
		printf("\t * \t.n_descsz = %u, (bytes)", descsz);
		if (descsz) {
			printf(" [ ");
			for (i = 0; i < descsz; ++i)
				printf("%.2X ", desc[i]);
			printf("]");
		}
		printf("\n");
		printf("\t * \t.n_type   = %"PRIX64", [%s]\n",
		       EGET(note->n_type), get_elfnttype(e_type, name, EGET(note->n_type)));
		printf("\t * };\n");
	}
	printf("\t */\n");
}

static const char *dump_p_flags(uint32_t type, uint32_t flags)
{
	static char buf[1024];
	char *p = buf;
	p[0] = p[1] = p[2] = '\0';

	if (flags & PF_R)
		p = stpcpy(p, " | PF_R");
	if (flags & PF_W)
		p = stpcpy(p, " | PF_W");
	if (flags & PF_X)
		p = stpcpy(p, " | PF_X");
	flags &= ~(PF_R | PF_W | PF_X);

	switch (type) {
	case PT_PAX_FLAGS:
#define X(b) if (flags & b) { p = stpcpy(p, " | " #b); flags &= ~b; }
		X(PF_PAGEEXEC) X(PF_NOPAGEEXEC)
		X(PF_SEGMEXEC) X(PF_NOSEGMEXEC)
		X(PF_MPROTECT) X(PF_NOMPROTECT)
		X(PF_RANDEXEC) X(PF_NORANDEXEC)
		X(PF_EMUTRAMP) X(PF_NOEMUTRAMP)
		X(PF_RANDMMAP) X(PF_NORANDMMAP)
#undef X
		break;
	}

	if (flags)
		sprintf(p, " | 0x%X", flags);

	return buf + 3;
}
static void dump_phdr(elfobj *elf, const void *phdr_void, size_t phdr_cnt)
{
#define DUMP_PHDR(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
	const Elf ## B ## _Phdr *phdr = PHDR ## B (phdr_void); \
	Elf ## B ## _Off offset = EGET(phdr->p_offset); \
	void *vdata = elf->vdata + offset; \
	uint32_t p_type = EGET(phdr->p_type); \
	switch (p_type) { \
	case PT_DYNAMIC: phdr_dynamic_void = phdr_void; break; \
	} \
	printf("/* Program Header #%zu 0x%tX */\n{\n", \
	       phdr_cnt, (uintptr_t)phdr_void - elf->udata); \
	printf("\t.p_type   = %-10u , /* [%s] */\n", p_type, get_elfptype(p_type)); \
	printf("\t.p_offset = %-10"PRIi64" , /* (bytes into file) */\n", EGET(phdr->p_offset)); \
	printf("\t.p_vaddr  = 0x%-8"PRIX64" , /* (virtual addr at runtime) */\n", EGET(phdr->p_vaddr)); \
	printf("\t.p_paddr  = 0x%-8"PRIX64" , /* (physical addr at runtime) */\n", EGET(phdr->p_paddr)); \
	printf("\t.p_filesz = %-10"PRIu64" , /* (bytes in file) */\n", EGET(phdr->p_filesz)); \
	printf("\t.p_memsz  = %-10"PRIu64" , /* (bytes in mem at runtime) */\n", EGET(phdr->p_memsz)); \
	printf("\t.p_flags  = 0x%-8X , /* %s */\n", (uint32_t)EGET(phdr->p_flags), dump_p_flags(p_type, EGET(phdr->p_flags))); \
	printf("\t.p_align  = %-10"PRIu64" , /* (min mem alignment in bytes) */\n", EGET(phdr->p_align)); \
	\
	if ((off_t)EGET(phdr->p_offset) > elf->len) { \
		printf("\t/* Warning: Program segment is corrupt. */\n"); \
		goto done##B; \
	} \
	\
	switch (p_type) { \
	case PT_NOTE: \
		dump_notes(elf, B, vdata, vdata + EGET(phdr->p_filesz)); \
		break; \
	} \
 done##B: \
	printf("},\n"); \
	}
	DUMP_PHDR(32)
	DUMP_PHDR(64)
}

static const char *timestamp(uint64_t stamp)
{
	/* This doesn't work when run on a 32-bit host with 32-bit time_t beyond
	 * beyond 2038, but we'll worry about that later.
	 */
	static char buf[20];
	time_t t;
	struct tm *tm;

	t = stamp;
	tm = gmtime(&t);
	snprintf (buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u:%02u",
		tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
		tm->tm_hour, tm->tm_min, tm->tm_sec);

	return buf;
}

static void dump_shdr(elfobj *elf, const void *shdr_void, size_t shdr_cnt, const char *section_name)
{
	size_t i;

	/* Make sure the string is valid. */
	if ((void *)section_name >= elf->data_end)
		section_name = "<corrupt>";
	else if (memchr(section_name, 0, elf->len - (section_name - elf->data)) == NULL)
		section_name = "<corrupt>";

#define DUMP_SHDR(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
	const Elf ## B ## _Shdr *shdr = SHDR ## B (shdr_void); \
	Elf ## B ## _Off offset = EGET(shdr->sh_offset); \
	uint32_t type = EGET(shdr->sh_type); \
	uint ## B ## _t size = EGET(shdr->sh_size); \
	\
	printf("/* Section Header #%zu '%s' 0x%tX */\n{\n", \
	       shdr_cnt, section_name, (uintptr_t)shdr_void - elf->udata); \
	printf("\t.sh_name      = %-10u ,\n", (uint32_t)EGET(shdr->sh_name)); \
	printf("\t.sh_type      = %-10u , /* [%s] */\n", (uint32_t)EGET(shdr->sh_type), get_elfshttype(type)); \
	printf("\t.sh_flags     = %-10"PRIu64" ,\n", EGET(shdr->sh_flags)); \
	printf("\t.sh_addr      = 0x%-8"PRIX64" ,\n", EGET(shdr->sh_addr)); \
	printf("\t.sh_offset    = %-10"PRIi64" , /* (bytes) */\n", (uint64_t)offset); \
	printf("\t.sh_size      = %-10"PRIu64" , /* (bytes) */\n", (uint64_t)size); \
	printf("\t.sh_link      = %-10u ,\n", (uint32_t)EGET(shdr->sh_link)); \
	printf("\t.sh_info      = %-10u ,\n", (uint32_t)EGET(shdr->sh_info)); \
	printf("\t.sh_addralign = %-10"PRIu64" ,\n", (uint64_t)EGET(shdr->sh_addralign)); \
	printf("\t.sh_entsize   = %-10"PRIu64"\n", (uint64_t)EGET(shdr->sh_entsize)); \
	\
	if (type == SHT_NOBITS) { \
		/* Special case so we can do valid check next. */ \
		if (be_verbose) \
			printf("\t/* NOBITS sections do not occupy the file. */\n"); \
	} else if (!(offset < (uint64_t)elf->len && size < (uint64_t)elf->len && offset <= elf->len - size)) { \
		printf(" /* corrupt section header ! */ "); \
	} else if (size && be_verbose) { \
		void *vdata = elf->vdata + offset; \
		unsigned char *data = vdata; \
		switch (type) { \
		case SHT_PROGBITS: { \
			if (strcmp(section_name, ".interp") == 0) { \
				printf("\n\t/* ELF interpreter: %s */\n", data); \
				break; \
			} \
			if (strcmp(section_name, ".comment") != 0) \
				break; \
			break; \
		} \
		case SHT_STRTAB: { \
			char b; \
			printf("\n\t/%c section dump:\n", '*'); \
			b = 1; \
			if (type == SHT_PROGBITS) --data; \
			for (i = 0; i < size; ++i) { \
				++data; \
				if (*data) { \
					if (b) printf("\t * "); \
					printf("%c", *data); \
					b = 0; \
				} else if (!b) { \
					printf("\n"); \
					b = 1; \
				} \
			} \
			printf("\t */\n"); \
			break; \
		} \
		case SHT_DYNSYM: { \
			Elf##B##_Sym *sym = vdata; \
			printf("\n\t/%c section dump:\n", '*'); \
			for (i = 0; i < EGET(shdr->sh_size) / EGET(shdr->sh_entsize); ++i) { \
				printf("\t * Elf%i_Sym sym%zu = {\n", B, i); \
				printf("\t * \t.st_name  = %u,\n", (uint32_t)EGET(sym->st_name)); \
				printf("\t * \t.st_value = 0x%"PRIX64",\n", EGET(sym->st_value)); \
				printf("\t * \t.st_size  = %"PRIu64", (bytes)\n", EGET(sym->st_size)); \
				printf("\t * \t.st_info  = %u,\n", (unsigned char)EGET(sym->st_info)); \
				printf("\t * \t.st_other = %u,\n", (unsigned char)EGET(sym->st_other)); \
				printf("\t * \t.st_shndx = %u\n", (uint16_t)EGET(sym->st_shndx)); \
				printf("\t * };\n"); \
				++sym; \
			} \
			printf("\t */\n"); \
			break; \
		} \
		case SHT_NOTE: \
			dump_notes(elf, B, vdata, vdata + EGET(shdr->sh_size)); \
			break; \
		case SHT_GNU_LIBLIST: { \
			Elf##B##_Lib *lib = vdata; \
			printf("\n\t/%c section dump:\n", '*'); \
			for (i = 0; i < EGET(shdr->sh_size) / EGET(shdr->sh_entsize); ++i) { \
				printf("\t * Elf%i_Lib lib%zu = {\n", B, i); \
				printf("\t * \t.l_name       = %"PRIu64",\n", EGET(lib->l_name)); \
				printf("\t * \t.l_time_stamp = 0x%"PRIX64", (%s)\n", \
				       EGET(lib->l_time_stamp), timestamp(EGET(lib->l_time_stamp))); \
				printf("\t * \t.l_checksum   = 0x%"PRIX64",\n", EGET(lib->l_checksum)); \
				printf("\t * \t.l_version    = %"PRIu64",\n", EGET(lib->l_version)); \
				printf("\t * \t.l_flags      = 0x%"PRIX64"\n", EGET(lib->l_flags)); \
				printf("\t * };\n"); \
				++lib; \
			} \
			printf("\t */\n"); \
		} \
		default: { \
			if (be_verbose <= 1) \
				break; \
			printf("\n\t/%c section dump:\n", '*'); \
			for (i = 0; i < size; ++i) { \
				++data; \
				if (i % 20 == 0) printf("\t * "); \
				printf("%.2X ", *data); /* this line can cause segfaults */ \
				if (i % 20 == 19) printf("\n"); \
			} \
			if (i % 20) printf("\n"); \
			printf("\t */\n"); \
		} \
		} \
	} \
	printf("},\n"); \
	}
	DUMP_SHDR(32)
	DUMP_SHDR(64)
}

static void dump_dyn(elfobj *elf, const void *dyn_void, size_t dyn_cnt)
{
#define DUMP_DYN(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
	const Elf ## B ## _Dyn *dyn = dyn_void; \
	int64_t tag = EGET(dyn->d_tag); \
	printf("/* Dynamic tag #%zu '%s' 0x%tX */\n{\n", \
	       dyn_cnt, get_elfdtype(tag), (uintptr_t)dyn_void - elf->udata); \
	printf("\t.d_tag     = 0x%-8"PRIX64" ,\n", tag); \
	printf("\t.d_un      = {\n"); \
	printf("\t\t.d_val = 0x%-8"PRIX64" ,\n", EGET(dyn->d_un.d_val)); \
	printf("\t\t.d_ptr = 0x%-8"PRIX64" ,\n", EGET(dyn->d_un.d_val)); \
	printf("\t},\n"); \
	printf("},\n"); \
	}
	DUMP_DYN(32)
	DUMP_DYN(64)
}

/* usage / invocation handling functions */
#define PARSE_FLAGS "vhV"
#define a_argument required_argument
static struct option const long_opts[] = {
	{"verbose",   no_argument, NULL, 'v'},
	{"help",      no_argument, NULL, 'h'},
	{"version",   no_argument, NULL, 'V'},
	{NULL,        no_argument, NULL, 0x0}
};
static const char * const opts_help[] = {
	"Be verbose (can be specified more than once)",
	"Print this help and exit",
	"Print version and exit",
	NULL
};

/* display usage and exit */
static void usage(int status)
{
	size_t i;
	printf("* Dump internal ELF structure\n\n"
	       "Usage: %s <file1> [file2 fileN ...]\n\n", argv0);
	printf("Options:\n");
	for (i = 0; long_opts[i].name; ++i)
		if (long_opts[i].has_arg == no_argument)
			printf("  -%c, --%-13s* %s\n", long_opts[i].val,
			       long_opts[i].name, opts_help[i]);
		else
			printf("  -%c, --%-6s <arg> * %s\n", long_opts[i].val,
			       long_opts[i].name, opts_help[i]);
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
			printf("pax-utils-%s: %s\n"
			       "%s written for Gentoo by <solar and vapier @ gentoo.org>\n",
			       VERSION, VCSID, argv0);
			exit(EXIT_SUCCESS);
			break;
		case 'h': usage(EXIT_SUCCESS); break;

		case 'v': be_verbose = (be_verbose % 20) + 1; break;

		case ':':
			err("Option missing parameter");
		case '?':
			err("Unknown option");
		default:
			err("Unhandled option '%c'", flag);
		}
	}

	if (optind == argc)
		err("Nothing to dump !?");

	{
	size_t file_cnt = 0;

	while (optind < argc)
		dumpelf(argv[optind++], file_cnt++);
	}
}

int main(int argc, char *argv[])
{
	security_init(false);
	if (argc < 2)
		usage(EXIT_FAILURE);
	parseargs(argc, argv);
	return EXIT_SUCCESS;
}
