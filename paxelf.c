/*
 * Copyright 2003-2006 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/paxelf.c,v 1.31 2006/01/05 03:12:07 vapier Exp $
 *
 * Copyright 2005-2006 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2005-2006 Mike Frysinger  - <vapier@gentoo.org>
 */

#include "paxinc.h"

#define argv0 "paxelf"

/*
 * Setup a bunch of helper functions to translate
 * binary defines into readable strings.
 */
#define QUERY(n) { #n, n }
typedef struct {
	const char *str;
	int value;
} pairtype;
static inline const char *find_pairtype(pairtype *pt, int type)
{
	int i;
	for (i = 0; pt[i].str; ++i)
		if (type == pt[i].value)
			return pt[i].str;
	return "UNKNOWN TYPE";
}

/* translate misc elf EI_ defines */
static pairtype elf_ei_class[] = {
	QUERY(ELFCLASSNONE),
	QUERY(ELFCLASS32),
	QUERY(ELFCLASS64),
	QUERY(ELFCLASSNUM),
	{ 0, 0 }
};
static pairtype elf_ei_data[] = {
	QUERY(ELFDATANONE),
	QUERY(ELFDATA2LSB),
	QUERY(ELFDATA2MSB),
	QUERY(ELFDATANUM),
	{ 0, 0 }
};
static pairtype elf_ei_version[] = {
	QUERY(EV_NONE),
	QUERY(EV_CURRENT),
	QUERY(EV_NUM),
	{ 0, 0 }
};
static pairtype elf_ei_osabi[] = {
	QUERY(ELFOSABI_NONE),
	QUERY(ELFOSABI_SYSV),
	QUERY(ELFOSABI_HPUX),
	QUERY(ELFOSABI_NETBSD),
	QUERY(ELFOSABI_LINUX),
	QUERY(ELFOSABI_SOLARIS),
	QUERY(ELFOSABI_AIX),
	QUERY(ELFOSABI_IRIX),
	QUERY(ELFOSABI_FREEBSD),
	QUERY(ELFOSABI_TRU64),
	QUERY(ELFOSABI_MODESTO),
	QUERY(ELFOSABI_OPENBSD),
	QUERY(ELFOSABI_ARM),
	QUERY(ELFOSABI_STANDALONE),
	{ 0, 0 }
};
const char *get_elfeitype(int ei_type, int type)
{
	switch (ei_type) {
		case EI_CLASS:   return find_pairtype(elf_ei_class, type);
		case EI_DATA:    return find_pairtype(elf_ei_data, type);
		case EI_VERSION: return find_pairtype(elf_ei_version, type);
		case EI_OSABI:   return find_pairtype(elf_ei_osabi, type);
	}
	return "UNKNOWN EI TYPE";
}

/* translate elf ET_ defines */
static pairtype elf_etypes[] = {
	QUERY(ET_NONE),
	QUERY(ET_REL),
	QUERY(ET_EXEC),
	QUERY(ET_DYN),
	QUERY(ET_CORE),
	QUERY(ET_NUM),
	QUERY(ET_LOOS),
	QUERY(ET_HIOS),
	QUERY(ET_LOPROC),
	QUERY(ET_HIPROC),
	{ 0, 0 }
};
const char *get_elfetype(elfobj *elf)
{
	int type;
	if (elf->elf_class == ELFCLASS32)
		type = EGET(EHDR32(elf->ehdr)->e_type);
	else
		type = EGET(EHDR64(elf->ehdr)->e_type);
	return find_pairtype(elf_etypes, type);
}

/* translate elf EM_ defines */
static pairtype elf_emtypes[] = {
	QUERY(EM_NONE),
	QUERY(EM_M32),
	QUERY(EM_SPARC),
	QUERY(EM_386),
	QUERY(EM_68K),
	QUERY(EM_88K),
	QUERY(EM_860),
	QUERY(EM_MIPS),
	QUERY(EM_S370),
	QUERY(EM_MIPS_RS3_LE),
	QUERY(EM_PARISC),
	QUERY(EM_VPP500),
	QUERY(EM_SPARC32PLUS),
	QUERY(EM_960),
	QUERY(EM_PPC),
	QUERY(EM_PPC64),
	QUERY(EM_S390),
	QUERY(EM_V800),
	QUERY(EM_FR20),
	QUERY(EM_RH32),
	QUERY(EM_RCE),
	QUERY(EM_ARM),
	QUERY(EM_FAKE_ALPHA),
	QUERY(EM_SH),
	QUERY(EM_SPARCV9),
	QUERY(EM_TRICORE),
	QUERY(EM_ARC),
	QUERY(EM_H8_300),
	QUERY(EM_H8_300H),
	QUERY(EM_H8S),
	QUERY(EM_H8_500),
	QUERY(EM_IA_64),
	QUERY(EM_MIPS_X),
	QUERY(EM_COLDFIRE),
	QUERY(EM_68HC12),
	QUERY(EM_MMA),
	QUERY(EM_PCP),
	QUERY(EM_NCPU),
	QUERY(EM_NDR1),
	QUERY(EM_STARCORE),
	QUERY(EM_ME16),
	QUERY(EM_ST100),
	QUERY(EM_TINYJ),
	QUERY(EM_X86_64),
	QUERY(EM_PDSP),
	QUERY(EM_FX66),
	QUERY(EM_ST9PLUS),
	QUERY(EM_ST7),
	QUERY(EM_68HC16),
	QUERY(EM_68HC11),
	QUERY(EM_68HC08),
	QUERY(EM_68HC05),
	QUERY(EM_SVX),
	QUERY(EM_ST19),
	QUERY(EM_VAX),
	QUERY(EM_CRIS),
	QUERY(EM_JAVELIN),
	QUERY(EM_FIREPATH),
	QUERY(EM_ZSP),
	QUERY(EM_MMIX),
	QUERY(EM_HUANY),
	QUERY(EM_PRISM),
	QUERY(EM_AVR),
	QUERY(EM_FR30),
	QUERY(EM_D10V),
	QUERY(EM_D30V),
	QUERY(EM_V850),
	QUERY(EM_M32R),
	QUERY(EM_MN10300),
	QUERY(EM_MN10200),
	QUERY(EM_PJ),
	QUERY(EM_OPENRISC),
	QUERY(EM_ARC_A5),
	QUERY(EM_XTENSA),
	QUERY(EM_NUM),
	QUERY(EM_ALPHA),
	{ 0, 0 }
};
const char *get_elfemtype(int type)
{
	return find_pairtype(elf_emtypes, type);
}

/* translate elf PT_ defines */
static pairtype elf_ptypes[] = {
	QUERY(PT_NULL),
	QUERY(PT_LOAD),
	QUERY(PT_DYNAMIC),
	QUERY(PT_INTERP),
	QUERY(PT_NOTE),
	QUERY(PT_SHLIB),
	QUERY(PT_PHDR),
	QUERY(PT_TLS),
	QUERY(PT_GNU_EH_FRAME),
	QUERY(PT_GNU_STACK),
	QUERY(PT_GNU_RELRO),
	QUERY(PT_PAX_FLAGS),
	{ 0, 0 }
};
const char *get_elfptype(int type)
{
	return find_pairtype(elf_ptypes, type);
}

/* translate elf PT_ defines */
static pairtype elf_dtypes[] = {
	QUERY(DT_NULL),
	QUERY(DT_NEEDED),
	QUERY(DT_PLTRELSZ),
	QUERY(DT_PLTGOT),
	QUERY(DT_HASH),
	QUERY(DT_STRTAB),
	QUERY(DT_SYMTAB),
	QUERY(DT_RELA),
	QUERY(DT_RELASZ),
	QUERY(DT_RELAENT),
	QUERY(DT_STRSZ),
	QUERY(DT_SYMENT),
	QUERY(DT_INIT),
	QUERY(DT_FINI),
	QUERY(DT_SONAME),
	QUERY(DT_RPATH),
	QUERY(DT_SYMBOLIC),
	QUERY(DT_REL),
	QUERY(DT_RELSZ),
	QUERY(DT_RELENT),
	QUERY(DT_PLTREL),
	QUERY(DT_DEBUG),
	QUERY(DT_TEXTREL),
	QUERY(DT_JMPREL),
	QUERY(DT_BIND_NOW),
	QUERY(DT_INIT_ARRAY),
	QUERY(DT_FINI_ARRAY),
	QUERY(DT_INIT_ARRAYSZ),
	QUERY(DT_FINI_ARRAYSZ),
	QUERY(DT_RUNPATH),
	QUERY(DT_FLAGS),
	QUERY(DT_ENCODING),
	QUERY(DT_PREINIT_ARRAY),
	QUERY(DT_PREINIT_ARRAYSZ),
	QUERY(DT_NUM),
	{ 0, 0 }
};
const char *get_elfdtype(int type)
{
	return find_pairtype(elf_dtypes, type);
}

/* translate elf SHT_ defines */
static pairtype elf_shttypes[] = {
	QUERY(SHT_NULL),
	QUERY(SHT_PROGBITS),
	QUERY(SHT_SYMTAB),
	QUERY(SHT_STRTAB),
	QUERY(SHT_RELA),
	QUERY(SHT_HASH),
	QUERY(SHT_DYNAMIC),
	QUERY(SHT_NOTE),
	QUERY(SHT_NOBITS),
	QUERY(SHT_REL),
	QUERY(SHT_SHLIB),
	QUERY(SHT_DYNSYM),
	QUERY(SHT_INIT_ARRAY),
	QUERY(SHT_FINI_ARRAY),
	QUERY(SHT_PREINIT_ARRAY),
	QUERY(SHT_GROUP),
	QUERY(SHT_SYMTAB_SHNDX),
	QUERY(SHT_NUM),
	QUERY(SHT_LOOS),
	QUERY(SHT_GNU_LIBLIST),
	QUERY(SHT_CHECKSUM),
	QUERY(SHT_LOSUNW),
	QUERY(SHT_SUNW_move),
	QUERY(SHT_SUNW_COMDAT),
	QUERY(SHT_SUNW_syminfo),
	QUERY(SHT_GNU_verdef),
	QUERY(SHT_GNU_verneed),
	QUERY(SHT_GNU_versym),
	QUERY(SHT_HISUNW),
	QUERY(SHT_HIOS),
	QUERY(SHT_LOPROC),
	QUERY(SHT_HIPROC),
	QUERY(SHT_LOUSER),
	QUERY(SHT_HIUSER),
	{ 0, 0 }
};
const char *get_elfshttype(int type)
{
	return find_pairtype(elf_shttypes, type);
}

/* translate elf STT_ defines */
static pairtype elf_stttypes[] = {
	QUERY(STT_NOTYPE),
	QUERY(STT_OBJECT),
	QUERY(STT_FUNC),
	QUERY(STT_SECTION),
	QUERY(STT_FILE),
	QUERY(STT_LOPROC),
	QUERY(STT_HIPROC),
	QUERY(STB_LOCAL),
	QUERY(STB_GLOBAL),
	QUERY(STB_WEAK),
	QUERY(STB_LOPROC),
	QUERY(STB_HIPROC),
	{ 0, 0 }
};
const char *get_elfstttype(int type)
{
	return find_pairtype(elf_stttypes, type & 0xF);
}

/* Read an ELF into memory */
#define IS_ELF_BUFFER(buff) \
	(buff[EI_MAG0] == ELFMAG0 && \
	 buff[EI_MAG1] == ELFMAG1 && \
	 buff[EI_MAG2] == ELFMAG2 && \
	 buff[EI_MAG3] == ELFMAG3)
#define DO_WE_LIKE_ELF(buff) \
	((buff[EI_CLASS] == ELFCLASS32 || buff[EI_CLASS] == ELFCLASS64) && \
	 (buff[EI_DATA] == ELFDATA2LSB || buff[EI_DATA] == ELFDATA2MSB) && \
	 (buff[EI_VERSION] == EV_CURRENT))
elfobj *readelf(const char *filename)
{
	struct stat st;
	int fd;
	elfobj *elf;

	if (stat(filename, &st) == -1)
		return NULL;

	if ((fd = open(filename, O_RDONLY)) == -1)
		return NULL;

	/* make sure we have enough bytes to scan e_ident */
	if (st.st_size <= EI_NIDENT)
		goto close_fd_and_return;

	elf = (elfobj*)malloc(sizeof(*elf));
	if (elf == NULL)
		goto close_fd_and_return;
	memset(elf, 0x00, sizeof(*elf));

	elf->fd = fd;
	elf->len = st.st_size;
	elf->data = (char*)mmap(0, elf->len, PROT_READ, MAP_PRIVATE, fd, 0);
	if (elf->data == (char*)MAP_FAILED) {
		warn("mmap on '%s' of %li bytes failed :(", filename, (unsigned long)elf->len);
		goto free_elf_and_return;
	}

	if (!IS_ELF_BUFFER(elf->data)) /* make sure we have an elf */
		goto unmap_data_and_return;
	if (!DO_WE_LIKE_ELF(elf->data)) { /* check class and stuff */
		warn("we no likey %s: {%s,%s,%s,%s}",
		     filename,
		     get_elfeitype(EI_CLASS, elf->data[EI_CLASS]),
		     get_elfeitype(EI_DATA, elf->data[EI_DATA]),
		     get_elfeitype(EI_VERSION, elf->data[EI_VERSION]),
		     get_elfeitype(EI_OSABI, elf->data[EI_OSABI]));
		goto unmap_data_and_return;
	}

	elf->filename = filename;
	elf->base_filename = strrchr(filename, '/');
	if (elf->base_filename == NULL)
		elf->base_filename = elf->filename;
	else
		elf->base_filename = elf->base_filename + 1;
	elf->elf_class = elf->data[EI_CLASS];
	do_reverse_endian = (ELF_DATA != elf->data[EI_DATA]);
	elf->ehdr = (void*)elf->data;

#define READELF_HEADER(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
		Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
		Elf ## B ## _Off size; \
		/* verify program header */ \
		if (EGET(ehdr->e_phnum) > 0) { \
			elf->phdr = elf->data + EGET(ehdr->e_phoff); \
			size = EGET(ehdr->e_phnum) * EGET(ehdr->e_phentsize); \
			if (elf->phdr < elf->ehdr || /* check overflow */ \
			    elf->phdr + size < elf->phdr || /* before start of mem */ \
			    elf->phdr + size > elf->ehdr + elf->len) /* before end of mem */ \
			{ \
				warn("%s: Invalid program header info", filename); \
				elf->phdr = NULL; \
			} \
		} else \
			elf->phdr = NULL; \
		/* verify section header */ \
		if (EGET(ehdr->e_shnum) > 0) { \
			elf->shdr = elf->data + EGET(ehdr->e_shoff); \
			size = EGET(ehdr->e_shnum) * EGET(ehdr->e_shentsize); \
			if (elf->shdr < elf->ehdr || /* check overflow */ \
			    elf->shdr + size < elf->shdr || /* before start of mem */ \
			    elf->shdr + size > elf->ehdr + elf->len) /* before end of mem */ \
			{ \
				warn("%s: Invalid section header info", filename); \
				elf->shdr = NULL; \
			} \
		} else \
			elf->shdr = NULL; \
	}
	READELF_HEADER(32)
	READELF_HEADER(64)
	/* { char *p; strncpy(elf->basename, (p = strrchr(filename, '/')) == NULL ? "?" : p+1 , sizeof(elf->basename)); } */

	return elf;

unmap_data_and_return:
	munmap(elf->data, elf->len);
free_elf_and_return:
	free(elf);
close_fd_and_return:
	close(fd);
	return NULL;
}

/* undo the readelf() stuff */
void unreadelf(elfobj *elf)
{
	munmap(elf->data, elf->len);
	close(elf->fd);
	free(elf);
}

char *pax_short_hf_flags(unsigned long flags)
{
	static char buffer[7];

	buffer[0] = (flags & HF_PAX_PAGEEXEC ? 'p' : 'P');
	buffer[1] = (flags & HF_PAX_EMUTRAMP ? 'E' : 'e');
	buffer[2] = (flags & HF_PAX_MPROTECT ? 'm' : 'M');
	buffer[3] = (flags & HF_PAX_RANDMMAP ? 'r' : 'R');
	buffer[4] = (flags & HF_PAX_RANDEXEC ? 'X' : 'x');
	buffer[5] = (flags & HF_PAX_SEGMEXEC ? 's' : 'S');
	buffer[6] = 0;

	return buffer;
}

/* the display logic is:
 * lower case: explicitly disabled
 * upper case: explicitly enabled
 * - : default */
char *pax_short_pf_flags(unsigned long flags)
{
	static char buffer[7];

	/* PT_PAX_FLAGS are tristate */
	buffer[0] = (flags & PF_PAGEEXEC ? 'P' : '-');
	buffer[0] = (flags & PF_NOPAGEEXEC ? 'p' : buffer[0]);

	buffer[1] = (flags & PF_SEGMEXEC ? 'S' : '-');
	buffer[1] = (flags & PF_NOSEGMEXEC ? 's' : buffer[1]);

	buffer[2] = (flags & PF_MPROTECT ? 'M' : '-');
	buffer[2] = (flags & PF_NOMPROTECT ? 'm' : buffer[2]);

	buffer[3] = (flags & PF_RANDEXEC ? 'X' : '-');
	buffer[3] = (flags & PF_NORANDEXEC ? 'x' : buffer[3]);

	buffer[4] = (flags & PF_EMUTRAMP ? 'E' : '-');
	buffer[4] = (flags & PF_NOEMUTRAMP ? 'e' : buffer[4]);

	buffer[5] = (flags & PF_RANDMMAP ? 'R' : '-');
	buffer[5] = (flags & PF_NORANDMMAP ? 'r' : buffer[5]);

	buffer[6] = 0;

  
	if (((flags & PF_PAGEEXEC) && (flags & PF_NOPAGEEXEC)) || ((flags & PF_SEGMEXEC) && (flags & PF_NOSEGMEXEC))
		|| ((flags & PF_RANDMMAP) && (flags & PF_NORANDMMAP)) || ((flags & PF_RANDEXEC) && (flags & PF_NORANDEXEC))
		|| ((flags & PF_EMUTRAMP) && (flags &  PF_NOEMUTRAMP)) || ((flags & PF_RANDMMAP) && (flags & PF_NORANDMMAP)))
		warn("inconsistent state detected. flags=%lu\n", flags);

	return buffer;
}

char *gnu_short_stack_flags(unsigned long flags)
{
	static char buffer[4];

	buffer[0] = (flags & PF_R ? 'R' : '-');
	buffer[1] = (flags & PF_W ? 'W' : '-');
	buffer[2] = (flags & PF_X ? 'X' : '-');
	buffer[3] = 0;

	return buffer;
}

void *elf_findsecbyname(elfobj *elf, const char *name)
{
	unsigned int i;
	char *shdr_name;
	void *ret = NULL;

	if (elf->shdr == NULL) return NULL;

#define FINDSEC(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
	Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
	Elf ## B ## _Shdr *shdr = SHDR ## B (elf->shdr); \
	Elf ## B ## _Shdr *strtbl; \
	Elf ## B ## _Off offset; \
	uint16_t shstrndx = EGET(ehdr->e_shstrndx); \
	uint16_t shnum = EGET(ehdr->e_shnum); \
	if (shstrndx >= shnum) return NULL; \
	strtbl = &(shdr[shstrndx]); \
	for (i = 0; i < shnum; ++i) { \
		if (EGET(shdr[i].sh_offset) >= elf->len - EGET(ehdr->e_shentsize)) continue; \
		offset = EGET(strtbl->sh_offset) + EGET(shdr[i].sh_name); \
		if (offset >= (Elf ## B ## _Off)elf->len) continue; \
		shdr_name = (char*)(elf->data + offset); \
		if (!strcmp(shdr_name, name)) { \
			if (ret) warnf("Multiple '%s' sections !?", name); \
			ret = (void*)&(shdr[i]); \
		} \
	} }
	FINDSEC(32)
	FINDSEC(64)

	return ret;
}
