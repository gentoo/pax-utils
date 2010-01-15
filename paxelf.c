/*
 * Copyright 2003-2007 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/pax-utils/paxelf.c,v 1.70 2010/01/15 12:06:37 vapier Exp $
 *
 * Copyright 2005-2007 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2005-2007 Mike Frysinger  - <vapier@gentoo.org>
 */

#include "paxinc.h"

/*
 * Setup a bunch of helper functions to translate
 * binary defines into readable strings.
 */
#define QUERY(n) { #n, n }
typedef const struct {
	const char *str;
	int value;
} pairtype;
static inline const char *find_pairtype(pairtype *pt, int type)
{
	int i;
	for (i = 0; pt[i].str; ++i)
		if (type == pt[i].value)
			return pt[i].str;
	return "UNKNOWN_TYPE";
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
	return "UNKNOWN_EI_TYPE";
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

int get_etype(elfobj *elf)
{
	int type;
	if (elf->elf_class == ELFCLASS32)
		type = EGET(EHDR32(elf->ehdr)->e_type);
	else
		type = EGET(EHDR64(elf->ehdr)->e_type);
	return type;
}

const char *get_elfetype(elfobj *elf)
{
	return find_pairtype(elf_etypes, get_etype(elf));
}

const char *get_endian(elfobj *elf)
{
	switch (elf->data[EI_DATA]) {
		case ELFDATA2LSB: return "LE";
		case ELFDATA2MSB: return "BE";
		default:          return "??";
	}
}

static int arm_eabi_poker(elfobj *elf)
{
	unsigned int emachine, eflags;

	if (ELFOSABI_NONE != elf->data[EI_OSABI])
		return -1;

	if (elf->elf_class == ELFCLASS32) {
		emachine = EHDR32(elf->ehdr)->e_machine;
		eflags = EHDR32(elf->ehdr)->e_flags;
	} else {
		emachine = EHDR64(elf->ehdr)->e_machine;
		eflags = EHDR64(elf->ehdr)->e_flags;
	}

	if (EGET(emachine) == EM_ARM)
		return EF_ARM_EABI_VERSION(EGET(eflags)) >> 24;
	else
		return -1;
}

const char *get_elf_eabi(elfobj *elf)
{
	static char buf[26];
	int eabi = arm_eabi_poker(elf);
	if (eabi >= 0)
		snprintf(buf, sizeof(buf), "%i", eabi);
	else
		strcpy(buf, "?");
	return buf;
}

const char *get_elfosabi(elfobj *elf)
{
	const char *str = get_elfeitype(EI_OSABI, elf->data[EI_OSABI]);
	if (str)
		if (strlen(str) > 9)
			return str + 9;
	return "";
}

void print_etypes(FILE *stream)
{
	int i, wrap = 0;
	for (i = 0; elf_etypes[i].str; ++i) {
		fprintf(stream, " (%4x) = %-10s", elf_etypes[i].value, elf_etypes[i].str);
		if (++wrap >= 4) {
			fprintf(stream, "\n");
			wrap = 0;
		}
	}
	if (wrap)
		fprintf(stream, "\n");
}

int etype_lookup(const char *str)
{
	if (*str == 'E') {
		int i;
		for (i = 0; elf_etypes[i].str; ++i) {
			if (strcmp(str, elf_etypes[i].str) == 0)
				return elf_etypes[i].value;
		}
	}
	return atoi(str);
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
	QUERY(EM_VIDEOCORE),
	QUERY(EM_TMM_GPP),
	QUERY(EM_NS32K),
	QUERY(EM_TPC),
	QUERY(EM_SNP1K),
	QUERY(EM_ST200),
	QUERY(EM_IP2K),
	QUERY(EM_MAX),
	QUERY(EM_CR),
	QUERY(EM_F2MC16),
	QUERY(EM_MSP430),
	QUERY(EM_BLACKFIN),
	QUERY(EM_SE_C33),
	QUERY(EM_SEP),
	QUERY(EM_ARCA),
	QUERY(EM_UNICORE),
	QUERY(EM_NUM),
	QUERY(EM_ALPHA),
	{ 0, 0 }
};

int get_emtype(elfobj *elf)
{
	int type;
	if (elf->elf_class == ELFCLASS32)
		type = EGET(EHDR32(elf->ehdr)->e_machine);
	else
		type = EGET(EHDR64(elf->ehdr)->e_machine);
	return type;
}

const char *get_elfemtype(elfobj *elf)
{
	return find_pairtype(elf_emtypes, get_emtype(elf));
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
	QUERY(PT_NUM),
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
	{ 0, 0 }
};
const char *get_elfstttype(int type)
{
	return find_pairtype(elf_stttypes, type);
}

/* translate elf STB_ defines */
static pairtype elf_stbtypes[] = {
	QUERY(STB_LOCAL),
	QUERY(STB_GLOBAL),
	QUERY(STB_WEAK),
	QUERY(STB_LOPROC),
	QUERY(STB_HIPROC),
	{ 0, 0 }
};
const char *get_elfstbtype(int type)
{
	return find_pairtype(elf_stbtypes, type);
}

/* translate elf SHN_ defines */
static pairtype elf_shntypes[] = {
	QUERY(SHN_UNDEF),
	QUERY(SHN_LORESERVE),
	QUERY(SHN_LOPROC),
	QUERY(SHN_HIPROC),
	QUERY(SHN_ABS),
	QUERY(SHN_COMMON),
	QUERY(SHN_HIRESERVE),
	{ 0, 0 }
};
const char *get_elfshntype(int type)
{
	if (type && type < SHN_LORESERVE)
		return "DEFINED";
	return find_pairtype(elf_shntypes, type);
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
elfobj *readelf_buffer(const char *filename, void *buffer, size_t buffer_len)
{
	elfobj *elf;

	/* make sure we have enough bytes to scan e_ident */
	if (buffer == NULL || buffer_len < EI_NIDENT)
		return NULL;

	elf = xzalloc(sizeof(*elf));

	elf->fd = -1;
	elf->len = buffer_len;
	elf->data = buffer;
	elf->data_end = buffer + buffer_len;

	/* make sure we have an elf */
	if (!IS_ELF_BUFFER(elf->data)) {
free_elf_and_return:
		free(elf);
		return NULL;
	}

	/* check class and stuff */
	if (!DO_WE_LIKE_ELF(elf->data)) {
		warn("we no likey %s: {%s,%s,%s,%s}",
		     filename,
		     get_elfeitype(EI_CLASS, elf->data[EI_CLASS]),
		     get_elfeitype(EI_DATA, elf->data[EI_DATA]),
		     get_elfeitype(EI_VERSION, elf->data[EI_VERSION]),
		     get_elfeitype(EI_OSABI, elf->data[EI_OSABI]));
		goto free_elf_and_return;
	}

	elf->filename = filename;
	elf->base_filename = strrchr(filename, '/');
	if (elf->base_filename == NULL)
		elf->base_filename = elf->filename;
	else
		elf->base_filename = elf->base_filename + 1;
	elf->elf_class = elf->data[EI_CLASS];
	do_reverse_endian = (ELF_DATA != elf->data[EI_DATA]);

	/* for arches that need alignment, we have to make sure the buffer
	 * is strictly aligned.  archive (.a) files only align to 2 bytes
	 * while the arch can easily require 8.  so dupe the buffer so
	 * that our local copy is always aligned (since we can't shift the
	 * file mapping back and forth a few bytes).
	 */
	if (!__PAX_UNALIGNED_OK && ((unsigned long)elf->vdata & 0x7)) {
		elf->_data = xmalloc(elf->len);
		memcpy(elf->_data, elf->data, elf->len);
		elf->data = elf->_data;
		elf->data_end = elf->_data + elf->len;
	}

#define READELF_HEADER(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
		char invalid; \
		Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
		Elf ## B ## _Off size; \
		/* verify program header */ \
		invalid = 0; \
		if (EGET(ehdr->e_phnum) <= 0) \
			invalid = 1; /* this is not abnormal so dont warn */ \
		else if (EGET(ehdr->e_phentsize) != sizeof(Elf ## B ## _Phdr)) \
			invalid = 3; \
		else { \
			elf->phdr = elf->vdata + EGET(ehdr->e_phoff); \
			size = EGET(ehdr->e_phnum) * EGET(ehdr->e_phentsize); \
			if (elf->phdr < elf->ehdr || /* check overflow */ \
			    elf->phdr + size < elf->phdr || /* before start of mem */ \
			    elf->phdr + size > elf->ehdr + elf->len) /* before end of mem */ \
				invalid = 2; \
		} \
		if (invalid > 1) \
			warn("%s: Invalid program header info (%i)", filename, invalid); \
		if (invalid) \
			elf->phdr = NULL; \
		/* verify section header */ \
		invalid = 0; \
		if (EGET(ehdr->e_shnum) <= 0) \
			invalid = 1; /* this is not abnormal so dont warn */ \
		else if (EGET(ehdr->e_shentsize) != sizeof(Elf ## B ## _Shdr)) \
			invalid = 3; \
		else { \
			elf->shdr = elf->vdata + EGET(ehdr->e_shoff); \
			size = EGET(ehdr->e_shnum) * EGET(ehdr->e_shentsize); \
			if (elf->shdr < elf->ehdr || /* check overflow */ \
			    elf->shdr + size < elf->shdr || /* before start of mem */ \
			    elf->shdr + size > elf->ehdr + elf->len) /* before end of mem */ \
				invalid = 2; \
		} \
		if (invalid > 1) \
			warn("%s: Invalid section header info (%i)", filename, invalid); \
		if (invalid) \
			elf->shdr = NULL; \
	}
	READELF_HEADER(32)
	READELF_HEADER(64)
	/* { char *p; strncpy(elf->basename, (p = strrchr(filename, '/')) == NULL ? "?" : p+1 , sizeof(elf->basename)); } */

	return elf;
}
elfobj *_readelf_fd(const char *filename, int fd, size_t len, int read_only)
{
	char *buffer;
	elfobj *ret;

	if (len == 0) {
		struct stat st;
		if (fstat(fd, &st) == -1)
			return NULL;
		len = st.st_size;
		if (len == 0)
			return NULL;
	}

	buffer = mmap(0, len, PROT_READ | (read_only ? 0 : PROT_WRITE), (read_only ? MAP_PRIVATE : MAP_SHARED), fd, 0);
	if (buffer == MAP_FAILED) {
		warn("mmap on '%s' of %li bytes failed :(", filename, (unsigned long)len);
		return NULL;
	}

	ret = readelf_buffer(filename, buffer, len);
	if (ret == NULL)
		munmap(buffer, len);
	else {
		ret->fd = fd;
		ret->is_mmap = 1;
	}

	return ret;
}
elfobj *_readelf(const char *filename, int read_only)
{
	elfobj *ret;
	struct stat st;
	int fd;

	if (stat(filename, &st) == -1)
		return NULL;

	if ((fd = open(filename, (read_only ? O_RDONLY : O_RDWR))) == -1)
		return NULL;

	/* make sure we have enough bytes to scan e_ident */
	if (st.st_size <= EI_NIDENT) {
close_fd_and_return:
		close(fd);
		return NULL;
	}

	ret = readelf_fd(filename, fd, st.st_size);
	if (ret == NULL)
		goto close_fd_and_return;

	return ret;
}

/* undo the readelf() stuff */
void unreadelf(elfobj *elf)
{
	if (elf->is_mmap) munmap(elf->vdata, elf->len);
	if (elf->fd != -1) close(elf->fd);
	if (!__PAX_UNALIGNED_OK) free(elf->_data);
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

/* PT_PAX_FLAGS are tristate ...
 * the display logic is:
 * lower case: explicitly disabled
 * upper case: explicitly enabled
 *      -    : default */
char *pax_short_pf_flags(unsigned long flags)
{
	static char buffer[7];

#define PAX_STATE(pf_on, pf_off, disp_on, disp_off) \
	(flags & pf_on ? disp_on : (flags & pf_off ? disp_off : '-'))

	buffer[0] = PAX_STATE(PF_PAGEEXEC, PF_NOPAGEEXEC, 'P', 'p');
	buffer[1] = PAX_STATE(PF_SEGMEXEC, PF_NOSEGMEXEC, 'S', 's');
	buffer[2] = PAX_STATE(PF_MPROTECT, PF_NOMPROTECT, 'M', 'm');
	buffer[3] = PAX_STATE(PF_RANDEXEC, PF_NORANDEXEC, 'X', 'x');
	buffer[4] = PAX_STATE(PF_EMUTRAMP, PF_NOEMUTRAMP, 'E', 'e');
	buffer[5] = PAX_STATE(PF_RANDMMAP, PF_NORANDMMAP, 'R', 'r');
	buffer[6] = 0;

	if (((flags & PF_PAGEEXEC) && (flags & PF_NOPAGEEXEC)) || \
	    ((flags & PF_SEGMEXEC) && (flags & PF_NOSEGMEXEC)) || \
	    ((flags & PF_RANDMMAP) && (flags & PF_NORANDMMAP)) || \
	    ((flags & PF_RANDEXEC) && (flags & PF_NORANDEXEC)) || \
	    ((flags & PF_EMUTRAMP) && (flags & PF_NOEMUTRAMP)) || \
	    ((flags & PF_RANDMMAP) && (flags & PF_NORANDMMAP)))
		warn("inconsistent state detected.  flags=%lX\n", flags);

	return buffer;
}

unsigned long pax_pf2hf_flags(unsigned long paxflags)
{
	unsigned long flags = 0;
	char *pf_flags = pax_short_pf_flags(paxflags);
	size_t x, len = strlen(pf_flags);
	for (x = 0; x < len; x++) {
		switch (pf_flags[x]) {
			case 'p':
				flags |= HF_PAX_PAGEEXEC;
				break;
			case 'P':
				flags = (flags & ~HF_PAX_PAGEEXEC) | HF_PAX_SEGMEXEC;
				break;
			case 'E':
				flags |= HF_PAX_EMUTRAMP;
				break;
			case 'e':
				flags = (flags & ~HF_PAX_EMUTRAMP);
				break;
			case 'm':
				flags |= HF_PAX_MPROTECT;
				break;
			case 'M':
				flags = (flags & ~HF_PAX_MPROTECT);
				break;
			case 'r':
				flags |= HF_PAX_RANDMMAP;
				break;
			case 'R':
				flags = (flags & ~HF_PAX_RANDMMAP);
				break;
			case 'X':
				flags |= HF_PAX_RANDEXEC;
				break;
			case 'x':
				flags = (flags & ~HF_PAX_RANDEXEC);
				break;
			case 's':
				flags |= HF_PAX_SEGMEXEC;
				break;
			case 'S':
				flags = (flags & ~HF_PAX_SEGMEXEC) | HF_PAX_PAGEEXEC;
				break;
			default:
				break;
		}
	}
	return flags;
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
		shdr_name = elf->data + offset; \
		if (!strcmp(shdr_name, name)) { \
			if (ret) warnf("Multiple '%s' sections !?", name); \
			ret = (void*)&(shdr[i]); \
		} \
	} }
	FINDSEC(32)
	FINDSEC(64)

	return ret;
}

int elf_max_pt_load(elfobj *elf)
{
#define MAX_PT_LOAD(B) \
	if (elf->elf_class == ELFCLASS ## B) { \
	Elf ## B ## _Ehdr *ehdr = EHDR ## B (elf->ehdr); \
	switch (EGET(ehdr->e_ident[EI_OSABI])) { \
	case ELFOSABI_NONE: \
	case ELFOSABI_NETBSD: \
	case ELFOSABI_FREEBSD: \
	case ELFOSABI_LINUX: \
	case ELFOSABI_ARM:     return 2; \
	case ELFOSABI_OPENBSD: return 7; \
	} }
	MAX_PT_LOAD(32)
	MAX_PT_LOAD(64)

	return 1;
}
#if 0
 # define ELFOSABI_NONE           0       /* UNIX System V ABI */
 # define ELFOSABI_SYSV           0       /* Alias.  */
 # define ELFOSABI_HPUX           1       /* HP-UX */
 # define ELFOSABI_NETBSD         2       /* NetBSD.  */
 # define ELFOSABI_LINUX          3       /* Linux.  */
 # define ELFOSABI_SOLARIS        6       /* Sun Solaris.  */
 # define ELFOSABI_AIX            7       /* IBM AIX.  */
 # define ELFOSABI_IRIX           8       /* SGI Irix.  */
 # define ELFOSABI_FREEBSD        9       /* FreeBSD.  */
 # define ELFOSABI_TRU64          10      /* Compaq TRU64 UNIX.  */
 # define ELFOSABI_MODESTO        11      /* Novell Modesto.  */
 # define ELFOSABI_OPENBSD        12      /* OpenBSD.  */
 # define ELFOSABI_ARM            97      /* ARM */
 # define ELFOSABI_STANDALONE     255     /* Standalone (embedded) application */

 /* These 3 ABIs should be in elf.h but are not.
  * http://www.caldera.com/developers/gabi/latest/ch4.eheader.html#generic_osabi_values
  */

 # define ELFOSABI_OPENVMS 13     /* OpenVMS */
 # define ELFOSABI_NSK     14     /* Hewlett-Packard Non-Stop Kernel */
 # define ELFOSABI_AROS    15     /* Amiga Research OS */

 #4 reserved for IA32 GNU Mach/Hurd
 #5 reserved for 86Open common IA32 ABI

#endif
