/*
 * Copyright 2003-2012 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2005-2012 Ned Ludd        - <solar@gentoo.org>
 * Copyright 2005-2012 Mike Frysinger  - <vapier@gentoo.org>
 */

#include "paxinc.h"

/*
 * Setup a bunch of helper functions to translate
 * binary defines into readable strings.
 */
#define QUERY(n) { #n, n }
typedef const struct {
	const char *str;
	/* We use unsigned int as we assume it's at least 32 bits.  This covers
	   all our uses so far as they have been limited to that size.  */
	unsigned int value;
} pairtype;
static inline const char *find_pairtype(pairtype *pt, unsigned int type)
{
	size_t i;
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
	{ 0, 0 }
};
static pairtype elf_ei_data[] = {
	QUERY(ELFDATANONE),
	QUERY(ELFDATA2LSB),
	QUERY(ELFDATA2MSB),
	{ 0, 0 }
};
static pairtype elf_ei_version[] = {
	QUERY(EV_NONE),
	QUERY(EV_CURRENT),
	{ 0, 0 }
};
static pairtype elf_ei_osabi[] = {
	QUERY(ELFOSABI_NONE),
	QUERY(ELFOSABI_SYSV),
	QUERY(ELFOSABI_HPUX),
	QUERY(ELFOSABI_NETBSD),
	QUERY(ELFOSABI_GNU),
	QUERY(ELFOSABI_LINUX),
	QUERY(ELFOSABI_SOLARIS),
	QUERY(ELFOSABI_AIX),
	QUERY(ELFOSABI_IRIX),
	QUERY(ELFOSABI_FREEBSD),
	QUERY(ELFOSABI_TRU64),
	QUERY(ELFOSABI_MODESTO),
	QUERY(ELFOSABI_OPENBSD),
	QUERY(ELFOSABI_ARM_AEABI),
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
	{ 0, 0 }
};

unsigned int get_etype(elfobj *elf)
{
	if (elf->elf_class == ELFCLASS32)
		return EGET(EHDR32(elf->ehdr)->e_type);
	else
		return EGET(EHDR64(elf->ehdr)->e_type);
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

/* translate elf EF_ defines -- tricky as it's based on EM_ */
static unsigned int get_eflags(elfobj *elf)
{
	if (elf->elf_class == ELFCLASS32)
		return EGET(EHDR32(elf->ehdr)->e_flags);
	else
		return EGET(EHDR64(elf->ehdr)->e_flags);
}

static int arm_eabi_poker(elfobj *elf)
{
	unsigned int emachine, eflags;

	if (ELFOSABI_NONE != elf->data[EI_OSABI])
		return -1;

	emachine = get_emtype(elf);
	eflags = get_eflags(elf);

	if (emachine == EM_ARM)
		return EF_ARM_EABI_VERSION(eflags) >> 24;
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
	if (strncmp(str, "ELFOSABI_", 9) == 0)
		str += 9;
	return str;
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

unsigned int etype_lookup(const char *str)
{
	if (*str == 'E') {
		size_t i;
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
	QUERY(EM_ALTERA_NIOS2),
	QUERY(EM_AARCH64),
	QUERY(EM_TILEPRO),
	QUERY(EM_MICROBLAZE),
	QUERY(EM_TILEGX),
	QUERY(EM_ALPHA),
	{ 0, 0 }
};

unsigned int get_emtype(elfobj *elf)
{
	if (elf->elf_class == ELFCLASS32)
		return EGET(EHDR32(elf->ehdr)->e_machine);
	else
		return EGET(EHDR64(elf->ehdr)->e_machine);
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
	QUERY(DT_GNU_PRELINKED),
	QUERY(DT_GNU_CONFLICTSZ),
	QUERY(DT_GNU_LIBLISTSZ),
	QUERY(DT_CHECKSUM),
	QUERY(DT_PLTPADSZ),
	QUERY(DT_MOVEENT),
	QUERY(DT_MOVESZ),
	QUERY(DT_GNU_HASH),
	QUERY(DT_TLSDESC_PLT),
	QUERY(DT_TLSDESC_GOT),
	QUERY(DT_GNU_CONFLICT),
	QUERY(DT_GNU_LIBLIST),
	QUERY(DT_CONFIG),
	QUERY(DT_DEPAUDIT),
	QUERY(DT_AUDIT),
	QUERY(DT_PLTPAD),
	QUERY(DT_MOVETAB),
	QUERY(DT_SYMINFO),
	QUERY(DT_VERSYM),
	QUERY(DT_RELACOUNT),
	QUERY(DT_RELCOUNT),
	QUERY(DT_FLAGS_1),
	QUERY(DT_VERDEF),
	QUERY(DT_VERDEFNUM),
	QUERY(DT_VERNEED),
	QUERY(DT_VERNEEDNUM),
	QUERY(DT_AUXILIARY),
	QUERY(DT_FILTER),
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
	QUERY(SHT_GNU_ATTRIBUTES),
	QUERY(SHT_GNU_HASH),
	QUERY(SHT_GNU_LIBLIST),
	QUERY(SHT_CHECKSUM),
	QUERY(SHT_SUNW_move),
	QUERY(SHT_SUNW_COMDAT),
	QUERY(SHT_SUNW_syminfo),
	QUERY(SHT_GNU_verdef),
	QUERY(SHT_GNU_verneed),
	QUERY(SHT_GNU_versym),
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
	QUERY(STT_COMMON),
	QUERY(STT_TLS),
	QUERY(STT_GNU_IFUNC),
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
	QUERY(STB_GNU_UNIQUE),
	{ 0, 0 }
};
const char *get_elfstbtype(int type)
{
	return find_pairtype(elf_stbtypes, type);
}

/* translate elf STV_ defines */
static pairtype elf_stvtypes[] = {
	QUERY(STV_DEFAULT),
	QUERY(STV_INTERNAL),
	QUERY(STV_HIDDEN),
	QUERY(STV_PROTECTED),
	{ 0, 0 }
};
const char *get_elfstvtype(int type)
{
	return find_pairtype(elf_stvtypes, type);
}

/* translate elf SHN_ defines */
static pairtype elf_shntypes[] = {
	QUERY(SHN_UNDEF),
	QUERY(SHN_BEFORE),
	QUERY(SHN_AFTER),
	QUERY(SHN_ABS),
	QUERY(SHN_COMMON),
	QUERY(SHN_XINDEX),
	{ 0, 0 }
};
const char *get_elfshntype(int type)
{
	if (type && type < SHN_LORESERVE)
		return "DEFINED";
	return find_pairtype(elf_shntypes, type);
}

/* translate elf NT_ defines */
static pairtype elf_nttypes_GNU[] = {
	QUERY(NT_GNU_ABI_TAG),
	QUERY(NT_GNU_HWCAP),
	QUERY(NT_GNU_BUILD_ID),
	QUERY(NT_GNU_GOLD_VERSION),
	{ 0, 0 }
};
static pairtype elf_nttypes_core[] = {
	QUERY(NT_PRSTATUS),
	QUERY(NT_FPREGSET),
	QUERY(NT_PRPSINFO),
	QUERY(NT_PRXREG),
	QUERY(NT_TASKSTRUCT),
	QUERY(NT_PLATFORM),
	QUERY(NT_AUXV),
	QUERY(NT_GWINDOWS),
	QUERY(NT_ASRS),
	QUERY(NT_PSTATUS),
	QUERY(NT_PSINFO),
	QUERY(NT_PRCRED),
	QUERY(NT_UTSNAME),
	QUERY(NT_LWPSTATUS),
	QUERY(NT_LWPSINFO),
	QUERY(NT_PRFPXREG),
	QUERY(NT_SIGINFO),
	QUERY(NT_FILE),
	QUERY(NT_PRXFPREG),
	QUERY(NT_PPC_VMX),
	QUERY(NT_PPC_SPE),
	QUERY(NT_PPC_VSX),
	QUERY(NT_386_TLS),
	QUERY(NT_386_IOPERM),
	QUERY(NT_X86_XSTATE),
	QUERY(NT_S390_HIGH_GPRS),
	QUERY(NT_S390_TIMER),
	QUERY(NT_S390_TODCMP),
	QUERY(NT_S390_TODPREG),
	QUERY(NT_S390_CTRS),
	QUERY(NT_S390_PREFIX),
	QUERY(NT_S390_LAST_BREAK),
	QUERY(NT_S390_SYSTEM_CALL),
	QUERY(NT_S390_TDB),
	QUERY(NT_ARM_VFP),
	QUERY(NT_ARM_TLS),
	QUERY(NT_ARM_HW_BREAK),
	QUERY(NT_ARM_HW_WATCH),
	{ 0, 0 }
};
static pairtype elf_nttypes_fallback[] = {
	QUERY(NT_VERSION),
	{ 0, 0 }
};
const char *get_elfnttype(uint16_t e_type, const char *name, int type)
{
	if (name) {
		if (!strcmp(name, "GNU"))
			return find_pairtype(elf_nttypes_GNU, type);

		/* Unknown extension, so just fallback to common ones. */
	}

	if (e_type == ET_CORE)
		return find_pairtype(elf_nttypes_core, type);
	else
		return find_pairtype(elf_nttypes_fallback, type);
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

	if ((fd = open(filename, (read_only ? O_RDONLY : O_RDWR))) == -1)
		return NULL;

	if (fstat(fd, &st) == -1) {
 close_fd_and_return:
		close(fd);
		return NULL;
	}

	/* make sure we have enough bytes to scan e_ident */
	if (st.st_size <= EI_NIDENT)
		goto close_fd_and_return;

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
		warn("inconsistent state detected.  flags=%lX", flags);

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
