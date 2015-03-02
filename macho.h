/*
 * Copyright 2008-2012 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 */

#ifndef _MACHO_H
#define	_MACHO_H 1

#include <stdint.h>

/*
 * http://developer.apple.com/documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html
 */

#define CPU_ARCH_ABI64  0x01000000      /* 64 bit */
typedef int   cpu_type_t;
typedef int   cpu_subtype_t;

struct mach_header
{
	uint32_t magic;
	cpu_type_t cputype;
	cpu_subtype_t cpusubtype;
	uint32_t filetype;
	uint32_t ncmds;
	uint32_t sizeofcmds;
	uint32_t flags;
};

/* magic */
#define MH_MAGIC    0xfeedface  /* same endianness */
#define MH_CIGAM    0xcefaedfe  /* the other endianness */
/* cputype */
#define CPU_TYPE_POWERPC            ((cpu_type_t)18)
#define CPU_TYPE_I386               ((cpu_type_t)7)
#define CPU_TYPE_ARM                ((cpu_type_t)12)
/* cpusubtype */
#define CPU_SUBTYPE_POWERPC_ALL     ((cpu_subtype_t)0)
#define CPU_SUBTYPE_POWERPC_601     ((cpu_subtype_t)1)
#define CPU_SUBTYPE_POWERPC_602     ((cpu_subtype_t)2)
#define CPU_SUBTYPE_POWERPC_603     ((cpu_subtype_t)3)
#define CPU_SUBTYPE_POWERPC_603e    ((cpu_subtype_t)4)
#define CPU_SUBTYPE_POWERPC_603ev   ((cpu_subtype_t)5)
#define CPU_SUBTYPE_POWERPC_604     ((cpu_subtype_t)6)
#define CPU_SUBTYPE_POWERPC_604e    ((cpu_subtype_t)7)
#define CPU_SUBTYPE_POWERPC_620     ((cpu_subtype_t)8)
#define CPU_SUBTYPE_POWERPC_750     ((cpu_subtype_t)9)
#define CPU_SUBTYPE_POWERPC_7400    ((cpu_subtype_t)10)
#define CPU_SUBTYPE_POWERPC_7450    ((cpu_subtype_t)11)
#define CPU_SUBTYPE_POWERPC_970     ((cpu_subtype_t)100)
#define CPU_SUBTYPE_I386_ALL        ((cpu_subtype_t)3)
#define CPU_SUBTYPE_486             ((cpu_subtype_t)4)
#define CPU_SUBTYPE_586             ((cpu_subtype_t)5)
#define CPU_SUBTYPE_PENTIUM_3       ((cpu_subtype_t)8)
#define CPU_SUBTYPE_PENTIUM_M       ((cpu_subtype_t)9)
#define CPU_SUBTYPE_PENTIUM_4       ((cpu_subtype_t)10)
#define CPU_SUBTYPE_ITANIUM         ((cpu_subtype_t)11)
#define CPU_SUBTYPE_XEON            ((cpu_subtype_t)12)
/* filetype */
#define MH_OBJECT   0x1     /* intermediate object file (.o) */
#define MH_EXECUTE  0x2     /* standard executable program */
#define MH_BUNDLE   0x8     /* dlopen plugin (.bundle) */
#define MH_DYLIB    0x6     /* dynamic shared library (.dylib) */
#define MH_PRELOAD  0x5     /* executable not loaded by Mac OS X kernel (ROM) */
#define MH_CORE     0x4     /* program crash core file */
#define MH_DYLINKER 0x7     /* dynamic linker shared library (dyld) */
#define	MH_DYLIB_STUB 0x9   /* shared library stub for static only, no section*/
#define MH_DSYM     0xa     /* debug symbols file (in .dSYM dir) */
/* flags */
#define MH_NOUNDEFS 0x1     /* there are no undefined references */
#define MH_INCRLINK 0x2     /* the object file is the output of an
							   incremental link against a base file and
							   cannot be link edited again */
#define MH_DYLDLINK 0x4     /* the object file is input for the dynamic
							   linker and cannot be staticly link edited
							   again */
#define MH_TWOLEVEL 0x80    /* the image is using two-level namespace
							   bindings */
#define MH_BINDATLOAD 0x8   /* the dynamic linker should bind the
							   undefined references when the file is
							   loaded */
#define MH_PREBOUND 0x10    /* the file’s undefined references are
							   prebound */
#define MH_PREBINDABLE 0x800/* the file is not prebound but can have its
							   prebinding redone, used only when
							   MH_PREBOUND is not set */
#define MH_NOFIXPREBINDING 0x400 /* the dynamic linker doesn’t notify
									the prebinding agent about this
									executable */
#define MH_ALLMODSBOUND 0x1000 /* indicates that this binary binds to
								  all two-level namespace modules of its
								  dependent libraries, used only when
								  MH_PREBINDABLE and MH_TWOLEVEL are set
								  */
#define MH_CANONICAL 0x4000  /* the file has been canonicalized by
								unprebinding, clearing prebinding
								information from the file */
#define MH_SPLIT_SEGS   0x20 /* the file has its read-only and
								read-write segments split */
#define MH_FORCE_FLAT  0x100 /* the executable is forcing all images to
								use flat namespace bindings */
#define MH_SUBSECTIONS_VIA_SYMBOLS 0x2000/* the sections of the object
											file can be divided into
											individual blocks, these
											blocks are dead-stripped if
											they are not used by other
											code */
#define MH_NOMULTIDEFS 0x200 /* this umbrella guarantees there are no
								multiple defintions of symbols in its
								subimages, as a result the two-level
								namespace hints can always be used */

struct mach_header_64
{
	uint32_t magic;
	cpu_type_t cputype;
	cpu_subtype_t cpusubtype;
	uint32_t filetype;
	uint32_t ncmds;
	uint32_t sizeofcmds;
	uint32_t flags;
	uint32_t reserved;
};

/* magic */
#define MH_MAGIC_64 0xfeedfacf /* same endianness 64-bits */
#define MH_CIGAM_64 0xcffaedfe /* the other endianness 64-bits */
/* cputype */
#define CPU_TYPE_POWERPC64  (CPU_TYPE_POWERPC | CPU_ARCH_ABI64)
#define CPU_TYPE_X86_64     (CPU_TYPE_I386 | CPU_ARCH_ABI64)

struct load_command
{
	uint32_t cmd;
	uint32_t cmdsize;
};

/* features that are required to be supported are flagged, this is to
 * make the constants below a bit more readable (although we only use it
 * once for now) */
#define LC_REQ_DYLD 0x80000000

/* cmd */
#define LC_UUID     0x1b    /* Specifies the 128-bit UUID for an image
							   or its corresponding dSYM file. */
#define LC_RPATH   (0x1c | LC_REQ_DYLD) /* Defines a runpath addition,
                               used in @rpath directives in LC_LOAD_DYLIB. */
#define LC_SEGMENT  0x1     /* Defines a segment of this file to be
							   mapped into the address space of the
							   process that loads this file. It also
							   includes all the sections contained by
							   the segment. */
#define LC_SEGMENT_64  0x19 /* Defines a 64-bit segment of this file to
							   be mapped into the address space of the
							   process that loads this file. It also
							   includes all the sections contained by
							   the segment. */
#define LC_SYMTAB   0x2     /* Specifies the symbol table for this file.
							   This information is used by both static
							   and dynamic linkers when linking the
							   file, and also by debuggers to map
							   symbols to the original source code files
							   from which the symbols were generated. */
#define LC_DYSYMTAB 0xb     /* Specifies additional symbol table
							   information used by the dynamic linker. */
#define LC_THREAD   0x4
#define LC_UNIXTHREAD  0x5  /* For an executable file, the LC_UNIXTHREAD
							   command defines the initial thread state
							   of the main thread of the process.
							   LC_THREAD is similar to LC_UNIXTHREAD but
							   does not cause the kernel to allocate a
							   stack. */
#define LC_LOAD_DYLIB   0xc /* Defines the name of a dynamic shared
							   library that this file links against.
							   (needed) */
#define LC_ID_DYLIB 0xd     /* Specifies the install name of a dynamic
							   shared library. (soname) */
#define LC_PREBOUND_DYLIB 0x10 /* For a shared library that this
								  executable is linked prebound against,
								  specifies the modules in the shared
								  library that are used. */
#define LC_LOAD_DYLINKER 0xe/* Specifies the dynamic linker that the
							   kernel executes to load this file. (.interp) */
#define LC_ID_DYLINKER  0xf /* Identifies this file as a dynamic linker. */
#define LC_ROUTINES 0x11    /* Contains the address of the shared
							   library initialization routine (specified
							   by the linker’s -init option). */
#define LC_ROUTINES_64 0x1a /* Contains the address of the shared
							   library 64-bit initialization routine
							   (specified by the linker’s -init option). */
#define LC_TWOLEVEL_HINTS 0x16 /* Contains the two-level namespace
								  lookup hint table. */
#define LC_SUB_FRAMEWORK 0x12/* Identifies this file as the
								implementation of a subframework of an
								umbrella framework. The name of the
								umbrella framework is stored in the
								string parameter. */
#define LC_SUB_UMBRELLA 0x13/* Specifies a file that is a subumbrella of
							   this umbrella framework. */
#define LC_SUB_LIBRARY  0x15/* Identifies this file as the
							   implementation of a sublibrary of an
							   umbrella framework. The name of the
							   umbrella framework is stored in the
							   string parameter. Note that Apple has not
							   defined a supported location for
							   sublibraries. */
#define LC_SUB_CLIENT   0x14/* A subframework can explicitly allow
							   another framework or bundle to link
							   against it by including an LC_SUB_CLIENT
							   load command containing the name of the
							   framework or a client name for a bundle. */

union lc_str
{
	uint32_t offset;
	/* The ptr field is not used in Mach-O files.
	char *ptr; */
};
/* offset: A byte offset from the start of the load command that
 * contains this string to the start of the string data.
 */

/*
Defines the data used by the dynamic linker to match a shared library against the files that have linked to it.
*/
struct dylib
{
	union lc_str  name;
	uint32_t timestamp;
	uint32_t current_version;
	uint32_t compatibility_version;
};

/*
Defines the attributes of the LC_LOAD_DYLIB and LC_ID_DYLIB load commands.
*/
struct dylib_command
{
	uint32_t cmd;
	uint32_t cmdsize;
	struct dylib dylib;
};

/* cmd: set to either LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, or LC_ID_DYLIB. */
/* cmdsize: set to sizeof(dylib_command) plus the size of the data
 * pointed to by the name field of the dylib field. */

struct dylinker_command {
	uint32_t cmd;
	uint32_t cmdsize;
	union lc_str name;
};

struct rpath_command {
    uint32_t cmd;
    uint32_t cmdsize;
    union lc_str path;
};

struct fat_header
{
	uint32_t magic;
	uint32_t nfat_arch;
};

/* magic */
#define FAT_MAGIC   0xcafebabe  /* big endian, how it is stored */
#define FAT_CIGAM   0xbebafeca  /* for intel dudes */
/* nfat_arch: the number of far_arch structures following */

struct fat_arch
{
	cpu_type_t cputype;
	cpu_subtype_t cpusubtype;
	uint32_t offset;
	uint32_t size;
	uint32_t align;
};

#endif
