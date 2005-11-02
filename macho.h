/*
 * Copyright (c) 2005 Apple Computer, Inc. 
 *
 * This file describes the format of mach object files.
 */

#ifndef _MACHO_LOADER_H_
#define _MACHO_LOADER_H_

#include <stdint.h>

typedef uint32_t cpu_type_t;
typedef uint32_t cpu_subtype_t;

/*
 * Specifies the general attributes of a file.
 * Appears at the beginning of object files.
 */
struct mach_header {
	uint32_t      magic;
	cpu_type_t    cputype;
	cpu_subtype_t cpusubtype;
	uint32_t      filetype;
	uint32_t      ncmds;
	uint32_t      sizeofcmds;
	uint32_t      flags;
} __attribute__((packed));

/* Constants for magic member */
#define MH_MAGIC     0xfeedface
#define MH_CIGAM     0xbebafeca
#define MH_MAGIC_32  MH_MAGIC
#define MH_CIGAM_32  MH_CIGAM


/*
 * Defines the general attributes of a file targeted for a 64-bit architecture
 */
struct mach_header_64 {
	uint32_t      magic;
	cpu_type_t    cputype;
	cpu_subtype_t cpusubtype;
	uint32_t      filetype;
	uint32_t      ncmds;
	uint32_t      sizeofcmds;
	uint32_t      flags;
	uint32_t      reserved;
};

/* Constants for magic member */
#define MH_MAGIC_64  0xfeedfacf
#define MH_CIGAM_64  0xcffaedfe



/* Constants for filetype member */
#define MH_OBJECT    0x1   /* intermediate object files */
#define MH_EXECUTE   0x2   /* standard executable programs */
#define MH_CORE      0x4   /* address space of a crashed program */
#define MH_PRELOAD   0x5   /* special-purpose programs (i.e. firmware) */
#define MH_DYLIB     0x6   /* dynamic shared libraries */
#define MH_DYLINKER  0x7   /* dynamic linker shared library */
#define MH_BUNDLE    0x8   /* runtime loadable code */

#endif /* _MACHO_LOADER_H_ */
