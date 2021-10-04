#!/bin/bash -e

# NB: This script is normally run in a GNU environment (e.g. Linux), but we also run it on other
# systems (e.g. macOS) as part of our automated CI.  So a little care must be taken.

cd "${0%/*}" || exit 1

m4dir="autotools/m4"

: ${MAKE:=make}

FROM_TOOL=
while [[ $# -gt 0 ]] ;do
	case $1 in
	--from=*) FROM_TOOL=${1#*=};;
	-x|--debug) set -x;;
	*) break;;
	esac
	shift
done

if [[ $# -ne 0 ]] ; then
	echo "Usage: $0" >&2
	exit 1
fi

rm -rf autotools
if [[ ${FROM_TOOL} != "make" ]] ; then
	${MAKE} autotools-update
fi

# reload the gnulib code if possible
PATH="${PWD}/gnulib:${PWD}/../gnulib:/usr/local/src/gnu/gnulib:${PATH}"
mods="
	alloca
	euidaccess
	faccessat
	fdopendir
	fstatat
	futimens
	getline
	getopt-posix
	mkdirat
	openat
	progname
	readlinkat
	renameat
	stat-time
	stpcpy
	strcasestr-simple
	strncat
	symlinkat
	sys_stat
	unlinkat
	utimensat
	vasprintf-posix
"
gnulib-tool \
	--source-base=autotools/gnulib --m4-base=autotools/m4 \
	--import \
	${mods}

# not everyone has sys-devel/autoconf-archive installed
tar xf travis/autotools.tar.xz
has() { [[ " ${*:2} " == *" $1 "* ]] ; }
import_ax() {
	local macro content m4 lm4s=()
	content=$(sed -e '/^[[:space:]]*#/d' -e 's:\<dnl\>.*::' "$@")
	for macro in $(echo "${content}" | grep -o '\<AX[A-Z_]*\>' | sort -u) ; do
		for m4 in $(grep -rl "\[${macro}\]" /usr/share/aclocal/) ; do
			has ${m4} "${m4s[@]}" || lm4s+=( ${m4} )
		done
	done
	if [[ ${#lm4s[@]} -gt 0 ]] ; then
		cp -v `printf '%s\n' ${lm4s[@]} | sort -u` autotools/m4/
		m4s+=( "${lm4s[@]}" )
	fi
}
m4s=()
import_ax configure.ac
curr=1
new=0
while [[ ${curr} -ne ${new} ]] ; do
	curr=${#m4s[@]}
	import_ax autotools/m4/ax_*.m4
	new=${#m4s[@]}
done

export AUTOMAKE="automake --foreign"
autoreconf -i -f

if [[ -x ./test.sh ]] ; then
	exec ./test.sh "$@"
fi
