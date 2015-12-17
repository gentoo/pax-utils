#!/bin/bash -e

. "${0%/*}"/travis/lib.sh

m4dir="autotools/m4"

v rm -rf autotools
if [[ $1 != "--from=make" ]] ; then
	v ${MAKE:-make} autotools-update
fi

# reload the gnulib code if possible
PATH=/usr/local/src/gnu/gnulib:${PATH}
mods="
	alloca
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
	strcasestr-simple
	strncat
	symlinkat
	sys_stat
	unlinkat
	utimensat
	vasprintf-posix
"
v --fold="gnulib-tool" gnulib-tool \
	--source-base=autotools/gnulib --m4-base=autotools/m4 \
	--import \
	${mods}

# not everyone has sys-devel/autoconf-archive installed
v tar xf travis/autotools.tar.xz
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
v autoreconf -i -f

if [[ -x ./test.sh ]] ; then
	exec ./test.sh "$@"
fi
