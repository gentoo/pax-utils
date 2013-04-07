#!/bin/bash

argv0=${0##*/}

usage() {
	cat <<-EOF
	Display libraries that satisfy undefined symbols, as a tree

	Usage: ${argv0} [options] <ELF file[s]>

	Options:
	  -x   Run with debugging
	  -h   Show this help output
	EOF
	exit ${1:-0}
}

sym_list() {
	# with large strings, bash is much slower than sed
	local type=$1; shift
	echo "%${type}%$@" | sed "s:,:,%${type}%:g"
}
find_elf() {
	echo "$2" | awk -F/ -v lib="$1" '$NF == lib {print}'
}
show_elf() {
	local elf=$1
	local rlib lib libs
	local resolved=$(realpath "${elf}")
	local resolved_libs=$(lddtree -l "${resolved}")

	printf "%s\n" "${resolved}"

	libs=$(scanelf -qF '#F%n' "${resolved}")

	local u uu d dd
	u=$(scanelf -q -F'%s#F' -s'%u%' "${elf}")
	for lib in ${libs//,/ } ; do
		lib=${lib##*/}
		rlib=$(find_elf "${lib}" "${resolved_libs}")

		d=$(scanelf -qF'%s#F' -s`sym_list d "${u}"` "${rlib}")
		if [[ -n ${d} ]] ; then
			dd=${dd:+${dd},}${d}
			printf "%4s%s => %s\n" "" "${lib}" "${d}"
		else
			printf "%4s%s => %s\n" "" "${lib}" "!?! useless link !?!"
		fi
	done

	uu=
	for u in `echo "${u}" | sed 's:,: :g'` ; do
		[[ ,${dd}, != *,${u},* ]] && uu=${uu:+${uu},}${u}
	done
	if [[ -n ${uu} ]] ; then
		u=${uu}
		dd=$(scanelf -qF'%s#F' -s`sym_list w "${u}"` "${resolved}")
		if [[ -n ${dd} ]] ; then
			printf "%4s%s => %s\n" "" "WEAK" "${dd}"
			uu=
			for u in `echo "${u}" | sed 's:,: :g'` ; do
				[[ ,${dd}, != *,${u},* ]] && uu=${uu:+${uu},}${u}
			done
		fi
		if [[ -n ${uu} ]] ; then
			printf "%4s%s => %s\n" "" "UNRESOLVED" "${uu}"
		fi
	fi
}

SET_X=false

while getopts hx OPT ; do
	case ${OPT} in
		x) SET_X=true;;
		h) usage;;
		*) usage 1;;
	esac
done
shift $((OPTIND - 1))
[[ -z $1 ]] && usage 1

${SET_X} && set -x

ret=0
for elf in "$@" ; do
	if [[ ! -e ${elf} ]] ; then
		error "${elf}: file does not exist"
	elif [[ ! -r ${elf} ]] ; then
		error "${elf}: file is not readable"
	elif [[ -d ${elf} ]] ; then
		error "${elf}: is a directory"
	else
		[[ ${elf} != */* ]] && elf="./${elf}"
		show_elf "${elf}" 0 ""
	fi
done
exit ${ret}
