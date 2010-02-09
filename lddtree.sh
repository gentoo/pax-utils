#!/bin/bash

argv0=${0##*/}

usage() {
	cat <<-EOF
	Display ELF dependencies as a tree

	Usage: ${argv0} [options] <ELF file[s]>

	Options:
	  -a   Show all duplicated dependencies
	  -x   Run with debugging
	  -h   Show this help output
	EOF
	exit ${1:-0}
}

error() {
	echo "${argv0}: $*" 1>&2
	ret=1
	return 1
}

find_elf() {
	local elf=$1 needed_by=$2
	if [[ ${elf} == */* ]] && [[ -e ${elf} ]] ; then
		echo "${elf}"
		return 0
	else
		check_paths() {
			local elf=$1 ; shift
			local path
			for path in "$@" ; do
				if [[ -e ${path}/${elf} ]] ; then
					echo "${path}/${elf}"
					return 0
				fi
			done
			return 1
		}
		if [[ ${__last_needed_by} != ${needed_by} ]] ; then
			__last_needed_by=${needed_by}
			__last_needed_by_rpaths=$(scanelf -qF '#F%r' "${needed_by}" | sed 's|:| |g')
		fi
		check_paths "${elf}" ${__last_needed_by_rpaths} && return 0
		if [[ -z ${__ldso_paths} ]] ; then
			if [[ -r /etc/ld.so.conf ]] ; then
				__ldso_paths=$(sed -e 's:^[[:space:]]*#.*::' /etc/ld.so.conf)
			fi
			: ${__ldso_paths:= }
		fi
		if [[ ${__ldso_paths} != " " ]] ; then
			check_paths "${elf}" ${__ldso_paths} && return 0
		fi
		check_paths "${elf}" /lib* /usr/lib* /usr/local/lib* && return 0
	fi
	return 1
}

show_elf() {
	local elf=$1 indent=$2 parent_elfs=$3
	local rlib lib libs
	local interp resolved=$(find_elf "${elf}")
	elf=${elf##*/}

	printf "%${indent}s%s => " "" "${elf}"
	if [[ ,${parent_elfs}, == *,${elf},* ]] ; then
		printf "!!! circular loop !!!\n" ""
		return
	fi
	parent_elfs="${parent_elfs},${elf}"
	printf "${resolved:-not found}"
	if [[ ${indent} -eq 0 ]] ; then
		interp=$(scanelf -qF '#F%i' "${resolved}")
		printf " (interpreter => ${interp:-none})"
		interp=${interp##*/}
	fi
	printf "\n"

	[[ -z ${resolved} ]] && return

	libs=$(scanelf -qF '#F%n' "${resolved}")

	local my_allhits
	if ! ${SHOW_ALL} ; then
		my_allhits="${allhits}"
		allhits="${allhits},${interp},${libs}"
	fi

	for lib in ${libs//,/ } ; do
		lib=${lib##*/}
		[[ ,${my_allhits}, == *,${lib},* ]] && continue
		rlib=$(find_elf "${lib}" "${resolved}")
		show_elf "${rlib:-${lib}}" $((indent + 4)) "${parent_elfs}"
	done
}

# XXX: internal hack
if [[ $1 != "/../..source.lddtree" ]] ; then

SHOW_ALL=false
SET_X=false

while getopts hax OPT ; do
	case ${OPT} in
		a) SHOW_ALL=true;;
		x) SET_X=true;;
		h) usage;;
		?) usage 1;;
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
		allhits=""
		[[ ${elf} != */* ]] && elf="./${elf}"
		show_elf "${elf}" 0 ""
	fi
done
exit ${ret}

fi
