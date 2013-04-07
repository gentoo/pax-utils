#!/bin/bash
# Copyright 2007-2013 Gentoo Foundation
# Copyright 2007-2013 Mike Frysinger <vapier@gentoo.org>
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-projects/pax-utils/lddtree.sh,v 1.22 2013/04/07 19:20:09 vapier Exp $

argv0=${0##*/}

: ${ROOT:=/}
[[ ${ROOT} != */ ]] && ROOT="${ROOT}/"
[[ ${ROOT} != /* ]] && ROOT="${PWD}${ROOT}"

usage() {
	cat <<-EOF
	Display ELF dependencies as a tree

	Usage: ${argv0} [options] <ELF file[s]>

	Options:
	  -a              Show all duplicated dependencies
	  -x              Run with debugging
	  -R <root>       Use this ROOT filesystem tree
	  --no-auto-root  Do not automatically prefix input ELFs with ROOT
	  -l              Display output in a flat format
	  -h              Show this help output
	  -V              Show version information
	EOF
	exit ${1:-0}
}

version() {
	local id='$Id: lddtree.sh,v 1.22 2013/04/07 19:20:09 vapier Exp $'
	id=${id##*,v }
	exec echo "lddtree-${id% * Exp*}"
}

error() {
	echo "${argv0}: $*" 1>&2
	ret=1
	return 1
}

elf_specs() {
	# With glibc, the NONE, SYSV, GNU, and LINUX OSABI's are compatible.
	# LINUX and GNU are the same thing, as are NONE and SYSV, so normalize
	# GNU & LINUX to NONE. #442024 #464380
	scanelf -BF '#F%a %M %D %I' "$1" | \
		sed -r 's: (LINUX|GNU)$: NONE:'
}

lib_paths_fallback="${ROOT}lib* ${ROOT}usr/lib* ${ROOT}usr/local/lib*"
c_ldso_paths_loaded='false'
find_elf() {
	_find_elf=''

	local elf=$1 needed_by=$2
	if [[ ${elf} == */* ]] && [[ -e ${elf} ]] ; then
		_find_elf=${elf}
		return 0
	else
		check_paths() {
			local elf=$1 ; shift
			local path pe
			for path ; do
				pe="${path%/}/${elf#/}"
				if [[ -e ${pe} ]] ; then
					if [[ $(elf_specs "${pe}") == "${elf_specs}" ]] ; then
						_find_elf=${pe}
						return 0
					fi
				fi
			done
			return 1
		}

		if [[ ${c_last_needed_by} != ${needed_by} ]] ; then
			c_last_needed_by=${needed_by}
			c_last_needed_by_rpaths=$(scanelf -qF '#F%r' "${needed_by}" | \
				sed -e 's|:| |g' -e "s:[$]ORIGIN:${needed_by%/*}:")
		fi
		check_paths "${elf}" ${c_last_needed_by_rpaths} && return 0

		if [[ -n ${LD_LIBRARY_PATH} ]] ; then
			# Need to handle empty paths as $PWD,
			# and handle spaces in between the colons
			local p path=${LD_LIBRARY_PATH}
			while : ; do
				p=${path%%:*}
				check_paths "${elf}" "${p:-${PWD}}" && return 0
				[[ ${path} == *:* ]] || break
				path=${path#*:}
			done
		fi

		if ! ${c_ldso_paths_loaded} ; then
			c_ldso_paths_loaded='true'
			c_ldso_paths=()
			if [[ -r ${ROOT}etc/ld.so.conf ]] ; then
				read_ldso_conf() {
					local line p
					for p ; do
						# if the glob didnt match anything #360041,
						# or the files arent readable, skip it
						[[ -r ${p} ]] || continue
						while read line ; do
							case ${line} in
								"#"*) ;;
								"include "*) read_ldso_conf ${line#* } ;;
								*) c_ldso_paths+=( "${ROOT}${line#/}" ) ;;
							esac
						done <"${p}"
					done
				}
				# the 'include' command is relative
				pushd "${ROOT}"etc >/dev/null
				read_ldso_conf "${ROOT}"etc/ld.so.conf
				popd >/dev/null
			fi
		fi
		if [[ ${#c_ldso_paths[@]} -gt 0 ]] ; then
			check_paths "${elf}" "${c_ldso_paths[@]}" && return 0
		fi

		check_paths "${elf}" ${lib_paths_ldso:-${lib_paths_fallback}} && return 0
	fi
	return 1
}

show_elf() {
	local elf=$1 indent=$2 parent_elfs=$3
	local rlib lib libs
	local interp resolved
	find_elf "${elf}"
	resolved=${_find_elf}
	elf=${elf##*/}

	${LIST} || printf "%${indent}s%s => " "" "${elf}"
	if [[ ,${parent_elfs}, == *,${elf},* ]] ; then
		${LIST} || printf "!!! circular loop !!!\n" ""
		return
	fi
	parent_elfs="${parent_elfs},${elf}"
	if ${LIST} ; then
		echo "${resolved:-$1}"
	else
		printf "${resolved:-not found}"
	fi
	if [[ ${indent} -eq 0 ]] ; then
		elf_specs=$(elf_specs "${resolved}")
		interp=$(scanelf -qF '#F%i' "${resolved}")
		[[ -n ${interp} ]] && interp="${ROOT}${interp#/}"

		if ${LIST} ; then
			[[ -n ${interp} ]] && echo "${interp}"
		else
			printf " (interpreter => ${interp:-none})"
		fi
		if [[ -r ${interp} ]] ; then
			# Extract the default lib paths out of the ldso.
			lib_paths_ldso=$(
				strings "${interp}" | \
				sed -nr -e "/^\/.*lib/{s|^/?|${ROOT}|;s|/$||;s|/?:/?|\n${ROOT}|g;p}"
			)
		fi
		interp=${interp##*/}
	fi
	${LIST} || printf "\n"

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
		find_elf "${lib}" "${resolved}"
		rlib=${_find_elf}
		show_elf "${rlib:-${lib}}" $((indent + 4)) "${parent_elfs}"
	done
}

# XXX: internal hack
if [[ $1 != "/../..source.lddtree" ]] ; then

SHOW_ALL=false
SET_X=false
LIST=false
AUTO_ROOT=true

while getopts haxVR:l-:  OPT ; do
	case ${OPT} in
	a) SHOW_ALL=true;;
	x) SET_X=true;;
	h) usage;;
	V) version;;
	R) ROOT="${OPTARG%/}/";;
	l) LIST=true;;
	-) # Long opts ftw.
		case ${OPTARG} in
		no-auto-root) AUTO_ROOT=false;;
		*) usage 1;;
		esac
		;;
	?) usage 1;;
	esac
done
shift $((OPTIND - 1))
[[ -z $1 ]] && usage 1

${SET_X} && set -x

ret=0
for elf ; do
	unset lib_paths_ldso
	unset c_last_needed_by
	if ${AUTO_ROOT} && [[ ${elf} == /* ]] ; then
		elf="${ROOT}${elf#/}"
	fi
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
