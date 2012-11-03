#!/bin/bash
# $Header: /var/cvsroot/gentoo-projects/pax-utils/lddtree.sh,v 1.11 2012/11/03 00:06:10 vapier Exp $

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

elf_specs() {
	scanelf -BF '#F%a %M %D %I' "$1"
}

lib_paths_fallback="/lib* /usr/lib* /usr/local/lib*"
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
			c_last_needed_by_rpaths=$(scanelf -qF '#F%r' "${needed_by}" | sed 's|:| |g')
		fi
		check_paths "${elf}" ${c_last_needed_by_rpaths} && return 0

		if [[ -n ${LD_LIBRARY_PATH} ]] ; then
			# Need to handle empty paths as $PWD,
			# and handle spaces in between the colons
			local p path=${LD_LIBRARY_PATH}
			while : ; do
				p=${path%%:*}
				check_paths "${elf}" "${path:-${PWD}}" && return 0
				[[ ${path} == *:* ]] || break
				path=${path#*:}
			done
		fi

		if ! ${c_ldso_paths_loaded} ; then
			c_ldso_paths_loaded='true'
			c_ldso_paths=()
			if [[ -r /etc/ld.so.conf ]] ; then
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
								*) c_ldso_paths+=( "${line}" ) ;;
							esac
						done <"${p}"
					done
				}
				# the 'include' command is relative
				pushd /etc >/dev/null
				read_ldso_conf /etc/ld.so.conf
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

	printf "%${indent}s%s => " "" "${elf}"
	if [[ ,${parent_elfs}, == *,${elf},* ]] ; then
		printf "!!! circular loop !!!\n" ""
		return
	fi
	parent_elfs="${parent_elfs},${elf}"
	printf "${resolved:-not found}"
	if [[ ${indent} -eq 0 ]] ; then
		elf_specs=$(elf_specs "${resolved}")
		interp=$(scanelf -qF '#F%i' "${resolved}")

		printf " (interpreter => ${interp:-none})"
		if [[ -r ${interp} ]] ; then
			# Extract the default lib paths out of the ldso.
			lib_paths_ldso=$(strings "${interp}" | grep '^/.*lib')
			lib_paths_ldso=${lib_paths_ldso//:/ }
		fi
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
		find_elf "${lib}" "${resolved}"
		rlib=${_find_elf}
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
for elf ; do
	unset lib_paths_ldso
	unset c_last_needed_by
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
