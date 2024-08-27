#!/bin/bash
# Copyright 2007-2024 Gentoo Foundation
# Copyright 2007-2024 Mike Frysinger <vapier@gentoo.org>
# Distributed under the terms of the GNU General Public License v2

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

	When called as *ldd (e.g. via a symlink), the output resembles the regular
	ldd command by default.
	EOF
	exit ${1:-0}
}

version() {
	exec echo "lddtree by Mike Frysinger <vapier@gentoo.org>"
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
		sed -E 's: (LINUX|GNU)$: NONE:'
}

lib_paths_fallback="${ROOT}lib* ${ROOT}usr/lib* ${ROOT}usr/local/lib* ${ROOT}usr/X11R6/lib*"
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
				sed -E -e 's|:| |g' -e "s:[$](ORIGIN|\{ORIGIN\}):${needed_by%/*}:")
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
						# If the glob didn't match anything #360041,
						# or the files aren't readable, skip it.
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

		check_paths "${elf}" ${lib_paths_fallback} && return 0
	fi
	return 1
}

show_elf() {
	local elf=$1 indent=$2 parent_elfs=$3 inputs=$4
	local rlib lib libs
	local resolved
	find_elf "${elf}"
	resolved=${_find_elf}
	elf=${elf##*/}

	local loop=false
	[[ ,${parent_elfs}, == *,${elf},* ]] && loop=true

	if ${LDD_MODE} ; then
		if [[ ${indent} -gt 0 ]] ; then
			printf "\t%s => " "${elf}"
		elif [[ ${inputs} -gt 1 ]] ; then
			printf "%s:\n" "${resolved}"
		fi
	elif ${LIST} ; then
		:
	else
		printf "%${indent}s%s => " "" "${elf}"
		${loop} && printf "!!! circular loop !!!\n"
	fi

	${loop} && return
	parent_elfs="${parent_elfs},${elf}"

	if ${LDD_MODE} ; then
		if [[ ${indent} -gt 0 ]] ; then
			printf "%s" "${resolved:-not found} (0xdeadbeef)"
		fi
	elif ${LIST} ; then
		printf "%s" "${resolved:-$1}"
	else
		printf "%s" "${resolved:-not found}"
	fi

	if [[ ${indent} -eq 0 ]] ; then
		local elf_specs full_interp root_interp base_interp

		elf_specs=$(elf_specs "${resolved}")
		full_interp=$(scanelf -qF '#F%i' "${resolved}")
		base_interp=${full_interp##*/}
		[[ -n ${full_interp} ]] && root_interp="${ROOT}${full_interp#/}"

		# If we are in the default mode, then we want to show the "duplicate"
		# interp lines -- first the header (interp=>xxx), and then the DT_NEEDED
		# line to show that the ELF is directly linked against the interp.
		# Otherwise, we only want to show the interp once.
		if ${LDD_MODE} ; then
			[[ -n ${root_interp} ]] && printf "\t%s" "${root_interp} (0xdeadbeef)"
			allhits+=",${base_interp}"
		elif ${LIST} ; then
			[[ -n ${root_interp} ]] && printf "\n%s" "${root_interp}"
			allhits+=",${base_interp}"
		else
			printf " (interpreter => %s)" "${root_interp:-none}"
		fi
	fi

	printf "\n"

	[[ -z ${resolved} ]] && return

	libs=$(scanelf -qF '#F%n' "${resolved}")

	local my_allhits
	if ! ${SHOW_ALL} ; then
		my_allhits="${allhits}"
		allhits+=",${libs}"
	fi

	for lib in ${libs//,/ } ; do
		lib=${lib##*/}
		# No need for leading comma w/my_allhits as we guarantee it always
		# starts with one due to the way we append the value above.
		[[ ${my_allhits}, == *,${lib},* ]] && continue
		# If the interp is being linked against directly, reuse the existing
		# full path rather than perform a search for it.  When systems symlink
		# the interp to a diff location, we might locate a different path, and
		# displaying both doesn't make sense as it doesn't match the runtime --
		# the ldso won't load another copy of ldso into memory from the search
		# path, it'll reuse the existing copy that was loaded from the full
		# hardcoded path.
		if [[ ${lib} == "${base_interp}" ]] ; then
			rlib=${full_interp}
		else
			find_elf "${lib}" "${resolved}"
			rlib=${_find_elf}
		fi
		show_elf "${rlib:-${lib}}" $((indent + 4)) "${parent_elfs}" "${inputs}"
	done
}

# XXX: internal hack
if [[ $1 != "/../..source.lddtree" ]] ; then

SHOW_ALL=false
SET_X=false
LIST=false
AUTO_ROOT=true
LDD_MODE=false

[[ ${argv0} = *ldd ]] && LDD_MODE=true

while getopts haxVR:l-:  OPT ; do
	case ${OPT} in
	a) SHOW_ALL=true;;
	x) SET_X=true;;
	h) usage;;
	V) version;;
	R) ROOT="${OPTARG%/}/";;
	l) LIST=true LDD_MODE=false;;
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
		show_elf "${elf}" 0 "" $#
	fi
done
exit ${ret}

fi
