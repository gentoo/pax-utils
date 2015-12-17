if [[ -z ${abs_top_builddir} ]] ; then
	srcdir=$(cd "${0%/*}" && pwd)
	top_srcdir=$(cd "${srcdir}/../.." && pwd)
	builddir=${srcdir}
	top_builddir=${top_srcdir}
else
	mkdir -p "${builddir}"
	top_srcdir=${abs_top_srcdir}
	top_builddir=${abs_top_builddir}
fi

[ -e /etc/init.d/functions.sh ] && source /etc/init.d/functions.sh

PATH="${top_srcdir}:${top_builddir}:${PATH}"
unset ROOT # who knows!

ret=0

pass() {
	echo "${GOOD}PASS${NORMAL}: $*"
}

fail() {
	ret=1
	echo "${BAD}FAIL${NORMAL}: $*" >&2
}

testit() {
	local tret=0 err
	case $# in
	1)
		if [[ -s ${builddir}/$1 ]] ; then
			tret=1
			err=$(<"${builddir}/$1")
		fi
		;;
	2)
		if ! err=$(diff -u "${builddir}/$1" "${srcdir}/$2") ; then
			tret=1
		fi
	esac
	if [[ ${tret} -eq 0 ]] ; then
		pass "$1"
	else
		fail "$1"
		echo "${err}"
	fi
	rm -f "${builddir}/$1"
}
