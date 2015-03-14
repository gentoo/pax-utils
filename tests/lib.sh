# no out of tree building so shut it
srcdir=`cd "${0%/*}" && pwd`
top_srcdir=`cd "${srcdir}/../.." && pwd`
builddir=${srcdir}
top_builddir=${top_srcdir}

[ -e /etc/init.d/functions.sh ] && source /etc/init.d/functions.sh

PATH=${top_builddir}:${PATH}
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
		if [[ -s $1 ]] ; then
			tret=1
			err=$(<"$1")
		fi
		;;
	2)
		if ! err=$(diff -u "$1" "$2") ; then
			tret=1
		fi
	esac
	if [[ ${tret} -eq 0 ]] ; then
		pass "$1"
	else
		fail "$1"
		echo "${err}"
	fi
	rm -f "$1"
}
