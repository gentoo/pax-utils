# no out of tree building so shut it
srcdir=`cd "${0%/*}" && pwd`
top_srcdir=`cd "${srcdir}/../.." && pwd`
builddir=${srcdir}
top_builddir=${top_srcdir}

PATH=${top_builddir}:${PATH}
unset ROOT # who knows!

[ -e /etc/init.d/functions.sh ] && source /etc/init.d/functions.sh

ret=0

testit() {
	local tret=0 err
	case $# in
		1)
			if [ -s $1 ] ; then
				tret=1
				err=$(<$1)
			fi
			;;
		2)
			if ! err=`diff -u $1 $2` ; then
				tret=1
			fi
	esac
	if [ ${tret} -eq 0 ] ; then
		echo ${GOOD}PASS${NORMAL}: $1
	else
		ret=1
		echo ${BAD}FAIL${NORMAL}: $1
		echo "${err}"
	fi
	rm -f $1
}
