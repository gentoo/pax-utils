#!/bin/bash

set -e

if ! . /etc/init.d/functions.sh 2>/dev/null ; then
	einfo() { printf ' * %b\n' "$*"; }
	eerror() { einfo "$@" 1>&2; }
fi
die() { eerror "$@"; exit 1; }

v() { printf '\t%s\n' "$*"; "$@"; }

: ${MAKE:=make}

CHECK=false
if [[ $1 == "--check" ]] ; then
	CHECK=true
	shift
fi

if [[ $# -ne 1 ]] ; then
	die "Usage: $0 <ver>"
fi

case $1 in
snap) ver=$(date -u +%Y%m%d) ;;
git) ver="HEAD" ;;
*)
	ver="v${1#v}"
	if ! git describe --tags "${ver}" >&/dev/null ; then
		die "Please create the tag first: git tag ${ver}"
	fi
	;;
esac
p="pax-utils-${ver#v}"

rm -rf "${p}"
mkdir "${p}"

einfo "Checking out clean git sources ..."
git archive "${ver}" | tar xf - -C "${p}"

pushd "${p}" >/dev/null

einfo "Building docs ..."
echo "<releaseinfo>${ver#v}</releaseinfo>" > man/fragment/version
make -C man

einfo "Building autotools ..."
sed -i "/^AC_INIT/s:git:${ver}:" configure.ac
sed -i "1iPV := ${ver}" Makefile
SKIP_AUTOTOOLS_UPDATE=true LC_ALL=C ${MAKE} -s autotools >/dev/null
rm -rf autom4te.cache

popd >/dev/null

einfo "Generating tarball ..."
tar cf - "${p}" | xz > "${p}".tar.xz
rm -r "${p}"

if ${CHECK} ; then

einfo "Checking tarball (simple) ..."
tar xf "${p}".tar.*
pushd "${p}" >/dev/null
v ${MAKE} -s
v ${MAKE} -s check
popd >/dev/null
rm -rf "${p}"

einfo "Checking tarball (autotools) ..."
tar xf "${p}".tar.*
pushd "${p}" >/dev/null
v ./configure -q
v ${MAKE} -s
v ${MAKE} -s check
popd >/dev/null
rm -rf "${p}"

fi

echo
einfo "All ready for distribution!"
du -b "${p}".tar.*

exit 0
