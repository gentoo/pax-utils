#!/bin/bash

if [[ $# -ne 1 ]] ; then
	echo "Usage: $0 <ver>" 1>&2
	exit 1
fi

ver="$1"
[[ "$ver" == "snap" ]] && ver=$(date -u +%Y%m%d)
bn="$(basename $(pwd))-${ver}"
[[ -d "${bn}" ]] && rm -r "${bn}"
mkdir "${bn}" || exit 1
cp -r Makefile README TODO BUGS *.[ch] man "${bn}/" || exit 1
rm -rf "${bn}"/man/CVS "${bn}"/*macho*
tar -jcf "${bn}".tar.bz2 ${bn} || exit 1
rm -r "${bn}" || exit 1
du -b "${bn}".tar.bz2
tar jvtf "${bn}".tar.bz2
