#!/bin/bash

if [[ $# -ne 1 ]] ; then
	echo "Usage: $0 <ver>" 1>&2
	exit 1
fi

ver=$1
bn=pax-utils-${ver}
[[ -d ${bn} ]] && rm -r ${bn}
mkdir ${bn} || exit 1
cp -r Makefile README *.[ch] man ${bn}/ || exit 1
rm -rf ${bn}/man/CVS
tar -jcf ${bn}.tar.bz2 ${bn} || exit 1
rm -r ${bn} || exit 1
du -b ${bn}.tar.bz2
