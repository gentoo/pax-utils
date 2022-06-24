#!/usr/bin/env bash
set -ufe
>&2 echo THIS IS A DEVELOPER SCRIPT
>&2 echo YOU DO NOT NEED TO RUN IT UNLESS YOU EDITED seccomp-bpf.c

: "${CC:=gcc}"
: "${CCFLAGS:=$(pkg-config --cflags --libs libseccomp)}"

generator="$(mktemp)"
trap 'rm "${generator}"' EXIT

"${CC}" -o "${generator}" -D_GNU_SOURCE ${CCFLAGS} seccomp-bpf.c && \
	"${generator}" > seccomp-bpf.h
