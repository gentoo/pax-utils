#!/usr/bin/env bash
set -ufe
>&2 echo THIS IS A DEVELOPER SCRIPT
>&2 echo YOU DO NOT NEED TO RUN IT UNLESS YOU EDITED seccomp-bpf.c

: "${CC:=gcc}"
: "${PKG_CONFIG:=pkg-config}"
: "${SECCOMP_CFLAGS:=$(${PKG_CONFIG} --cflags libseccomp)}"
: "${SECCOMP_LIBS:=$(${PKG_CONFIG} --libs libseccomp)}"

generator="$(mktemp)"
trap 'rm "${generator}"' EXIT

${CC} -o "${generator}" -D_GNU_SOURCE ${SECCOMP_CFLAGS} ${CFLAGS-} ${LDFLAGS-} seccomp-bpf.c ${SECCOMP_LIBS} && \
	"${generator}" > seccomp-bpf.h
