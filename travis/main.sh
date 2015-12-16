#!/bin/bash -e

. "${0%/*}"/lib.sh

main() {
	if [[ ${TRAVIS_OS_NAME} == "osx" ]] ; then
		# Note: Linux deps are maintained in .travis.yml.
		v --fold="brew_update" brew update
		v --fold="brew_install" brew install xmlto xz
	fi

	# See if we have to bootstrap gnulib.  This is the case on OS X, and on
	# Linux until they whitelist the package:
	# https://github.com/travis-ci/apt-package-whitelist/issues/727
	if ! gnulib-tool --version >&/dev/null ; then
		if [[ ! -d ../gnulib ]] ; then
			v --fold="git_clone_gnulib" \
				git clone --depth=1 https://github.com/coreutils/gnulib.git ../gnulib
		else
			pushd ../gnulib
			v --fold="git_pull_gnulib" git pull
			popd
		fi
		export PATH="${PATH}:${PWD}/../gnulib"
	fi

	if [[ ${TRAVIS_OS_NAME} == "linux" ]] ; then
		# Standard optimized build.
		m
		m check

		# Debug build w/ASAN and such enabled.
		m debug
		m check
	fi

	# Autotools based build.
	v ./autogen.sh
	if [[ ${TRAVIS_OS_NAME} == "linux" ]] ; then
		v --fold="configure" ./configure
		m V=1 distcheck
	else
		# ELF checks don't work on OS X -- no ELFs!
		v ./configure
		m V=1
	fi
}
main "$@"
