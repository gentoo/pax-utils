#!/bin/bash -e

. "${0%/*}"/lib.sh

# We have to do this by hand rather than use the coverity addon because of
# matrix explosion: https://github.com/travis-ci/travis-ci/issues/1975
# We also do it by hand because when we're throttled, the addon will exit
# the build immediately and skip the main script!
coverity_scan() {
	local reason
	[[ ${TRAVIS_JOB_NUMBER} != *.1 ]] && reason="not first build job"
	[[ -n ${TRAVIS_TAG} ]] && reason="git tag"
	[[ ${TRAVIS_PULL_REQUEST} == "true" ]] && reason="pull request"
	if [[ -n ${reason} ]] ; then
		echo "Skipping coverity scan due to: ${reason}"
		return
	fi

	export COVERITY_SCAN_PROJECT_NAME="${TRAVIS_REPO_SLUG}"
	export COVERITY_SCAN_NOTIFICATION_EMAIL="vapier@gentoo.org"
	export COVERITY_SCAN_BUILD_COMMAND="make -j${ncpus}"
	export COVERITY_SCAN_BUILD_COMMAND_PREPEND="git clean -q -x -d -f; git checkout -f"
	export COVERITY_SCAN_BRANCH_PATTERN="master"

	curl -s "https://scan.coverity.com/scripts/travisci_build_coverity_scan.sh" | bash || :
}

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

	# Do scans last as they like to dirty the tree and some tests
	# expect a clean tree (like code style checks).
	v --fold="coverity_scan" coverity_scan
}
main "$@"
