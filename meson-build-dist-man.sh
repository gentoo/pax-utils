#!/bin/sh
# This script should be invoked by meson itself (via 'meson dist')
# See https://github.com/mesonbuild/meson/issues/2166 and more specifically,
# https://github.com/mesonbuild/meson/issues/2166#issuecomment-629696911.
set -eu

cd "${MESON_DIST_ROOT}"
mkdir build
meson setup build -Dbuild_manpages=enabled
meson compile -C build
cp build/man/* man/
rm -rf build
