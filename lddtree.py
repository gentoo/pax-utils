#!/usr/bin/env python
# PYTHON_ARGCOMPLETE_OK
# Copyright 2012-2024 Gentoo Foundation
# Copyright 2012-2024 Mike Frysinger <vapier@gentoo.org>
# Copyright 2012-2024 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license (BSD-3)

"""Read the ELF dependency tree and show it

This does not work like `ldd` in that we do not execute/load code (only read
files on disk), and we show the ELFs as a tree rather than a flat list.

Paths may be globs that lddtree will take care of expanding.
Useful when you want to glob a path under the ROOT path.

When using the --root option, all paths are implicitly prefixed by that.
  e.g. lddtree -R /my/magic/root /bin/bash
This will load up the ELF found at /my/magic/root/bin/bash and then resolve
all libraries via that path.  If you wish to actually read /bin/bash (and
so use the ROOT path as an alternative library tree), you can specify the
--no-auto-root option.

When pairing --root with --copy-to-tree, the ROOT path will be stripped.
  e.g. lddtree -R /my/magic/root --copy-to-tree /foo /bin/bash
You will see /foo/bin/bash and /foo/lib/libc.so.6 and not paths like
/foo/my/magic/root/bin/bash.  If you want that, you'll have to manually
add the ROOT path to the output path.

The --bindir and --libdir flags are used to normalize the output subdirs
when used with --copy-to-tree.
  e.g. lddtree --copy-to-tree /foo /bin/bash /usr/sbin/lspci /usr/bin/lsof
This will mirror the input paths in the output.  So you will end up with
/foo/bin/bash and /foo/usr/sbin/lspci and /foo/usr/bin/lsof.  Similarly,
the libraries needed will be scattered among /foo/lib/ and /foo/usr/lib/
and perhaps other paths (like /foo/lib64/ and /usr/lib/gcc/...).  You can
collapse all that down into nice directory structure.
  e.g. lddtree --copy-to-tree /foo /bin/bash /usr/sbin/lspci /usr/bin/lsof \\
               --bindir /bin --libdir /lib
This will place bash, lspci, and lsof into /foo/bin/.  All the libraries
they need will be placed into /foo/lib/ only.
"""

import argparse
import errno
import functools
import glob
import mmap
import os
import re
import shutil
import sys
from typing import Any, cast, Dict, Iterable, List, Optional, Tuple, Union


assert sys.version_info >= (3, 8), f"Python 3.8+ required, but found {sys.version}"

# Disable import errors for all 3rd party modules.
# pylint: disable=import-error
try:
    import argcomplete  # type: ignore
except ImportError:
    argcomplete = cast(Any, None)

from elftools.common import exceptions  # type: ignore
from elftools.elf.elffile import ELFFile  # type: ignore


# pylint: enable=import-error


def warn(msg: Any, prefix: Optional[str] = "warning") -> None:
    """Write |msg| to stderr with a |prefix| before it"""
    print(f"{os.path.basename(sys.argv[0])}: {prefix}: {msg}", file=sys.stderr)


def err(msg: Any, status: Optional[int] = 1) -> None:
    """Write |msg| to stderr and exit with |status|"""
    warn(msg, prefix="error")
    sys.exit(status)


def dbg(debug: bool, *args, **kwargs) -> None:
    """Pass |args| and |kwargs| to print() when |debug| is True"""
    if debug:
        print(*args, **kwargs)


def bstr(buf: Union[bytes, str]) -> str:
    """Decode the byte string into a string"""
    if isinstance(buf, str):
        return buf
    return buf.decode("utf-8")


def normpath(path: str) -> str:
    """Normalize a path

    Python's os.path.normpath() doesn't handle some cases:
      // -> //
      //..// -> //
      //..//..// -> ///
    """
    return os.path.normpath(path).replace("//", "/")


@functools.lru_cache(maxsize=None)
def readlink(path: str, root: str, prefixed: Optional[bool] = False) -> str:
    """Like os.readlink(), but relative to a |root|

    This does not currently handle the pathological case:
      /lib/foo.so -> ../../../../../../../foo.so
    This relies on the .. entries in / to point to itself.

    Args:
      path: The symlink to read
      root: The path to use for resolving absolute symlinks
      prefixed: When False, the |path| must not have |root| prefixed to it, nor
          will the return value have |root| prefixed.  When True, |path|
          must have |root| prefixed, and the return value will have |root|
          added.

    Returns:
      A fully resolved symlink path
    """
    root = root.rstrip("/")
    if prefixed:
        path = path[len(root) :]

    while os.path.islink(root + path):
        path = os.path.join(os.path.dirname(path), os.readlink(root + path))

    return normpath((root + path) if prefixed else path)


def dedupe(items: List[str]) -> List[str]:
    """Remove all duplicates from |items| (keeping order)"""
    seen: Dict[str, str] = {}
    return [seen.setdefault(x, x) for x in items if x not in seen]


@functools.lru_cache(maxsize=None)
def interp_supports_argv0(interp: str) -> bool:
    """See whether |interp| supports the --argv0 option.

    Starting with glibc-2.33, the ldso supports --argv0 to override argv[0].
    """
    with open(interp, "rb") as fp:
        with mmap.mmap(fp.fileno(), 0, prot=mmap.PROT_READ) as mm:
            return mm.find(b"--argv0") >= 0


def GenerateLdsoWrapper(
    root: str,
    path: str,
    interp: str,
    libpaths: Iterable[str] = (),
    preload: Optional[str] = None,
) -> None:
    """Generate a shell script wrapper which uses local ldso to run the ELF

    Since we cannot rely on the host glibc (or other libraries), we need to
    execute the local packaged ldso directly and tell it where to find our
    copies of libraries.

    Args:
      root: The root tree to generate scripts inside of
      path: The full path (inside |root|) to the program to wrap
      interp: The ldso interpreter that we need to execute
      libpaths: Extra lib paths to search for libraries
    """
    basedir = os.path.dirname(path)
    interp_dir, interp_name = os.path.split(interp)
    # Add ldso interpreter dir to end of libpaths as a fallback library path.
    libpaths = dedupe(list(libpaths) + [interp_dir])
    if preload:
        # If preload is an absolute path, calculate it from basedir.
        preload_prefix = f'${{basedir}}/{os.path.relpath("/", basedir)}'
        preload = ":".join(
            f"{preload_prefix}{x}" if os.path.isabs(x) else x
            for x in re.split(r"[ :]", preload)
        )

    replacements = {
        "interp": os.path.join(os.path.relpath(interp_dir, basedir), interp_name),
        "interp_rel": os.path.relpath(path, interp_dir),
        "libpaths": ":".join(
            "${basedir}/" + os.path.relpath(p, basedir) for p in libpaths
        ),
        "argv0_arg": '--argv0 "$0"' if interp_supports_argv0(root + interp) else "",
        "preload_arg": f'--preload "{preload}"' if preload else "",
    }

    # Keep path relativeness of argv0 (in ${base}.elf). This allows tools to
    # remove absolute paths from build outputs and enables directory independent
    # cache sharing in distributed build systems.
    #
    # NB: LD_ARGV0_REL below is unrelated & non-standard.  It's to let tools see
    # the original path if they need it and when they know they'll be wrapped up
    # by this script.
    wrapper = """#!/bin/sh
if base=$(readlink "$0" 2>/dev/null); then
  # If $0 is an abspath symlink, fully resolve the target.
  case ${base} in
  /*) base=$(readlink -f "$0" 2>/dev/null);;
  *)  base=$(dirname "$0")/${base};;
  esac
else
  case $0 in
  /*) base=$0;;
  *)  base=${PWD:-`pwd`}/$0;;
  esac
fi
basedir=${base%%/*}
LD_ARGV0_REL="%(interp_rel)s" \\
exec \\
  "${basedir}/%(interp)s" \\
  %(argv0_arg)s \\
  %(preload_arg)s \\
  --library-path "%(libpaths)s" \\
  --inhibit-cache \\
  --inhibit-rpath '' \\
  "${base}.elf" \\
  "$@"
"""
    wrappath = root + path
    os.rename(wrappath, wrappath + ".elf")
    with open(wrappath, "w", encoding="utf-8") as f:
        f.write(wrapper % replacements)
    os.chmod(wrappath, 0o0755)


@functools.lru_cache(maxsize=None)
def ParseLdPaths(
    str_ldpaths: str,
    root: str = "",
    cwd: Optional[str] = None,
    path: str = "",
) -> List[str]:
    """Parse the colon-delimited list of paths and apply ldso rules to each

    Note the special handling as dictated by the ldso:
     - Empty paths are equivalent to $PWD
     - $ORIGIN is expanded to the path of the given file
     - (TODO) $LIB and friends

    Args:
      str_ldpaths: A colon-delimited string of paths
      root: The path to prepend to all paths found
      cwd: The path to resolve relative paths against (defaults to getcwd()).
      path: The object actively being parsed (used for $ORIGIN)

    Returns:
      list of processed paths
    """
    if cwd is None:
        cwd = os.getcwd()

    ldpaths = []
    for ldpath in str_ldpaths.split(":"):
        # Expand placeholders first.
        if "$ORIGIN" in ldpath:
            ldpath = ldpath.replace("$ORIGIN", os.path.dirname(path))
        elif "${ORIGIN}" in ldpath:
            ldpath = ldpath.replace("${ORIGIN}", os.path.dirname(path))

        # Expand relative paths if needed.  These don't make sense in general,
        # but that doesn't stop people from using them.  As such, root prefix
        # doesn't make sense with it either.
        if not ldpath.startswith("/"):
            # NB: The ldso treats "" paths as cwd too.
            ldpath = os.path.join(cwd, ldpath)
        else:
            ldpath = root + ldpath

        ldpaths.append(normpath(ldpath))

    return dedupe(ldpaths)


def ParseLdSoConf(
    ldso_conf: str,
    root: str = "/",
    debug: bool = False,
    _first: bool = True,
) -> List[str]:
    """Load all the paths from a given ldso config file

    This should handle comments, whitespace, and "include" statements.

    Args:
      ldso_conf: The file to scan
      root: The path to prepend to all paths found
      debug: Enable debug output
      _first: Recursive use only; is this the first ELF ?

    Returns:
      list of paths found
    """
    paths = []

    dbg_pfx = "" if _first else "  "
    try:
        dbg(debug, f"{dbg_pfx}ParseLdSoConf({ldso_conf})")
        with open(ldso_conf, encoding="utf-8") as f:
            for line in f.readlines():
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                if line.startswith("include "):
                    line = line[8:]
                    if line[0] == "/":
                        line = root + line.lstrip("/")
                    else:
                        line = os.path.dirname(ldso_conf) + "/" + line
                    dbg(debug, dbg_pfx, "glob:", line)
                    # ldconfig in glibc uses glob() which returns entries sorted according
                    # to LC_COLLATE.  Further, ldconfig does not reset that but respects
                    # the active env settings (which might be a mistake).  Python does not
                    # sort its results by default though, so do it ourselves.
                    for path in sorted(glob.glob(line)):
                        paths += ParseLdSoConf(
                            path, root=root, debug=debug, _first=False
                        )
                else:
                    paths += [normpath(root + line)]
    except IOError as e:
        if e.errno != errno.ENOENT:
            warn(e)

    if _first:
        # XXX: Load paths from ldso itself.
        # Remove duplicate entries to speed things up.
        paths = dedupe(paths)

    return paths


def LoadLdpaths(
    root: str = "/",
    cwd: Optional[str] = None,
    prefix: str = "",
    debug: bool = False,
) -> Dict[str, List[str]]:
    """Load linker paths from common locations

    This parses the ld.so.conf and LD_LIBRARY_PATH env var.

    Args:
      root: The root tree to prepend to paths
      cwd: The path to resolve relative paths against
      prefix: The path under |root| to search
      debug: Enable debug output

    Returns:
      dict containing library paths to search
    """
    ldpaths: Dict[str, List[str]] = {
        "conf": [],
        "env": [],
        "interp": [],
    }

    # Load up $LD_LIBRARY_PATH.
    ldpaths["env"] = []
    env_ldpath = os.environ.get("LD_LIBRARY_PATH")
    if not env_ldpath is None:
        if root != "/":
            warn("ignoring LD_LIBRARY_PATH due to ROOT usage")
        else:
            # XXX: If this contains $ORIGIN, we probably have to parse this
            # on a per-ELF basis so it can get turned into the right thing.
            ldpaths["env"] = ParseLdPaths(env_ldpath, cwd=cwd, path="")

    # Load up /etc/ld.so.conf.
    ldpaths["conf"] = ParseLdSoConf(
        root + prefix + "/etc/ld.so.conf", root=root, debug=debug
    )

    return ldpaths


def CompatibleELFs(elf1: ELFFile, elf2: ELFFile) -> bool:
    """See if two ELFs are compatible

    This compares the aspects of the ELF to see if they're compatible:
    bit size, endianness, machine type, and operating system.

    Args:
      elf1: an ELFFile object
      elf2: an ELFFile object

    Returns:
      True if compatible, False otherwise
    """
    osabis = frozenset([e.header["e_ident"]["EI_OSABI"] for e in (elf1, elf2)])
    compat_sets = (
        frozenset(f"ELFOSABI_{x}" for x in ("NONE", "SYSV", "GNU", "LINUX")),
    )
    return (
        (len(osabis) == 1 or any(osabis.issubset(x) for x in compat_sets))
        and elf1.elfclass == elf2.elfclass
        and elf1.little_endian == elf2.little_endian
        and elf1.header["e_machine"] == elf2.header["e_machine"]
    )


def FindLib(
    elf: ELFFile,
    lib: str,
    ldpaths: List[str],
    root: str = "/",
    debug: bool = False,
) -> Tuple[Optional[str], Optional[str]]:
    """Try to locate a |lib| that is compatible to |elf| in the given |ldpaths|

    Args:
      elf: The elf which the library should be compatible with (ELF wise)
      lib: The library (basename) to search for
      ldpaths: A list of paths to search
      root: The root path to resolve symlinks
      debug: Enable debug output

    Returns:
      Tuple of the full path to the desired library and the real path to it
    """
    dbg(debug, f"  FindLib({lib})")

    for ldpath in ldpaths:
        path = os.path.join(ldpath, lib)
        target = readlink(path, root, prefixed=True)
        if path != target:
            dbg(debug, "    checking:", path, "->", target)
        else:
            dbg(debug, "    checking:", path)

        if os.path.exists(target):
            with open(target, "rb") as f:
                try:
                    libelf = ELFFile(f)
                    if CompatibleELFs(elf, libelf):
                        return (target, path)
                except exceptions.ELFError as e:
                    warn(f"{target}: {e}")

    return (None, None)


# We abuse the _all_libs state.  We probably shouldn't, but we do currently.
# pylint: disable=dangerous-default-value
def ParseELF(
    path: str,
    root: str = "/",
    cwd: Optional[str] = None,
    prefix: str = "",
    ldpaths={"conf": [], "env": [], "interp": []},
    display: Optional[str] = None,
    debug: bool = False,
    _first: bool = True,
    _all_libs={},
) -> Dict[str, Any]:
    """Parse the ELF dependency tree of the specified file

    Args:
      path: The ELF to scan
      root: The root tree to prepend to paths; this applies to interp and rpaths
          only as |path| and |ldpaths| are expected to be prefixed already
      cwd: The path to resolve relative paths against.
      prefix: The path under |root| to search
      ldpaths: dict containing library paths to search; should have the keys:
          conf, env, interp
      display: The path to show rather than |path|
      debug: Enable debug output
      _first: Recursive use only; is this the first ELF ?
      _all_libs: Recursive use only; dict of all libs we've seen

    Returns:
      a dict containing information about all the ELFs; e.g.
      {
        'interp': '/lib64/ld-linux.so.2',
        'needed': ['libc.so.6', 'libcurl.so.4',],
        'libs': {
          'libc.so.6': {
            'path': '/lib64/libc.so.6',
            'needed': [],
          },
          'libcurl.so.4': {
            'path': '/usr/lib64/libcurl.so.4',
            'needed': ['libc.so.6', 'librt.so.1',],
          },
        },
      }
    """
    if _first:
        _all_libs = {}
        ldpaths = ldpaths.copy()
    ret: Dict[str, Any] = {
        "interp": None,
        "path": path if display is None else display,
        "realpath": path,
        "needed": [],
        "rpath": [],
        "runpath": [],
        "libs": _all_libs,
    }

    dbg(debug, f"ParseELF({path})")

    with open(path, "rb") as f:
        try:
            elf = ELFFile(f)
        except exceptions.ELFParseError:
            warn("ELFParser failed to parse", path)
            raise

        # If this is the first ELF, extract the interpreter.
        if _first:
            for segment in elf.iter_segments():
                if segment.header.p_type != "PT_INTERP":
                    continue

                interp = bstr(segment.get_interp_name())
                dbg(debug, "  interp           =", interp)
                ret["interp"] = normpath(root + interp)
                real_interp = readlink(ret["interp"], root, prefixed=True)
                ret["libs"][os.path.basename(interp)] = {
                    "path": ret["interp"],
                    "realpath": real_interp,
                    "needed": [],
                }
                # XXX: Could read it and scan for /lib paths.
                # If the interp is a symlink, lets follow it on the assumption that it
                # is in this path purely for ABI reasons, and the distro is using a
                # different (probably more correct) path.  This can come up in some
                # multilib situations like s390x where /lib64/ contains all the native
                # libraries, but /lib/ld64.so.1 is the interp hardcoded in gcc, so the
                # ld64.so.1 is really a symlink to ../lib64/ld64.so.1.  In the multiarch
                # setup, it'll be /lib/ld64.so.1 -> /lib/s390x-linux-gnu/ld64.so.1.
                # That is why we use |real_interp| here instead of |interp|.
                ldpaths["interp"] = [
                    os.path.dirname(real_interp),
                    normpath(
                        root
                        + prefix
                        + "/usr/"
                        + os.path.dirname(real_interp)[len(root) + len(prefix) :]
                    ),
                ]
                dbg(debug, "  ldpaths[interp]  =", ldpaths["interp"])
                break

        # Parse the ELF's dynamic tags.
        libs = []
        rpaths = []
        runpaths = []
        for segment in elf.iter_segments():
            if segment.header.p_type != "PT_DYNAMIC":
                continue

            for t in segment.iter_tags():
                if t.entry.d_tag == "DT_RPATH":
                    rpaths = ParseLdPaths(bstr(t.rpath), root=root, cwd=cwd, path=path)
                elif t.entry.d_tag == "DT_RUNPATH":
                    runpaths = ParseLdPaths(
                        bstr(t.runpath), root=root, cwd=cwd, path=path
                    )
                elif t.entry.d_tag == "DT_NEEDED":
                    libs.append(bstr(t.needed))
            if runpaths:
                # If both RPATH and RUNPATH are set, only the latter is used.
                rpaths = []

            # XXX: We assume there is only one PT_DYNAMIC.  This is
            # probably fine since the runtime ldso does the same.
            break
        if _first:
            # Propagate the rpaths used by the main ELF since those will be
            # used at runtime to locate things.
            ldpaths["rpath"] = rpaths
            ldpaths["runpath"] = runpaths
            dbg(debug, "  ldpaths[rpath]   =", rpaths)
            dbg(debug, "  ldpaths[runpath] =", runpaths)
        ret["rpath"] = rpaths
        ret["runpath"] = runpaths
        ret["needed"] = libs

        # Search for the libs this ELF uses.
        all_ldpaths = None
        for lib in libs:
            if lib in _all_libs:
                continue
            if all_ldpaths is None:
                all_ldpaths = (
                    rpaths
                    + ldpaths["rpath"]
                    + ldpaths["env"]
                    + runpaths
                    + ldpaths["runpath"]
                    + ldpaths["conf"]
                    + ldpaths["interp"]
                )
            realpath, fullpath = FindLib(elf, lib, all_ldpaths, root, debug=debug)
            _all_libs[lib] = {
                "realpath": realpath,
                "path": fullpath,
                "needed": [],
            }
            if realpath is not None:
                try:
                    lret = ParseELF(
                        realpath,
                        root,
                        cwd,
                        prefix,
                        ldpaths,
                        display=fullpath,
                        debug=debug,
                        _first=False,
                        _all_libs=_all_libs,
                    )
                except exceptions.ELFError as e:
                    warn(f"{realpath}: {e}")
                _all_libs[lib]["needed"] = lret["needed"]

        del elf

    return ret


# pylint: enable=dangerous-default-value


class _NormalizePathAction(argparse.Action):
    """Argparse action to normalize paths."""

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, normpath(values))


def _ActionShow(options: argparse.Namespace, elf: dict):
    """Show the dependency tree for this ELF"""

    def _show(lib, depth):
        chain_libs.append(lib)
        fullpath = elf["libs"][lib]["path"]
        if options.list:
            print(fullpath or lib)
        else:
            indent = "    " * depth
            print(f"{indent}{lib}", "=>", fullpath)

        new_libs = []
        for nlib in elf["libs"][lib]["needed"]:
            if nlib in chain_libs:
                if not options.list:
                    print(f"{indent}{nlib} => !!! circular loop !!!")
                continue
            if options.all or not nlib in shown_libs:
                shown_libs.add(nlib)
                new_libs.append(nlib)

        for nlib in new_libs:
            _show(nlib, depth + 1)
        chain_libs.pop()

    shown_libs = set(elf["needed"])
    new_libs = elf["needed"][:]
    chain_libs: List[str] = []
    interp = elf["interp"]
    if interp:
        lib = os.path.basename(interp)
        shown_libs.add(lib)
        # If we are in non-list mode, then we want to show the "duplicate" interp
        # lines -- first the header (interp=>xxx), and then the DT_NEEDED line to
        # show that the ELF is directly linked against the interp.
        # If we're in list mode though, we only want to show the interp once.
        # Unless of course we have the --all flag active, then we show everything.
        if not options.all and options.list and lib in new_libs:
            new_libs.remove(lib)
    if options.list:
        print(elf["path"])
        if not interp is None:
            print(interp)
    else:
        print(elf["path"], f"(interpreter => {interp})")
    for lib in new_libs:
        _show(lib, 1)


def _ActionCopy(options: argparse.Namespace, elf: dict):
    """Copy the ELF and its dependencies to a destination tree"""

    def _StripRoot(path: str) -> str:
        return path[len(options.root) - 1 :]

    def _copy(
        realsrc,
        src,
        striproot=True,
        wrapit=False,
        libpaths=(),
        outdir=None,
        preload=None,
    ):
        if realsrc is None:
            return

        if wrapit:
            # Static ELFs don't need to be wrapped.
            if not elf["interp"]:
                wrapit = False

        striproot = _StripRoot if striproot else lambda x: x

        if outdir:
            subdst = os.path.join(outdir, os.path.basename(src))
        else:
            subdst = striproot(src)
        dst = options.dest + subdst

        try:
            # See if they're the same file.
            nstat = os.stat(dst + (".elf" if wrapit else ""))
            ostat = os.stat(realsrc)
            for field in ("mode", "mtime", "size"):
                if getattr(ostat, "st_" + field) != getattr(nstat, "st_" + field):
                    break
            else:
                return
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise

        if options.verbose:
            print(src, "->", dst)

        os.makedirs(os.path.dirname(dst), exist_ok=True)
        try:
            shutil.copy2(realsrc, dst)
        except FileNotFoundError as e:
            warn(f'{elf["path"]}: {e}')
            return
        except IOError:
            try:
                os.unlink(dst)
            except FileNotFoundError:
                pass
            shutil.copy2(realsrc, dst)

        if wrapit:
            if options.verbose:
                print("generate wrapper", dst)

            if options.libdir:
                interp = os.path.join(options.libdir, os.path.basename(elf["interp"]))
            else:
                interp = _StripRoot(elf["interp"])
            GenerateLdsoWrapper(options.dest, subdst, interp, libpaths, preload)

    # XXX: We should automatically import libgcc_s.so whenever libpthread.so
    # is copied over (since we know it can be dlopen-ed by NPTL at runtime).
    # Similarly, we should provide an option for automatically copying over
    # the libnsl.so and libnss_*.so libraries, as well as an open ended list
    # for known libs that get loaded (e.g. curl will dlopen(libresolv)).
    uniq_libpaths = set()
    for lib in elf["libs"]:
        libdata = elf["libs"][lib]
        path = libdata["realpath"]
        if path is None:
            warn("could not locate library:", lib)
            continue
        if not options.libdir:
            uniq_libpaths.add(_StripRoot(os.path.dirname(path)))
        _copy(path, libdata["path"], outdir=options.libdir)

    if not options.libdir:
        libpaths = list(uniq_libpaths)
        if elf["runpath"]:
            libpaths = elf["runpath"] + libpaths
        else:
            libpaths = elf["rpath"] + libpaths
    else:
        uniq_libpaths.add(options.libdir)
        libpaths = list(uniq_libpaths)

    # We don't bother to copy this as ParseElf adds the interp to the 'libs',
    # so it was already copied in the libs loop above.
    # _copy(elf['interp'], outdir=options.libdir)
    _copy(
        elf["realpath"],
        elf["path"],
        striproot=options.auto_root,
        wrapit=options.generate_wrappers,
        libpaths=libpaths,
        outdir=options.bindir,
        preload=options.wrapper_preload,
    )


def GetParser() -> argparse.ArgumentParser:
    """Get a CLI parser."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        default=False,
        help="Show all duplicated dependencies",
    )
    parser.add_argument(
        "-l",
        "--list",
        action="store_true",
        default=False,
        help="Display output in a simple list (easy for copying)",
    )
    parser.add_argument(
        "-x", "--debug", action="store_true", default=False, help="Run with debugging"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=False, help="Be verbose"
    )
    parser.add_argument(
        "--skip-non-elfs",
        action="store_true",
        default=False,
        help="Skip plain (non-ELF) files instead of warning",
    )
    parser.add_argument(
        "--skip-missing",
        action="store_true",
        default=False,
        help="Skip missing files instead of failing",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version="lddtree by Mike Frysinger <vapier@gentoo.org>",
        help="Show version information",
    )
    parser.add_argument("path", nargs="+")

    group = parser.add_argument_group("Path options")
    group.add_argument(
        "-R",
        "--root",
        default=os.environ.get("ROOT", ""),
        type=str,
        action=_NormalizePathAction,
        help="Search for all files/dependencies in ROOT",
    )
    group.add_argument(
        "--auto-root",
        action="store_true",
        help="Automatically prefix input ELFs with ROOT",
    )
    group.add_argument(
        "--no-auto-root",
        dest="auto_root",
        action="store_false",
        help=argparse.SUPPRESS,
    )
    group.set_defaults(auto_root=False)
    group.add_argument(
        "-C",
        "--cwd",
        default=os.getcwd(),
        type=str,
        action=_NormalizePathAction,
        help="Path to resolve relative paths against",
    )
    group.add_argument(
        "-P",
        "--prefix",
        default=os.environ.get("EPREFIX", "@GENTOO_PORTAGE_EPREFIX@"),
        type=str,
        action=_NormalizePathAction,
        help="Specify EPREFIX for binaries (for Gentoo Prefix)",
    )

    group = parser.add_argument_group("Copying options")
    group.add_argument(
        "--copy-to-tree",
        dest="dest",
        default=None,
        type=str,
        action=_NormalizePathAction,
        help="Copy all files to the specified tree",
    )
    group.add_argument(
        "--bindir",
        default=None,
        type=str,
        action=_NormalizePathAction,
        help="Dir to store all ELFs specified on the command line",
    )
    group.add_argument(
        "--libdir",
        default=None,
        type=str,
        action=_NormalizePathAction,
        help="Dir to store all ELF libs",
    )
    group.add_argument(
        "--generate-wrappers",
        action="store_true",
        default=False,
        help="Wrap executable ELFs with scripts for local ldso",
    )
    group.add_argument(
        "--copy-non-elfs",
        action="store_true",
        default=False,
        help="Copy over plain (non-ELF) files instead of warn+ignore",
    )
    group.add_argument(
        "--wrapper-preload",
        default=None,
        type=str,
        help="Have wrapper add --preload to the ldso invocation",
    )

    if argcomplete is not None:
        argcomplete.autocomplete(parser)
    return parser


def main(argv: List[str]) -> Optional[int]:
    """The main entry point!"""
    parser = GetParser()
    options = parser.parse_args(argv)
    paths = options.path

    if options.root != "/":
        options.root += "/"
    if options.prefix == "@" "GENTOO_PORTAGE_EPREFIX" "@":
        options.prefix = ""

    if options.bindir and options.bindir[0] != "/":
        parser.error("--bindir accepts absolute paths only")
    if options.libdir and options.libdir[0] != "/":
        parser.error("--libdir accepts absolute paths only")

    if options.skip_non_elfs and options.copy_non_elfs:
        parser.error("pick one handler for non-ELFs: skip or copy")

    dbg(options.debug, "root =", options.root)
    dbg(options.debug, "cwd =", options.cwd)
    if options.dest:
        dbg(options.debug, "dest =", options.dest)
    if not paths:
        err("missing ELF files to scan")

    ldpaths = LoadLdpaths(
        options.root, cwd=options.cwd, prefix=options.prefix, debug=options.debug
    )
    dbg(options.debug, "ldpaths[conf] =", ldpaths["conf"])
    dbg(options.debug, "ldpaths[env]  =", ldpaths["env"])

    # Process all the files specified.
    ret = 0
    for path in paths:
        dbg(options.debug, "argv[x]       =", path)
        # Only auto-prefix the path if the ELF is absolute.
        # If it's a relative path, the user most likely wants
        # the local path.
        if options.auto_root and path.startswith("/"):
            path = options.root + path.lstrip("/")
            dbg(options.debug, "  +auto-root  =", path)

        matched = False
        for p in glob.iglob(path):
            # Once we've processed the globs, resolve the symlink.  This way you can
            # operate on a path that is an absolute symlink itself.  e.g.:
            #   $ ln -sf /bin/bash $PWD/root/bin/sh
            #   $ lddtree --root $PWD/root /bin/sh
            # First we'd turn /bin/sh into $PWD/root/bin/sh, then we want to resolve
            # the symlink to $PWD/root/bin/bash rather than a plain /bin/bash.
            dbg(options.debug, "  globbed     =", p)
            if not path.startswith("/"):
                realpath = os.path.realpath(path)
            elif options.auto_root:
                realpath = readlink(p, options.root, prefixed=True)
            else:
                realpath = path
            if path != realpath:
                dbg(options.debug, "  resolved    =", realpath)

            matched = True
            try:
                elf = ParseELF(
                    realpath,
                    options.root,
                    options.cwd,
                    options.prefix,
                    ldpaths,
                    display=p,
                    debug=options.debug,
                )
            except exceptions.ELFError as e:
                if options.skip_non_elfs:
                    continue
                # XXX: Ugly.  Should unify with _Action* somehow.
                if options.dest is not None and options.copy_non_elfs:
                    if os.path.exists(p):
                        elf = {
                            "interp": None,
                            "libs": [],
                            "runpath": [],
                            "rpath": [],
                            "path": p,
                            "realpath": realpath,
                        }
                        _ActionCopy(options, elf)
                        continue
                ret = 1
                warn(f"{p}: {e}")
                continue
            except IOError as e:
                ret = 1
                warn(f"{p}: {e}")
                continue

            if options.dest is None:
                _ActionShow(options, elf)
            else:
                _ActionCopy(options, elf)

        if not matched:
            if not options.skip_missing:
                ret = 1
            warn(f"{path}: did not match any paths")

    return ret


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
