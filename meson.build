project('pax-utils', 'c',
  version : '1.3.7',
  license : 'GPL-2.0-only',
  default_options : [
    'warning_level=2',
    'c_std=gnu11',
  ],
)

cc = meson.get_compiler('c')

libcap = dependency('libcap', required : get_option('use_libcap'))
if libcap.found()
  add_project_arguments('-DWANT_SYSCAP', language : 'c')
endif

if get_option('use_seccomp')
  add_project_arguments('-DWANT_SECCOMP', language : 'c')
endif

if get_option('buildtype') in ['debug', 'debugoptimized']
  add_project_arguments('-DEBUG', language : 'c')
endif

# generate VCSID
version_h = vcs_tag(input : 'version.h.in', output : 'pax_utils_version.h')
# tell paxinc.h to use it
add_project_arguments('-DINCLUDE_GENERATE_VERSION_H', language : 'c')
add_project_arguments('-DVERSION="' + meson.project_version() + '"', language : 'c')

add_project_arguments('-D_GNU_SOURCE', language : 'c')
add_project_arguments('-D_FILE_OFFSET_BITS=64', language : 'c')

# probe the platform...
probe_results = configuration_data()

## first, we check a bunch of headers
foreach x : [
  'endian.h', 'byteswap.h', # GNU-likes
  'sys/endian.h', # BSDs,
  'sys/isa_defs.h', # Sun/Illumios
  'machine/endian.h', # Mach

  'linux/seccomp.h',
  'linux/securebits.h',
  'sys/prctl.h',
  'alloca.h',
  'elf-hints.h',
  'glob.h',
]
  x_exists = 0
  if cc.has_header(x)
    x_exists = 1
  endif
  probe_results.set('HAS_' + x.to_upper().underscorify(), x_exists)
endforeach

configure_file(
  output : 'probes.h',
  configuration : probe_results,
)


# common code
common_src = [
  'paxinc.c',
  'security.c',
  'xfuncs.c',
  version_h,
]
common = static_library('common',
  common_src,
  install : false
)

if cc.get_define('__svr4__') == ''
  executable('pspax',
    'paxelf.c',
    'paxldso.c',
    'pspax.c',
    version_h,
    dependencies : [libcap],
    link_with : common,
    install : true
  )
endif

executable('scanelf',
  'paxelf.c',
  'paxldso.c',
  'scanelf.c',
  version_h,
  dependencies : [libcap],
  link_with : common,
  install : true
)

# dumpelf code (without the common code above)
dumpelf_src = [
  'paxelf.c',
  'paxldso.c',
  'dumpelf.c',
  version_h,
]

executable('dumpelf',
  dumpelf_src,
  dependencies : [libcap],
  link_with : common,
  install : true
)

executable('scanmacho',
  'paxmacho.c',
  'scanmacho.c',
  version_h,
  dependencies : [libcap],
  link_with : common,
  install : true
)

lddtree_impl = get_option('lddtree_implementation')
if lddtree_impl != 'none'
  if lddtree_impl == 'python'
    suffix = '.py'
  else
    suffix = '.sh'
  endif
  install_data('lddtree' + suffix,
    rename : 'lddtree',
    install_dir : get_option('bindir')
  )
endif
install_data('symtree.sh',
  rename : 'symtree',
  install_dir : get_option('bindir')
)

subdir('man')

meson.add_dist_script('meson-build-dist-man.sh')

do_tests = get_option('tests')
if do_tests
  subdir('tests/lddtree')
  subdir('tests/scanelf')
  subdir('tests/source')
endif

if do_tests and get_option('use_fuzzing')
  ncc = meson.get_compiler('c', native : true)
  fuzz_flags = [
    '-g3', '-ggdb',
    '-fsanitize=fuzzer', '-fsanitize-coverage=edge',
    '-DPAX_UTILS_LIBFUZZ=1',
  ]
  if ncc.get_id() != 'clang'
    warning('use_fuzzing requires Clang, due to LibFuzzer. Not building fuzzers')
  else
    dumpelf_fuzzer = executable('dumpelf.fuzz',
      common_src + dumpelf_src,
      override_options : [
        'buildtype=debug',
      ],
      c_args : fuzz_flags,
      link_args : fuzz_flags,
      install : false
    )
    test('fuzz-dumpelf', dumpelf_fuzzer,
      args : [
        '-close_fd_mask=3',
        '-max_total_time=10',
        '-print_final_stats',
      ]
    )
  endif
endif
