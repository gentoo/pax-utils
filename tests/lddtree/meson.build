foreach sfx : ['sh', 'py', 'cmp']
  test('lddtree-' + sfx, files('dotest-' + sfx),
    workdir : meson.current_source_dir(),
    env : {
      'builddir' : meson.project_build_root(),
      'srcdir' : meson.project_source_root(),
      'current_srcdir' : meson.current_source_dir(),
    }
  )
endforeach
