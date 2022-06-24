xmlto = find_program('xmlto', required : get_option('build_manpages'))

if not xmlto.found()
  subdir_done()
endif

docbook_conf = configuration_data()
docbook_conf.set('version', meson.project_version())
docbook_conf.set('man_dir', meson.current_source_dir())

book = configure_file(
  input : 'pax-utils.docbook.in',
  output : 'pax-utils.docbook',
  configuration : docbook_conf
)

pages = [
    'dumpelf.docbook', 'pspax.docbook', 'scanelf.docbook', 'scanmacho.docbook'
]

out_pages = []
foreach page : pages
  out_pages += page.replace('.docbook', '.1')
endforeach

custom_target('docbook_to_man',
  command : [
    xmlto, 'man', '-x', files('custom.xsl'), '--skip-validation', book,
    '-o', meson.current_build_dir()
  ],
  input : [
    'pax-utils.docbook.in', 'custom.xsl', 'fragment/reftail',
  ] + pages,
  output : out_pages,
  install : true,
  install_dir : get_option('mandir') / 'man1'
)
