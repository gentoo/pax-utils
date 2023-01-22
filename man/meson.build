xmlto = find_program('xmlto', required : get_option('build_manpages'), disabler: true)

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

fs = import('fs')

out_pages = []
generated_man_pages_exist = true
foreach page : pages
  man_page_name = page.replace('.docbook', '.1')
  out_pages += man_page_name
  if not fs.exists(man_page_name)
      generated_man_pages_exist = false
  endif
endforeach

if generated_man_pages_exist
  install_man(out_pages)
else
  custom_target('docbook_to_man',
    command : [
      xmlto, '-x', files('custom.xsl'), '--skip-validation',
      '-o', meson.current_build_dir(), 'man', book
    ],
    input : [
      'pax-utils.docbook.in', 'custom.xsl', 'fragment/reftail',
    ] + pages,
    output : out_pages,
    install : true,
    install_dir : get_option('mandir') / 'man1'
  )
endif
