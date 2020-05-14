require 'mkmf'

pkg_config('olm')

abort "Missing olm, or olm too old (need at least 3.1.0)" unless have_library("olm")

create_makefile('self_olm/self_olm')
