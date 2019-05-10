require 'mkmf'

dir_config('olm')

abort "Missing olm, or olm too old (need at least 3.1.0)" unless have_library("olm", "olm_pk_signing")

create_makefile('ruby_olm')
