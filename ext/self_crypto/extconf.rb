require 'mkmf'

$CFLAGS << ' -std=c99'

RbConfig::MAKEFILE_CONFIG['CC'] = ENV['CC'] if ENV['CC']

pkg_config('self_olm')
pkg_config('self_omemo')
pkg_config("sodium")

abort "Missing sodium" unless have_library("sodium")
abort "Missing omemo" unless have_library("self_omemo")
abort "Missing olm" unless have_library("self_olm")

create_makefile('self_crypto/self_crypto')
