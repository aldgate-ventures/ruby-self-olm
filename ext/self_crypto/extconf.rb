require 'mkmf'

$CFLAGS = " -std=c99"

RbConfig::MAKEFILE_CONFIG['CC'] = ENV['CC'] if ENV['CC']

pkg_config('stdc++')
pkg_config('self_omemo')

abort "Missing stdc++" unless have_library("stdc++")
abort "Missing omemo" unless have_library("self_omemo")

create_makefile('self_crypto/self_crypto')
