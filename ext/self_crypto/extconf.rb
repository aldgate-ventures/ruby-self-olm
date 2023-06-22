require 'mkmf'

$CFLAGS = "-fPIC -std=c99"
$LDFLAGS = " -no-pie -shared " + $LDFLAGS

RbConfig::MAKEFILE_CONFIG['CC'] = ENV['CC'] if ENV['CC']

pkg_config('self_omemo')

abort "Missing omemo" unless have_library("self_omemo")

create_makefile('self_crypto/self_crypto')
