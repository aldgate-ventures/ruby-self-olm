require File.expand_path("../lib/self_crypto/version", __FILE__)
require 'time'
require 'rake'

Gem::Specification.new do |s|
    s.name    = "self_crypto"
    s.version = SelfCrypto::VERSION
    s.date = Date.today.to_s
    s.summary = "Group end to end encryption for self"
    s.authors  = ["Tom Bevan", "Cameron Harper"]
    s.email = "ops@selfid.net"
    s.homepage = "https://github.com/aldgate-ventures/self-crypto-ruby"
    s.files = FileList['lib/**/*.rb', 'ext/**/*.{rb,c,h,cpp,hh}', "test/**/*.rb", "Rakefile"]
    s.extensions = ["ext/self_crypto/extconf.rb"]
    s.license = 'Apache-2.0'
    s.test_files = Dir.glob("test/**/*.rb")
    s.add_development_dependency 'rake-compiler'
    s.add_development_dependency 'rake'
    s.add_development_dependency 'minitest'
    s.add_development_dependency 'minitest-reporters'
    s.required_ruby_version = '>= 2.0'
end
