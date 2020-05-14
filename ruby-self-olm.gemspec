require File.expand_path("../lib/self_olm/version", __FILE__)
require 'time'
require 'rake'

Gem::Specification.new do |s|
    s.name    = "self_olm"
    s.version = SelfOlm::VERSION
    s.date = Date.today.to_s
    s.summary = "Selfs fork of Olm for Ruby"
    s.authors  = ["Cameron Harper", "Tom Bevan"]
    s.email = "ops@selfid.net"
    s.homepage = "https://github.com/aldgate-ventures/ruby-self-olm"
    s.files = FileList['lib/**/*.rb', 'ext/**/*.{rb,c,h,cpp,hh}', "test/**/*.rb", "Rakefile"]
    s.extensions = ["ext/self_olm/extconf.rb"]
    s.license = 'Apache-2.0'
    s.test_files = Dir.glob("test/**/*.rb")
    s.add_development_dependency 'rake-compiler'
    s.add_development_dependency 'rake'
    s.add_development_dependency 'minitest'
    s.required_ruby_version = '>= 2.0'
end
