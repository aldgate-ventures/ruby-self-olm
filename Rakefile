require 'rake/testtask'
require 'rake/extensiontask'

Rake::ExtensionTask.new  do |ext|
  ext.name = "self_crypto"
  ext.ext_dir = "ext/self_crypto"
  ext.lib_dir = "lib/self_crypto"
end

task :test => :compile

Rake::TestTask.new do |t|
  t.name = :test
  t.libs << "lib"
  t.test_files = FileList["test/**/test_*.rb"]
  t.verbose = true
end

task :default => :test
