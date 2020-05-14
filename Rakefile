require 'rake/testtask'
require 'rake/extensiontask'

Rake::ExtensionTask.new  do |ext|
  ext.name = "self_olm"
  ext.ext_dir = "ext/self_olm"
  ext.lib_dir = "lib/self_olm"
end

task :test => :compile

Rake::TestTask.new do |t|
  t.name = :test
  t.libs << "lib"
  t.test_files = FileList["test/**/test_*.rb"]    
end

task :default => :test
