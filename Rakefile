require 'rake'
require File.join('rake', 'testtask')
require File.join('rake', 'rdoctask')

desc 'Default: run unit tests.'
task :default => :test

desc 'Test the encrypted_strings plugin.'
Rake::TestTask.new(:test) do |t|
  # Dependency on other plugins requires this plugin to exist in an rails
  # application
  if (root_path = ENV['RAILS_ROOT']).nil?
    root_path = File.dirname(File.expand_path(__FILE__))
    while (boot_paths = Dir[File.join(root_path, 'config', 'boot{,.rb}')]).empty?
      root_path = File.dirname(root_path)
    end
  end
  Dir.chdir(root_path)
  
  t.libs << 'lib'
  t.pattern = File.join(File.dirname(__FILE__), 'test', '**', '*_test.rb')
  t.verbose = true
end

desc 'Generate documentation for the encrypted_strings plugin.'
Rake::RDocTask.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title    = 'EncryptedStrings'
  rdoc.options << '--line-numbers' << '--inline-source'
  rdoc.rdoc_files.include('README')
  rdoc.rdoc_files.include(File.join('lib', '**', '*.rb'))
end
