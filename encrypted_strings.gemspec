$LOAD_PATH.unshift File.expand_path('../lib', __FILE__)
require 'encrypted_strings/version'

Gem::Specification.new do |s|
  s.name              = "encrypted_strings"
  s.version           = EncryptedStrings::VERSION
  s.authors           = ["Aaron Pfeifer"]
  s.email             = "aaron@pluginaweek.org"
  s.homepage          = "http://www.pluginaweek.org"
  s.description       = "Dead-simple string encryption/decryption syntax"
  s.summary           = "Encrypts strings"
  s.require_paths     = ["lib"]
  s.files             = `git ls-files`.split("\n")
  s.test_files        = `git ls-files -- test/*`.split("\n")
  s.rdoc_options      = %w(--line-numbers --inline-source --title encrypted_strings --main README.rdoc)
  s.extra_rdoc_files  = %w(README.rdoc CHANGELOG.rdoc LICENSE)
  
  s.add_development_dependency("rake")
end
