# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{encrypted_strings}
  s.version = "0.3.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Aaron Pfeifer"]
  s.date = %q{2009-06-08}
  s.description = %q{Dead-simple string encryption/decryption syntax}
  s.email = %q{aaron@pluginaweek.org}
  s.files = ["lib/encrypted_strings.rb", "lib/encrypted_strings", "lib/encrypted_strings/sha_cipher.rb", "lib/encrypted_strings/asymmetric_cipher.rb", "lib/encrypted_strings/symmetric_cipher.rb", "lib/encrypted_strings/extensions", "lib/encrypted_strings/extensions/string.rb", "lib/encrypted_strings/cipher.rb", "test/asymmetric_cipher_test.rb", "test/keys", "test/keys/private", "test/keys/encrypted_private", "test/keys/public", "test/sha_cipher_test.rb", "test/string_test.rb", "test/cipher_test.rb", "test/test_helper.rb", "test/symmetric_cipher_test.rb", "CHANGELOG.rdoc", "init.rb", "LICENSE", "Rakefile", "README.rdoc"]
  s.has_rdoc = true
  s.homepage = %q{http://www.pluginaweek.org}
  s.require_paths = ["lib"]
  s.rubyforge_project = %q{pluginaweek}
  s.rubygems_version = %q{1.3.1}
  s.summary = %q{Dead-simple string encryption/decryption syntax}
  s.test_files = ["test/asymmetric_cipher_test.rb", "test/sha_cipher_test.rb", "test/string_test.rb", "test/cipher_test.rb", "test/symmetric_cipher_test.rb"]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 2

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
