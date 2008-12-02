require File.dirname(__FILE__) + '/test_helper'

class ShaEncryptorByDefaulTest < Test::Unit::TestCase
  def setup
    @sha_encryptor = PluginAWeek::EncryptedStrings::ShaEncryptor.new
  end
  
  def test_should_use_default_salt
    assert_equal 'salt', @sha_encryptor.salt
  end
  
  def test_should_encrypt_using_default_salt
    assert_equal 'f438229716cab43569496f3a3630b3727524b81b', @sha_encryptor.encrypt('test')
  end
end

class ShaEncryptorWithCustomDefaultsTest < Test::Unit::TestCase
  def setup
    @original_default_salt = PluginAWeek::EncryptedStrings::ShaEncryptor.default_salt
    PluginAWeek::EncryptedStrings::ShaEncryptor.default_salt = 'custom_salt'
    @sha_encryptor = PluginAWeek::EncryptedStrings::ShaEncryptor.new
  end
  
  def test_should_use_custom_default_salt
    assert_equal 'custom_salt', @sha_encryptor.salt
  end
  
  def test_should_encrypt_using_custom_default_salt
    assert_equal '280f3c516070b09aa3eb755378509c725a9c6561', @sha_encryptor.encrypt('test')
  end
  
  def teardown
    PluginAWeek::EncryptedStrings::ShaEncryptor.default_salt = @original_default_salt
  end
end

class ShaEncryptorWithInvalidOptionsTest < Test::Unit::TestCase
  def test_should_throw_an_exception
    assert_raise(ArgumentError) {PluginAWeek::EncryptedStrings::ShaEncryptor.new(:invalid => true)}
  end
end

class ShaEncryptorTest < Test::Unit::TestCase
  def setup
    @sha_encryptor = PluginAWeek::EncryptedStrings::ShaEncryptor.new
  end
  
  def test_should_not_be_able_to_decrypt
    assert !PluginAWeek::EncryptedStrings::ShaEncryptor.new.can_decrypt?
  end
  
  def test_should_raise_exception_if_trying_to_decrypt
    assert_raises(NotImplementedError) {PluginAWeek::EncryptedStrings::ShaEncryptor.new.decrypt('test')}
  end
end

class ShaEncryptorWithCustomOptionsTest < Test::Unit::TestCase
  def setup
    @sha_encryptor = PluginAWeek::EncryptedStrings::ShaEncryptor.new(:salt => 'different salt')
  end
  
  def test_should_use_custom_salt
    assert_equal 'different salt', @sha_encryptor.salt
  end
  
  def test_should_encrypt_using_custom_salt
    assert_equal '18e3256d71529db8fa65b2eef24a69ddad7070f3', @sha_encryptor.encrypt('test')
  end
end

class ShaEncryptorWithNonStringSaltTest < Test::Unit::TestCase
  require 'time'
  
  def setup
    @sha_encryptor = PluginAWeek::EncryptedStrings::ShaEncryptor.new(:salt => Time.parse('Tue Jan 01 00:00:00 UTC 2008'))
  end
  
  def test_should_stringify_salt
    assert_equal 'Tue Jan 01 00:00:00 UTC 2008', @sha_encryptor.salt
  end
end
