require File.dirname(__FILE__) + '/test_helper'

class ShaCipherByDefaulTest < Test::Unit::TestCase
  def setup
    @sha_cipher = EncryptedStrings::ShaCipher.new
  end
  
  def test_should_use_default_salt
    assert_equal 'salt', @sha_cipher.salt
  end
  
  def test_should_encrypt_using_default_salt
    assert_equal 'f438229716cab43569496f3a3630b3727524b81b', @sha_cipher.encrypt('test')
  end
end

class ShaCipherWithCustomDefaultsTest < Test::Unit::TestCase
  def setup
    @original_default_salt = EncryptedStrings::ShaCipher.default_salt
    EncryptedStrings::ShaCipher.default_salt = 'custom_salt'
    @sha_cipher = EncryptedStrings::ShaCipher.new
  end
  
  def test_should_use_custom_default_salt
    assert_equal 'custom_salt', @sha_cipher.salt
  end
  
  def test_should_encrypt_using_custom_default_salt
    assert_equal '280f3c516070b09aa3eb755378509c725a9c6561', @sha_cipher.encrypt('test')
  end
  
  def teardown
    EncryptedStrings::ShaCipher.default_salt = @original_default_salt
  end
end

class ShaCipherWithInvalidOptionsTest < Test::Unit::TestCase
  def test_should_throw_an_exception
    assert_raise(ArgumentError) {EncryptedStrings::ShaCipher.new(:invalid => true)}
  end
end

class ShaCipherTest < Test::Unit::TestCase
  def setup
    @sha_cipher = EncryptedStrings::ShaCipher.new
  end
  
  def test_should_not_be_able_to_decrypt
    assert !EncryptedStrings::ShaCipher.new.can_decrypt?
  end
  
  def test_should_raise_exception_if_trying_to_decrypt
    assert_raises(NotImplementedError) {EncryptedStrings::ShaCipher.new.decrypt('test')}
  end
end

class ShaCipherWithCustomOptionsTest < Test::Unit::TestCase
  def setup
    @sha_cipher = EncryptedStrings::ShaCipher.new(:salt => 'different salt')
  end
  
  def test_should_use_custom_salt
    assert_equal 'different salt', @sha_cipher.salt
  end
  
  def test_should_encrypt_using_custom_salt
    assert_equal '18e3256d71529db8fa65b2eef24a69ddad7070f3', @sha_cipher.encrypt('test')
  end
end

class ShaCipherWithNonStringSaltTest < Test::Unit::TestCase
  require 'time'
  
  def setup
    @sha_cipher = EncryptedStrings::ShaCipher.new(:salt => Time.parse('Tue Jan 01 00:00:00 UTC 2008'))
  end
  
  def test_should_stringify_salt
    assert_equal 'Tue Jan 01 00:00:00 UTC 2008', @sha_cipher.salt
  end
end
