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
    @original_default_algorithm = EncryptedStrings::ShaCipher.default_algorithm
    @original_default_salt = EncryptedStrings::ShaCipher.default_salt
    
    EncryptedStrings::ShaCipher.default_algorithm = 'sha512'
    EncryptedStrings::ShaCipher.default_salt = 'custom_salt'
    @sha_cipher = EncryptedStrings::ShaCipher.new
  end
  
  def test_should_use_custom_default_algorithm
    assert_equal 'SHA512', @sha_cipher.algorithm
  end
  
  def test_should_use_custom_default_salt
    assert_equal 'custom_salt', @sha_cipher.salt
  end
  
  def test_should_encrypt_using_custom_default_configuration
    assert_equal '22e38b0da46ab455cdb61375c58f66a7160227fe58727042087a59419258184b72ee0e4198110b951778dc76ace4402a377cdc31bb04195bce75196fe7684218', @sha_cipher.encrypt('test')
  end
  
  def teardown
    EncryptedStrings::ShaCipher.default_algorithm = @original_default_algorithm
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
    @sha_cipher = EncryptedStrings::ShaCipher.new(:algorithm => 'sha512', :salt => 'different salt')
  end
  
  def test_should_use_custom_algorithm
    assert_equal 'SHA512', @sha_cipher.algorithm
  end
  
  def test_should_use_custom_salt
    assert_equal 'different salt', @sha_cipher.salt
  end
  
  def test_should_encrypt_using_custom_salt
    assert_equal 'c0b0d80d279a471d9ad53cdab4a667612ecfbc0a685f502ea7a586acf107a549d17a2e5f515c2fdfe6d90a772072e4e8b0bf3de7b9c51a9c95c43b91d129f7e1', @sha_cipher.encrypt('test')
  end
end

class ShaCipherWithNonStringSaltTest < Test::Unit::TestCase
  require 'time'
  
  def setup
    @time = Time.parse('Tue Jan 01 00:00:00 UTC 2008')
    @sha_cipher = EncryptedStrings::ShaCipher.new(:salt => @time)
  end
  
  def test_should_stringify_salt
    assert_equal @time.to_s, @sha_cipher.salt
  end
end
