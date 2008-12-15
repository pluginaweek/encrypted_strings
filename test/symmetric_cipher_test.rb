require File.dirname(__FILE__) + '/test_helper'

class NoPasswordErrorTest < Test::Unit::TestCase
  def test_should_exist
    assert_not_nil EncryptedStrings::NoPasswordError
  end
end

class SymmetricCipherByDefaultTest < Test::Unit::TestCase
  def setup
    @symmetric_cipher = EncryptedStrings::SymmetricCipher.new(:password => 'secret')
  end
  
  def test_should_use_default_algorithm
    assert_equal 'DES-EDE3-CBC', @symmetric_cipher.algorithm
  end
  
  def test_should_raise_exception
    assert_raise(EncryptedStrings::NoPasswordError) {EncryptedStrings::SymmetricCipher.new}
  end
  
  def test_should_encrypt_using_default_configuration
    assert_equal "oTxJd67ElLY=\n", @symmetric_cipher.encrypt('test')
  end
  
  def test_should_decrypt_encrypted_string_using_default_configuration
    assert_equal 'test', @symmetric_cipher.decrypt("oTxJd67ElLY=\n")
  end
end

class SymmetricCipherWithCustomDefaultsTest < Test::Unit::TestCase
  def setup
    @original_default_algorithm = EncryptedStrings::SymmetricCipher.default_algorithm
    @original_default_password = EncryptedStrings::SymmetricCipher.default_password
    
    EncryptedStrings::SymmetricCipher.default_algorithm = 'DES-EDE3-CFB'
    EncryptedStrings::SymmetricCipher.default_password = 'secret'
    @symmetric_cipher = EncryptedStrings::SymmetricCipher.new
  end
  
  def test_should_use_custom_default_algorithm
    assert_equal 'DES-EDE3-CFB', @symmetric_cipher.algorithm
  end
  
  def test_should_use_custom_default_password
    assert_equal 'secret', @symmetric_cipher.password
  end
  
  def test_should_encrypt_using_custom_default_configuration
    assert_equal "QWz/eQ==\n", @symmetric_cipher.encrypt('test')
  end
  
  def test_should_decrypt_encrypted_string_using_custom_default_configuration
    assert_equal 'test', @symmetric_cipher.decrypt("QWz/eQ==\n")
  end
  
  def teardown
    EncryptedStrings::SymmetricCipher.default_algorithm = @original_default_algorithm
    EncryptedStrings::SymmetricCipher.default_password = @original_default_password
  end
end

class SymmetricCipherWithInvalidOptionsTest < Test::Unit::TestCase
  def test_should_throw_an_exception
    assert_raise(ArgumentError) {EncryptedStrings::SymmetricCipher.new(:invalid => true)}
  end
end

class SymmetricCipherTest < Test::Unit::TestCase
  def setup
    @symmetric_cipher = EncryptedStrings::SymmetricCipher.new(:password => 'secret')
  end
  
  def test_should_be_able_to_decrypt
    assert @symmetric_cipher.can_decrypt?
  end
end

class SymmetricCipherWithCustomOptionsTest < Test::Unit::TestCase
  def setup
    @symmetric_cipher = EncryptedStrings::SymmetricCipher.new(:algorithm => 'DES-EDE3-CFB', :password => 'secret')
  end
  
  def test_should_use_custom_algorithm
    assert_equal 'DES-EDE3-CFB', @symmetric_cipher.algorithm
  end
  
  def test_should_use_custom_password
    assert_equal 'secret', @symmetric_cipher.password
  end
  
  def test_should_encrypt_using_custom_options
    assert_equal "QWz/eQ==\n", @symmetric_cipher.encrypt('test')
  end
  
  def test_should_decrypt_using_custom_options
    assert_equal 'test', @symmetric_cipher.decrypt("QWz/eQ==\n")
  end
end
