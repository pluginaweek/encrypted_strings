require File.dirname(__FILE__) + '/test_helper'

class SymmetricEncryptorByDefaultTest < Test::Unit::TestCase
  def setup
    PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_key = 'secret'
    @symmetric_encryptor = PluginAWeek::EncryptedStrings::SymmetricEncryptor.new
  end
  
  def test_should_use_the_default_key
    assert_equal 'secret', @symmetric_encryptor.key
  end
  
  def test_should_use_the_default_algorithm
    assert_equal 'DES-EDE3-CBC', @symmetric_encryptor.algorithm
  end
  
  def test_should_encrypt_using_the_default_configuration
    assert_equal "MU6e/5LvhKA=\n", @symmetric_encryptor.encrypt('test')
  end
  
  def test_should_decrypt_encrypted_string_using_the_default_configuration
    assert_equal 'test', @symmetric_encryptor.decrypt("MU6e/5LvhKA=\n")
  end
  
  def teardown
    PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_key = nil
  end
end

class SymmetricEncryptorWithInvalidOptionsTest < Test::Unit::TestCase
  def test_should_throw_an_exception
    assert_raise(ArgumentError) {PluginAWeek::EncryptedStrings::SymmetricEncryptor.new(:invalid => true)}
  end
end

class SymmetricEncryptorTest < Test::Unit::TestCase
  def setup
    @symmetric_encryptor = PluginAWeek::EncryptedStrings::SymmetricEncryptor.new(:key => 'secret')
  end
  
  def test_should_be_able_to_decrypt
    assert @symmetric_encryptor.can_decrypt?
  end
end

class SymmetricEncryptorWithCustomOptionsTest < Test::Unit::TestCase
  def setup
    @symmetric_encryptor = PluginAWeek::EncryptedStrings::SymmetricEncryptor.new(:key => 'secret', :algorithm => 'DES-EDE3-CFB')
  end
  
  def test_should_use_custom_key
    assert_equal 'secret', @symmetric_encryptor.key
  end
  
  def test_should_use_custom_algorithm
    assert_equal 'DES-EDE3-CFB', @symmetric_encryptor.algorithm
  end
  
  def test_should_encrypt_using_custom_options
    assert_equal "C7D9mg==\n", @symmetric_encryptor.encrypt('test')
  end
  
  def test_should_decrypt_using_custom_options
    assert_equal 'test', @symmetric_encryptor.decrypt("C7D9mg==\n")
  end
end
