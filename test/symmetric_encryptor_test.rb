require File.dirname(__FILE__) + '/test_helper'

class SymmetricEncryptorByDefaultTest < Test::Unit::TestCase
  def setup
    @symmetric_encryptor = PluginAWeek::EncryptedStrings::SymmetricEncryptor.new(:password => 'secret')
  end
  
  def test_should_use_default_algorithm
    assert_equal 'DES-EDE3-CBC', @symmetric_encryptor.algorithm
  end
  
  def test_should_raise_exception
    assert_raise(PluginAWeek::EncryptedStrings::NoKeyError) {PluginAWeek::EncryptedStrings::SymmetricEncryptor.new}
  end
  
  def test_should_encrypt_using_default_configuration
    assert_equal "MU6e/5LvhKA=\n", @symmetric_encryptor.encrypt('test')
  end
  
  def test_should_decrypt_encrypted_string_using_default_configuration
    assert_equal 'test', @symmetric_encryptor.decrypt("MU6e/5LvhKA=\n")
  end
end

class SymmetricEncryptorWithCustomDefaultsTest < Test::Unit::TestCase
  def setup
    @original_default_algorithm = PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_algorithm
    @original_default_password = PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_password
    
    PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_algorithm = 'DES-EDE3-CFB'
    PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_password = 'secret'
    @symmetric_encryptor = PluginAWeek::EncryptedStrings::SymmetricEncryptor.new
  end
  
  def test_should_use_custom_default_algorithm
    assert_equal 'DES-EDE3-CFB', @symmetric_encryptor.algorithm
  end
  
  def test_should_use_custom_default_password
    assert_equal 'secret', @symmetric_encryptor.password
  end
  
  def test_should_encrypt_using_custom_default_configuration
    assert_equal "C7D9mg==\n", @symmetric_encryptor.encrypt('test')
  end
  
  def test_should_decrypt_encrypted_string_using_custom_default_configuration
    assert_equal 'test', @symmetric_encryptor.decrypt("C7D9mg==\n")
  end
  
  def teardown
    PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_algorithm = @original_default_algorithm
    PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_password = @original_default_password
  end
end

class SymmetricEncryptorWithInvalidOptionsTest < Test::Unit::TestCase
  def test_should_throw_an_exception
    assert_raise(ArgumentError) {PluginAWeek::EncryptedStrings::SymmetricEncryptor.new(:invalid => true)}
  end
end

class SymmetricEncryptorTest < Test::Unit::TestCase
  def setup
    @symmetric_encryptor = PluginAWeek::EncryptedStrings::SymmetricEncryptor.new(:password => 'secret')
  end
  
  def test_should_be_able_to_decrypt
    assert @symmetric_encryptor.can_decrypt?
  end
end

class SymmetricEncryptorWithCustomOptionsTest < Test::Unit::TestCase
  def setup
    @symmetric_encryptor = PluginAWeek::EncryptedStrings::SymmetricEncryptor.new(:algorithm => 'DES-EDE3-CFB', :password => 'secret')
  end
  
  def test_should_use_custom_algorithm
    assert_equal 'DES-EDE3-CFB', @symmetric_encryptor.algorithm
  end
  
  def test_should_use_custom_password
    assert_equal 'secret', @symmetric_encryptor.password
  end
  
  def test_should_encrypt_using_custom_options
    assert_equal "C7D9mg==\n", @symmetric_encryptor.encrypt('test')
  end
  
  def test_should_decrypt_using_custom_options
    assert_equal 'test', @symmetric_encryptor.decrypt("C7D9mg==\n")
  end
end

class SymmetricEncryptorWithPKCS5CompliancyTest < Test::Unit::TestCase
  def setup
    @symmetric_encryptor = PluginAWeek::EncryptedStrings::SymmetricEncryptor.new(:password => 'secret', :pkcs5_compliant => true)
  end
  
  def test_should_encrypt_using_pkcs5_generated_key
    assert_equal "oTxJd67ElLY=\n", @symmetric_encryptor.encrypt('test')
  end
  
  def test_should_decrypt_using_pkcs5_generated_key
    assert_equal 'test', @symmetric_encryptor.decrypt("oTxJd67ElLY=\n" )
  end
end

class SymmetricEncryptorWithDeprecatedDefaultsTest < Test::Unit::TestCase
  def setup
    @original_default_password = PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_password
  end
  
  def test_should_set_password_when_setting_key
    PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_key = 'secret'
    assert_equal 'secret', PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_password
  end
  
  def test_should_get_password_when_getting_key
    PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_key = 'secret'
    assert_equal 'secret', PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_key
  end
  
  def teardown
    PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_password = @original_default_password
  end
end

class SymmetricEncryptorWithDeprecatedKeyTest < Test::Unit::TestCase
  def setup
    @symmetric_encryptor = PluginAWeek::EncryptedStrings::SymmetricEncryptor.new(:key => 'secret')
  end
  
  def test_should_set_password
    assert_equal 'secret', @symmetric_encryptor.password
  end
end
