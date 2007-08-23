require File.join(File.dirname(__FILE__), 'test_helper')

class EncryptedStringsTest < Test::Unit::TestCase
  def test_should_use_sha_for_default_encryption
    assert_instance_of PluginAWeek::EncryptedStrings::ShaEncryptor, 'test'.encrypt.encryptor
  end
  
  def test_should_use_configuration_options_for_default_encryption
    encrypted_string = 'test'.encrypt(:salt => 'different_salt')
    assert_instance_of PluginAWeek::EncryptedStrings::ShaEncryptor, encrypted_string.encryptor
    assert_equal 'different_salt', encrypted_string.encryptor.salt
  end
  
  def test_should_use_custom_encryptor_if_mode_specified
    encrypted_string = 'test'.encrypt(:symmetric, :key => 'key')
    assert_instance_of PluginAWeek::EncryptedStrings::SymmetricEncryptor, encrypted_string.encryptor
  end
  
  def test_should_replace_string_with_bang_encryption
    encrypted_string = 'test'
    encrypted_string.encrypt!
    
    assert !'test'.equals_without_encryption(encrypted_string)
    assert_instance_of PluginAWeek::EncryptedStrings::ShaEncryptor, encrypted_string.encryptor
  end
  
  def test_should_be_encrypted_if_string_has_been_encrypted
    assert 'test'.encrypt.encrypted?
  end
  
  def test_should_not_be_encrypted_if_string_has_not_been_encrypted
    assert !'test'.encrypted?
  end
  
  def test_should_not_be_encrypted_after_being_decrypted
    encrypted_string = 'test'.encrypt(:symmetric, :key => 'secret')
    decrypted_string = encrypted_string.decrypt
    assert !decrypted_string.encrypted?
  end
  
  def test_should_use_encryptor_for_decryption_by_default
    encrypted_string = 'test'.encrypt(:symmetric, :key => 'secret')
    assert 'test'.equals_without_encryption(encrypted_string.decrypt)
  end
  
  def test_should_allow_custom_mode_when_decrypting
    assert_equal 'test', "MU6e/5LvhKA=\n".decrypt(:symmetric, :key => 'secret')
  end
  
  def test_should_replace_string_with_bang_decryption
    encrypted_string = "MU6e/5LvhKA=\n"
    encrypted_string.decrypt!(:symmetric, :key => 'secret')
    
    assert !"MU6e/5LvhKA=\n".equals_without_encryption(encrypted_string)
    assert 'test'.equals_without_encryption(encrypted_string)
  end
  
  def test_should_be_able_to_decrypt_if_encryptor_can_decrypt
    assert 'test'.encrypt(:symmetric, :key => 'secret').can_decrypt?
  end
  
  def test_should_not_be_able_to_decrypt_if_encryptor_cant_decrypt
    assert !'test'.encrypt(:sha).can_decrypt?
  end
  
  def test_should_not_be_able_to_decrypt_if_never_encrypted
    assert !'test'.can_decrypt?
  end
  
  def test_should_be_able_to_check_equality_without_decryption_support
    value = 'test'
    encrypted_string = 'test'.encrypt(:sha)
    encrypted_encrypted_string = encrypted_string.encrypt(:sha)
    
    assert_equal value, encrypted_string
    assert_equal encrypted_string, value
    assert_equal encrypted_string, encrypted_encrypted_string
    assert_equal encrypted_encrypted_string, encrypted_string
    assert_equal encrypted_string.to_s, encrypted_string
    assert_equal encrypted_string, encrypted_string.to_s
    assert_equal encrypted_string, encrypted_string
    
    assert_not_equal value, encrypted_encrypted_string
    assert_not_equal encrypted_encrypted_string, value
  end
  
  def test_should_be_able_to_check_equality_with_decryption_support
    PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_key = 'secret'
    
    value = 'test'
    encrypted_string = value.encrypt(:symmetric)
    encrypted_encrypted_string = encrypted_string.encrypt(:symmetric)
    
    assert_equal value, encrypted_string
    assert_equal encrypted_string, value
    assert_equal encrypted_string, encrypted_encrypted_string
    assert_equal encrypted_encrypted_string, encrypted_string
    assert_equal encrypted_string.to_s, encrypted_string
    assert_equal encrypted_string, encrypted_string.to_s
    assert_equal encrypted_string, encrypted_string
    
    assert_not_equal value, encrypted_encrypted_string
    assert_not_equal encrypted_encrypted_string, value
  end
end
