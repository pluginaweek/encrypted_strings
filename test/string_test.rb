require File.join(File.dirname(__FILE__), 'test_helper')

class EncryptedStringsTest < Test::Unit::TestCase
  def test_default_encryption
    assert_instance_of PluginAWeek::EncryptedStrings::ShaEncryptor, 'test'.encrypt.encryptor
    
    encrypted_string = 'test'.encrypt(:salt => 'different_salt')
    assert_instance_of PluginAWeek::EncryptedStrings::ShaEncryptor, encrypted_string.encryptor
    assert_equal 'different_salt', encrypted_string.encryptor.salt
  end
  
#  def test_encryption_with_mode
#    assert_instance_of SymmetricallyEncryptedString, 'test'.encrypt(:symmetrically, :key => 'key')
#  end
#  
#  def test_equality_with_no_decryption_support
#    value = 'test'
#    encrypted_string = SHAEncryptedString.new(value)
#    encrypted_encrypted_string = SHAEncryptedString.new(encrypted_string)
#    
#    assert_equal value, encrypted_string
#    assert_equal encrypted_string, value
#    assert_equal encrypted_string, encrypted_encrypted_string
#    assert_equal encrypted_encrypted_string, encrypted_string
#    assert_equal encrypted_string.to_s, encrypted_string
#    assert_equal encrypted_string, encrypted_string.to_s
#    assert_equal encrypted_string, encrypted_string
#    
#    assert_not_equal value, encrypted_encrypted_string
#    assert_not_equal encrypted_encrypted_string, value
#  end
#  
#  def test_equality_with_decryption_support
#    SymmetricallyEncryptedString.default_key = 'secret'
#    
#    value = 'test'
#    encrypted_string = SymmetricallyEncryptedString.new(value)
#    encrypted_encrypted_string = SymmetricallyEncryptedString.new(encrypted_string)
#    
#    assert_equal value, encrypted_string
#    assert_equal encrypted_string, value
#    assert_equal encrypted_string, encrypted_encrypted_string
#    assert_equal encrypted_encrypted_string, encrypted_string
#    assert_equal encrypted_string.to_s, encrypted_string
#    assert_equal encrypted_string, encrypted_string.to_s
#    assert_equal encrypted_string, encrypted_string
#    
#    assert_not_equal value, encrypted_encrypted_string
#    assert_not_equal encrypted_encrypted_string, value
#  end
end