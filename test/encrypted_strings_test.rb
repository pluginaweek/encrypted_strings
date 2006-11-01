require File.join(File.dirname(__FILE__), 'test_helper')

class EncryptedStringsTest < Test::Unit::TestCase
  def test_default_encryption
    assert_instance_of SHAEncryptedString, 'test'.encrypt
    
    encrypted_string = 'test'.encrypt(:salt => 'different_salt')
    assert_instance_of SHAEncryptedString, encrypted_string
    assert_equal 'different_salt', encrypted_string.salt
  end
  
  def test_encryption_with_mode
    assert_instance_of SymmetricallyEncryptedString, 'test'.encrypt(:symmetrically, :key => 'key')
  end
end