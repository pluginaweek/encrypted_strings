require File.join(File.dirname(__FILE__), 'test_helper')

class EncryptedStringTest < Test::Unit::TestCase
  def setup
    @encrypted_string = EncryptedString.new('test', :encrypt => false)
  end
  
  def test_default_supports_decryption
    assert @encrypted_string.supports_decryption?
  end
  
  def test_decryption_not_implemented
    assert_raises(NotImplementedError) { @encrypted_string.decrypt }
  end
  
  def test_class_level_decrypt
    SymmetricallyEncryptedString.default_key = 'secret'
    
    instance_decryption = SymmetricallyEncryptedString.new("zGIFuxNpo9/Ayg5gv9WpcqTJPPtG1eW5\n", :encrypt => false).decrypt
    class_decryption = SymmetricallyEncryptedString.decrypt("zGIFuxNpo9/Ayg5gv9WpcqTJPPtG1eW5\n")
    
    assert_equal instance_decryption, class_decryption
  end
  
  def test_equality_with_no_decryption_support
    value = 'test'
    encrypted_string = SHAEncryptedString.new(value)
    encrypted_encrypted_string = SHAEncryptedString.new(encrypted_string)
    
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
  
  def test_equality_with_decryption_support
    SymmetricallyEncryptedString.default_key = 'secret'
    
    value = 'test'
    encrypted_string = SymmetricallyEncryptedString.new(value)
    encrypted_encrypted_string = SymmetricallyEncryptedString.new(encrypted_string)
    
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