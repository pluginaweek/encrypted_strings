require File.join(File.dirname(__FILE__), 'test_helper')

class SymmetricallyEncryptedStringTest < Test::Unit::TestCase
  def setup
    @str = 'encrypted_strings'
    @key = 'secret'
    @encrypted = "zGIFuxNpo9/Ayg5gv9WpcqTJPPtG1eW5\n"
    @encrypted_string = SymmetricallyEncryptedString.new(@encrypted, :key => @key, :encrypt => false)
    SymmetricallyEncryptedString.default_key = nil
  end
  
  def test_should_encrypt
    assert_equal @encrypted, SymmetricallyEncryptedString.new(@encrypted, :key => @key)
  end
  
  def test_should_decrypt
    assert_equal @str, @encrypted_string.decrypt
  end
  
  def test_should_encrypt_with_default_key
    SymmetricallyEncryptedString.default_key = @key
    assert_equal @encrypted, SymmetricallyEncryptedString.new(@encrypted)
  end
  
  def test_should_decrypt_with_default_key
    SymmetricallyEncryptedString.default_key = @key
    assert_equal @str, SymmetricallyEncryptedString.new(@encrypted, :encrypt => false)
  end
  
  def test_should_raise_error_when_no_key
    assert_raises(EncryptedString::NoKeyError) { SymmetricallyEncryptedString.new(@encrypted) }
  end
end