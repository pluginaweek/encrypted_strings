require File.join(File.dirname(__FILE__), 'test_helper')

class SymmetricallyEncryptedStringTest < Test::Unit::TestCase
  def setup
    @data = 'test'
    @key = 'secret'
    @encrypted = "MU6e/5LvhKA=\n"
    PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_key = nil
  end
  
  def test_should_raise_exception_if_no_key_specified
    assert_raises(PluginAWeek::EncryptedStrings::NoKeyError) { PluginAWeek::EncryptedStrings::SymmetricEncryptor.new }
  end
  
  def test_encrypt_with_default_key_if_key_not_specified
    PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_key = @key
    assert_equal @encrypted, PluginAWeek::EncryptedStrings::SymmetricEncryptor.new.encrypt(@data)
  end
  
  def test_should_encrypt_with_custom_key_if_key_specified
    assert_equal @encrypted, PluginAWeek::EncryptedStrings::SymmetricEncryptor.new(:key => @key).encrypt(@data)
  end
  
  def test_should_be_able_to_decrypt
    assert PluginAWeek::EncryptedStrings::SymmetricEncryptor.new(:key => @key).can_decrypt?
  end
  
  def test_should_decrypt_encrypted_string_with_custom_key_if_key_specified
    assert_equal @data, PluginAWeek::EncryptedStrings::SymmetricEncryptor.new(:key => @key).decrypt(@encrypted)
  end
  
  def test_should_decrypt_encrypted_string_with_default_key_if_key_not_specified
    PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_key = @key
    assert_equal @data, PluginAWeek::EncryptedStrings::SymmetricEncryptor.new.decrypt(@encrypted)
  end
end
