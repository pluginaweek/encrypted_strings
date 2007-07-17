require File.join(File.dirname(__FILE__), 'test_helper')

class SymmetricallyEncryptedStringTest < Test::Unit::TestCase
  def setup
    @data = 'encrypted_strings'
    @key = 'secret'
    @encrypted = "zGIFuxNpo9/Ayg5gv9WpcqTJPPtG1eW5\n"
    PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_key = nil
  end
  
  def test_no_key
    assert_raises(PluginAWeek::EncryptedStrings::NoKeyError) { PluginAWeek::EncryptedStrings::SymmetricEncryptor.new }
  end
  
  def test_encrypt
    assert_equal @encrypted, PluginAWeek::EncryptedStrings::SymmetricEncryptor.new(:key => @key).encrypt(@data)
  end
  
  def test_encrypt_with_default_key
    PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_key = @key
    assert_equal @encrypted, PluginAWeek::EncryptedStrings::SymmetricEncryptor.new.encrypt(@data)
  end
  
  def test_can_decrypt?
    assert PluginAWeek::EncryptedStrings::SymmetricEncryptor.new(:key => @key).can_decrypt?
  end
  
  def test_decrypt
    assert_equal @data, PluginAWeek::EncryptedStrings::SymmetricEncryptor.new(:key => @key).decrypt(@encrypted)
  end
  
  def test_decrypt_with_default_key
    PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_key = @key
    assert_equal @data, PluginAWeek::EncryptedStrings::SymmetricEncryptor.new.decrypt(@encrypted)
  end
end