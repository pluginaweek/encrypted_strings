require File.join(File.dirname(__FILE__), 'test_helper')

class EncryptorTest < Test::Unit::TestCase
  def setup
    @encryptor = PluginAWeek::EncryptedStrings::Encryptor.new
  end
  
  def test_can_decrypt
    assert @encryptor.can_decrypt?
  end
  
  def test_decryption_not_implemented
    assert_raises(NotImplementedError) { @encryptor.decrypt('test') }
  end
end