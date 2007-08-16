require File.join(File.dirname(__FILE__), 'test_helper')

class EncryptorTest < Test::Unit::TestCase
  def setup
    @encryptor = PluginAWeek::EncryptedStrings::Encryptor.new
  end
  
  def test_should_be_able_to_decrypt_by_default
    assert @encryptor.can_decrypt?
  end
  
  def test_should_raise_exception_if_decrypt_not_implemented
    assert_raises(NotImplementedError) { @encryptor.decrypt('test') }
  end
end