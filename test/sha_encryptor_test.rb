require File.join(File.dirname(__FILE__), 'test_helper')

class ShaEncryptorTest < Test::Unit::TestCase
  def setup
    PluginAWeek::EncryptedStrings::ShaEncryptor.default_salt = 'salt'
  end
  
  def test_encrypt_with_salt
    assert_equal '18e3256d71529db8fa65b2eef24a69ddad7070f3', PluginAWeek::EncryptedStrings::ShaEncryptor.new(:salt => 'different salt').encrypt('test')
  end
  
  def test_encrypt_with_default_salt
    assert_equal 'f438229716cab43569496f3a3630b3727524b81b', PluginAWeek::EncryptedStrings::ShaEncryptor.new.encrypt('test')
  end
  
  def test_can_decrypt?
    assert !PluginAWeek::EncryptedStrings::ShaEncryptor.new.can_decrypt?
  end
  
  def test_should_not_decrypt
    assert_raises(NotImplementedError) { PluginAWeek::EncryptedStrings::ShaEncryptor.new.decrypt('test') }
  end
end