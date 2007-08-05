require File.join(File.dirname(__FILE__), 'test_helper')

class NoPrivateKeyErrorTest < Test::Unit::TestCase
  def test_should_exist
    assert_not_nil PluginAWeek::EncryptedStrings::NoPrivateKeyError
  end
end