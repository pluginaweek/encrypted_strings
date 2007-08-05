require File.join(File.dirname(__FILE__), 'test_helper')

class NoKeyErrorTest < Test::Unit::TestCase
  def test_should_exist
    assert_not_nil PluginAWeek::EncryptedStrings::NoKeyError
  end
end