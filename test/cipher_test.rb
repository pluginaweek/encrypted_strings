require File.dirname(__FILE__) + '/test_helper'

class CipherByDefaultTest < Test::Unit::TestCase
  def setup
    @cipher = EncryptedStrings::Cipher.new
  end
  
  def test_should_be_able_to_decrypt_by_default
    assert @cipher.can_decrypt?
  end
  
  def test_should_raise_exception_if_decrypt_not_implemented
    assert_raises(NotImplementedError) {@cipher.decrypt('test')}
  end
end
