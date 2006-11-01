require File.join(File.dirname(__FILE__), 'test_helper')

class SHAEncryptedStringTest < Test::Unit::TestCase
  def setup
    SHAEncryptedString.default_salt = 'salt'
  end
  
  def test_should_encrypt_with_salt
    assert_equal '18e3256d71529db8fa65b2eef24a69ddad7070f3', SHAEncryptedString.new('test', :salt => 'different salt')
  end
  
  def test_should_encrypt_with_default_salt
    assert_equal 'f438229716cab43569496f3a3630b3727524b81b', SHAEncryptedString.new('test')
  end
  
  def test_should_not_decrypt
    assert_raises(NotImplementedError) { SHAEncryptedString.new('test').decrypt }
  end
end