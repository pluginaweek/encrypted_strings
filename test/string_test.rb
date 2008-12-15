require File.dirname(__FILE__) + '/test_helper'

class StringByDefaultTest < Test::Unit::TestCase
  def setup
    @encrypted_string = 'test'.encrypt
  end
  
  def test_should_use_sha
    assert_instance_of EncryptedStrings::ShaCipher, @encrypted_string.cipher
  end
end

class StringWithCustomOptionsTest < Test::Unit::TestCase
  def setup
    @encrypted_string = 'test'.encrypt(:salt => 'different_salt')
  end
  
  def test_should_use_sha
    assert_instance_of EncryptedStrings::ShaCipher, @encrypted_string.cipher
  end
  
  def test_should_use_custom_options
    assert_equal 'different_salt', @encrypted_string.cipher.salt
  end
end

class StringWithCustomCipher
  def setup
    @encrypted_string = 'test'.encrypt(:symmetric, :password => 'key')
  end
  
  def test_should_use_custom_cipher
    assert_instance_of EncryptedStrings::SymmetricCipher, @encrypted_string.cipher
  end
end

class StringTest < Test::Unit::TestCase
  def setup
    @string = 'test'
  end
  
  def test_should_not_be_encrypted
    assert !@string.encrypted?
  end
  
  def test_should_not_have_a_cipher
    assert_nil @string.cipher
  end
  
  def test_should_not_be_able_to_decrypt
    assert !@string.can_decrypt?
  end
end

class StringAfterBeingEncryptedTest < Test::Unit::TestCase
  def setup
    @encrypted_string = 'test'.encrypt
  end
  
  def test_should_be_encrypted
    assert @encrypted_string.encrypted?
  end
end

class StringAfterBeingEncryptedAndReplacedTest < Test::Unit::TestCase
  def setup
    @encrypted_string = 'string'
    @encrypted_string.encrypt!
  end
  
  def test_should_not_be_the_original_value
    assert !'test'.equals_without_encryption(@encrypted_string)
  end
  
  def test_should_have_a_cipher
    assert_instance_of EncryptedStrings::ShaCipher, @encrypted_string.cipher
  end
  
  def test_should_be_encrypted
    assert @encrypted_string.encrypted?
  end
end

class StringAfterBeingDecryptedTest < Test::Unit::TestCase
  def setup
    @encrypted_string = 'test'.encrypt(:symmetric, :password => 'secret')
    @decrypted_string = @encrypted_string.decrypt
  end
  
  def test_should_not_be_encrypted
    assert !@decrypted_string.encrypted?
  end
  
  def test_should_not_have_a_cipher
    assert_nil @decrypted_string.cipher
  end
end

class StringAfterBeingDecryptedAndReplacedTest < Test::Unit::TestCase
  def setup
    @encrypted_string = 'test'.encrypt(:symmetric, :password => 'secret')
    @encrypted_string.decrypt!
  end
  
  def test_should_not_be_the_original_value
    assert !"oTxJd67ElLY=\n".equals_without_encryption(@encrypted_string)
  end
  
  def test_should_be_the_decrypted_value
    assert 'test'.equals_without_encryption(@encrypted_string)
  end
  
  def test_should_not_have_a_cipher
    assert_nil @encrypted_string.cipher
  end
  
  def test_should_not_be_encrypted
    assert !@encrypted_string.encrypted?
  end
end

class StringWithUndecryptableCipherTest < Test::Unit::TestCase
  def setup
    @encrypted_string = 'test'.encrypt(:sha)
  end
  
  def test_should_not_be_able_to_decrypt
    assert !@encrypted_string.can_decrypt?
  end
  
  def test_should_raise_exception_if_decrypted
    assert_raise(NotImplementedError) {@encrypted_string.decrypt}
  end
  
  def test_should_be_able_to_check_equality_with_itself
    assert_equal @encrypted_string, @encrypted_string
  end
  
  def test_should_be_able_to_check_equality_with_unencrypted_string
    assert_equal 'test', @encrypted_string
    assert_equal @encrypted_string, 'test'
  end
  
  def test_should_be_able_to_check_equality_with_encrypted_value_of_encrypted_string
    encrypted_encrypted_string = @encrypted_string.encrypt(:sha)
    
    assert_equal @encrypted_string, encrypted_encrypted_string
    assert_equal encrypted_encrypted_string, @encrypted_string
  end
  
  def test_should_be_able_to_check_equality_with_same_string_without_cipher
    assert_equal @encrypted_string.to_s, @encrypted_string
    assert_equal @encrypted_string, @encrypted_string.to_s
  end
  
  def test_should_not_be_able_to_check_equality_more_than_one_encryption_away
    encrypted_encrypted_string = @encrypted_string.encrypt(:sha)
    
    assert_not_equal 'test', encrypted_encrypted_string
    assert_not_equal encrypted_encrypted_string, 'test'
  end
end

class StringWithDecryptableCipherTest < Test::Unit::TestCase
  def setup
    @encrypted_string = 'test'.encrypt(:symmetric, :password => 'secret')
  end
  
  def test_should_be_able_to_decrypt
    assert @encrypted_string.can_decrypt?
  end
  
  def test_should_be_able_to_check_equality_with_itself
    assert_equal @encrypted_string, @encrypted_string
  end
  
  def test_should_be_able_to_check_equality_with_unencrypted_string
    assert_equal 'test', @encrypted_string
    assert_equal @encrypted_string, 'test'
  end
  
  def test_should_be_able_to_check_equality_with_encrypted_value_of_encrypted_string
    encrypted_encrypted_string = @encrypted_string.encrypt(:symmetric, :password => 'secret')
    
    assert_equal @encrypted_string, encrypted_encrypted_string
    assert_equal encrypted_encrypted_string, @encrypted_string
  end
  
  def test_should_be_able_to_check_equality_with_same_string_without_cipher
    assert_equal @encrypted_string.to_s, @encrypted_string
    assert_equal @encrypted_string, @encrypted_string.to_s
  end
  
  def test_should_not_be_able_to_check_equality_more_than_one_encryption_away
    encrypted_encrypted_string = @encrypted_string.encrypt(:symmetric, :password => 'secret')
    
    assert_not_equal 'test', encrypted_encrypted_string
    assert_not_equal encrypted_encrypted_string, 'test'
  end
end

class StringPreviouslyEncryptedTest < Test::Unit::TestCase
  def setup
    @encrypted_string = "oTxJd67ElLY=\n"
  end
  
  def test_should_not_be_encrypted
    assert !@encrypted_string.encrypted?
  end
  
  def test_should_not_have_a_cipher
    assert_nil @encrypted_string.cipher
  end
  
  def test_should_not_be_able_to_decrypt
    assert !@encrypted_string.can_decrypt?
  end
  
  def test_should_be_able_to_decrypt_with_custom_mode
    assert_equal 'test', @encrypted_string.decrypt(:symmetric, :password => 'secret')
  end
end
