require File.join(File.dirname(__FILE__), 'test_helper')

class AsymmetricEncryptorTest < Test::Unit::TestCase
  def setup
    @data = 'encrypted_strings'
    @key = 'secret'
    @public_key_file = File.dirname(__FILE__) + '/keys/public'
    @private_key_file = File.dirname(__FILE__) + '/keys/private'
    @encrypted_public_key_file = File.dirname(__FILE__) + '/keys/encrypted_public'
    @encrypted_private_key_file = File.dirname(__FILE__) + '/keys/encrypted_private'
    
    @encrypted_data = "NMGkkSu8dFdM455ru46b8TIkWQDHVdi4aJFZBCZ5p2VQV88OJnLBnnWYBXZk\n8HcyXzKb1I9lxuVHU/eZorGl7Q==\n"
    @encrypted_data_with_encrypted_keys = "C6sJrSzSaVZ9gCPanUpUmSir5At6tMfBzPvJO/MXYJVJNxF3uKMy9IsJHqos\nz5tVAdyOUNBr3jroqFK22mdKqw==\n"
    
    PluginAWeek::EncryptedStrings::AsymmetricEncryptor.default_public_key_file = nil
    PluginAWeek::EncryptedStrings::AsymmetricEncryptor.default_private_key_file = nil
  end
  
  def test_should_not_be_public_without_public_key_file
    encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new
    assert !encryptor.public?
  end
  
  def test_should_not_be_private_without_privae_key_file
    encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new
    assert !encryptor.private?
  end
  
  def test_should_read_key_files
    encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new(
      :public_key_file => @public_key_file,
      :private_key_file => @private_key_file
    )
    assert encryptor.public?
    assert encryptor.private?
  end
  
  def test_should_read_encrypted_key_files
    encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new(
      :public_key_file => @encrypted_public_key_file,
      :private_key_file => @encrypted_private_key_file
    )
    assert encryptor.public?
    assert encryptor.private?
  end
  
  def test_should_decrypt_files
    encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new(
      :public_key_file => @public_key_file,
      :private_key_file => @private_key_file
    )
    
    assert_equal @data, encryptor.decrypt(@encrypted_data)
  end
  
  def test_should_decrypt_files_with_encrypted_key
    encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new(
      :public_key_file => @encrypted_public_key_file,
      :private_key_file => @encrypted_private_key_file,
      :key => @key
    )
    
    assert_equal @data, encryptor.decrypt(@encrypted_data_with_encrypted_keys)
  end
  
  def test_should_decrypt_files_with_default_key
    set_default_key_files @public_key_file, @private_key_file
    assert_equal @data, PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new.decrypt(@encrypted_data)
  end
  
  def test_should_decrypt_files_with_default_encrypted_key
    set_default_key_files @encrypted_public_key_file, @encrypted_private_key_file
    assert_equal @data, PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new(:key => @key).decrypt(@encrypted_data_with_encrypted_keys)
  end
  
  def test_should_read_key_files_with_default_key
    set_default_key_files @public_key_file, @private_key_file
    
    encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new
    assert encryptor.private?
    assert encryptor.public?
  end
  
  def test_should_read_encrypted_key_files_with_default_key
    set_default_key_files @encrypted_public_key_file, @encrypted_private_key_file
    
    encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new
    assert encryptor.private?
    assert encryptor.public?
  end
  
  private
  def set_default_key_files(public_key, private_key)
    PluginAWeek::EncryptedStrings::AsymmetricEncryptor.default_public_key_file = public_key
    PluginAWeek::EncryptedStrings::AsymmetricEncryptor.default_private_key_file = private_key
  end
end
