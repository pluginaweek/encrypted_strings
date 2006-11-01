require File.join(File.dirname(__FILE__), 'test_helper')

class AsymmetricallyEncryptedStringTest < Test::Unit::TestCase
  def setup
    @str = 'encrypted_strings'
    @key = 'secret'
    @public_key_file = File.dirname(__FILE__) + '/keys/public'
    @private_key_file = File.dirname(__FILE__) + '/keys/private'
    @encrypted_public_key_file = File.dirname(__FILE__) + '/keys/encrypted_public'
    @encrypted_private_key_file = File.dirname(__FILE__) + '/keys/encrypted_private'
    
    @orig = 'encrypted_strings'
    @data = "NMGkkSu8dFdM455ru46b8TIkWQDHVdi4aJFZBCZ5p2VQV88OJnLBnnWYBXZk\n8HcyXzKb1I9lxuVHU/eZorGl7Q==\n"
    @encrypted_data = "C6sJrSzSaVZ9gCPanUpUmSir5At6tMfBzPvJO/MXYJVJNxF3uKMy9IsJHqos\nz5tVAdyOUNBr3jroqFK22mdKqw==\n"
    
    AsymmetricallyEncryptedString.default_public_key_file = nil
    AsymmetricallyEncryptedString.default_private_key_file = nil
  end
  
  def test_not_public_or_private
    @encrypted_string = AsymmetricallyEncryptedString.new(@data, :encrypt => false)
    assert !@encrypted_string.public?
    assert !@encrypted_string.private?
  end
  
  def test_should_read_key_files
    @encrypted_string = AsymmetricallyEncryptedString.new(@str,
      :public_key_file => @public_key_file,
      :private_key_file => @private_key_file
    )
    assert @encrypted_string.public?
    assert @encrypted_string.private?
  end
  
  def test_should_read_encrypted_key_files
    @encrypted_string = AsymmetricallyEncryptedString.new(@str,
      :public_key_file => @encrypted_public_key_file,
      :private_key_file => @encrypted_private_key_file
    )
    assert @encrypted_string.public?
    assert @encrypted_string.private?
  end
  
  def test_should_decrypt_files
    encrypted_string = AsymmetricallyEncryptedString.new(@data,
      :public_key_file => @public_key_file,
      :private_key_file => @private_key_file,
      :encrypt => false
    )
    
    assert_equal @orig, encrypted_string
  end
  
  def test_should_decrypt_files_with_encrypted_key
    encrypted_string = AsymmetricallyEncryptedString.new(@encrypted_data,
      :public_key_file => @encrypted_public_key_file,
      :private_key_file => @encrypted_private_key_file,
      :key => @key,
      :encrypt => false
    )
    
    assert_equal @orig, encrypted_string
  end
  
  def test_should_decrypt_files_with_default_key
    set_default_key_files @public_key_file, @private_key_file
    assert_equal @orig, AsymmetricallyEncryptedString.new(@data, :encrypt => false)
  end
  
  def test_should_decrypt_files_with_default_encrypted_key
    set_default_key_files @encrypted_public_key_file, @encrypted_private_key_file
    assert_equal @orig, AsymmetricallyEncryptedString.new(@encrypted_data, :key => @key, :encrypt => false)
  end
  
  def test_should_read_key_files_with_default_key
    set_default_key_files @public_key_file, @private_key_file
    
    encrypted_string = AsymmetricallyEncryptedString.new(@str)
    assert encrypted_string.private?
    assert encrypted_string.public?
  end
  
  def test_should_read_encrypted_key_files_with_default_key
    set_default_key_files @encrypted_public_key_file, @encrypted_private_key_file
    
    encrypted_string = AsymmetricallyEncryptedString.new(@str)
    assert encrypted_string.private?
    assert encrypted_string.public?
  end
  
  private
  def set_default_key_files(public_key, private_key)
    AsymmetricallyEncryptedString.default_public_key_file = public_key
    AsymmetricallyEncryptedString.default_private_key_file = private_key
  end
end