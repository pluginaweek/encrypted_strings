require File.dirname(__FILE__) + '/test_helper'

class AsymmetricEncryptorByDefaultTest < Test::Unit::TestCase
  def setup
    @asymmetric_encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new(:public_key_file => File.dirname(__FILE__) + '/keys/public')
  end
  
  def test_should_raise_an_exception
    assert_raise(ArgumentError) {PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new}
  end
  
  def test_should_not_have_a_public_key_file
    @asymmetric_encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new(:private_key_file => File.dirname(__FILE__) + '/keys/private')
    assert_nil @asymmetric_encryptor.public_key_file
  end
  
  def test_should_not_have_a_private_key_file
    assert_nil @asymmetric_encryptor.private_key_file
  end
  
  def test_should_not_have_an_algorithm
    assert_nil @asymmetric_encryptor.algorithm
  end
  
  def test_should_not_have_a_password
    assert_nil @asymmetric_encryptor.password
  end
end

class AsymmetricEncryptorWithCustomDefaultsTest < Test::Unit::TestCase
  def setup
    @original_default_public_key_file = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.default_public_key_file
    @original_default_private_key_file = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.default_private_key_file
    @original_default_algorithm = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.default_algorithm
    
    PluginAWeek::EncryptedStrings::AsymmetricEncryptor.default_public_key_file = File.dirname(__FILE__) + '/keys/public'
    PluginAWeek::EncryptedStrings::AsymmetricEncryptor.default_private_key_file = File.dirname(__FILE__) + '/keys/private'
    PluginAWeek::EncryptedStrings::AsymmetricEncryptor.default_algorithm = 'DES-EDE3-CBC'
    
    @asymmetric_encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new
  end
  
  def test_should_use_default_public_key_file
    assert_equal File.dirname(__FILE__) + '/keys/public', @asymmetric_encryptor.public_key_file
  end
  
  def test_should_use_default_private_key_file
    assert_equal File.dirname(__FILE__) + '/keys/private', @asymmetric_encryptor.private_key_file
  end
  
  def test_should_use_the_default_algorithm
    assert_equal 'DES-EDE3-CBC', @asymmetric_encryptor.algorithm
  end
  
  def test_should_not_have_a_password
    assert_nil @asymmetric_encryptor.password
  end
  
  def teardown
    PluginAWeek::EncryptedStrings::AsymmetricEncryptor.default_public_key_file = @original_default_public_key_file
    PluginAWeek::EncryptedStrings::AsymmetricEncryptor.default_private_key_file = @original_default_private_key_file
    PluginAWeek::EncryptedStrings::AsymmetricEncryptor.default_algorithm = @original_default_algorithm
  end
end

class AsymmetricEncryptorWithInvalidOptionsTest < Test::Unit::TestCase
  def test_should_throw_an_exception
    assert_raise(ArgumentError) {PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new(:invalid => true)}
  end
end

class AsymmetricEncryptorTest < Test::Unit::TestCase
  def setup
    @asymmetric_encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new(:public_key_file => File.dirname(__FILE__) + '/keys/public')
  end
  
  def test_should_be_able_to_decrypt
    assert @asymmetric_encryptor.can_decrypt?
  end
end

class AsymmetricEncryptorWithoutPublicKeyTest < Test::Unit::TestCase
  def setup
    @asymmetric_encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new(:public_key_file => nil, :private_key_file => File.dirname(__FILE__) + '/keys/private')
  end
  
  def test_should_not_be_public
    assert !@asymmetric_encryptor.public?
  end
  
  def test_should_not_be_able_to_encrypt
    assert_raise(PluginAWeek::EncryptedStrings::NoPublicKeyError) {@asymmetric_encryptor.encrypt('test')}
  end
end

class AsymmetricEncryptorWithPublicKeyTest < Test::Unit::TestCase
  def setup
    @asymmetric_encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new(:public_key_file => File.dirname(__FILE__) + '/keys/public')
  end
  
  def test_should_be_public
    assert @asymmetric_encryptor.public?
  end
  
  def test_should_not_be_private
    assert !@asymmetric_encryptor.private?
  end
  
  def test_should_be_able_to_encrypt
    assert_equal 90, @asymmetric_encryptor.encrypt('test').length
  end
  
  def test_should_not_be_able_to_decrypt
    assert_raise(PluginAWeek::EncryptedStrings::NoPrivateKeyError) {@asymmetric_encryptor.decrypt("HbEh0Hwri26S7SWYqO26DBbzfhR1h/0pXYLjSKUpxF5DOaOCtD9oRN748+Na\nrfNaVN5Eg7RUhbRFZE+UnNHo6Q==\n")}
  end
end

class AsymmetricEncryptorWithoutPrivateKeyTest < Test::Unit::TestCase
  def setup
    @asymmetric_encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new(:private_key_file => nil, :public_key_file => File.dirname(__FILE__) + '/keys/public')
  end
  
  def test_should_not_be_private
    assert !@asymmetric_encryptor.private?
  end
  
  def test_should_not_be_able_to_decrypt
    assert_raise(PluginAWeek::EncryptedStrings::NoPrivateKeyError) {@asymmetric_encryptor.decrypt("HbEh0Hwri26S7SWYqO26DBbzfhR1h/0pXYLjSKUpxF5DOaOCtD9oRN748+Na\nrfNaVN5Eg7RUhbRFZE+UnNHo6Q==\n")}
  end
end

class AsymmetricEncryptorWithPrivateKeyTest < Test::Unit::TestCase
  def setup
    @asymmetric_encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new(:private_key_file => File.dirname(__FILE__) + '/keys/private')
  end
  
  def test_should_not_be_public
    assert !@asymmetric_encryptor.public?
  end
  
  def test_should_be_private
    assert @asymmetric_encryptor.private?
  end
  
  def test_not_should_be_able_to_encrypt
    assert_raise(PluginAWeek::EncryptedStrings::NoPublicKeyError) {@asymmetric_encryptor.encrypt('test')}
  end
  
  def test_should_be_able_to_decrypt
    assert_equal 'test', @asymmetric_encryptor.decrypt("HbEh0Hwri26S7SWYqO26DBbzfhR1h/0pXYLjSKUpxF5DOaOCtD9oRN748+Na\nrfNaVN5Eg7RUhbRFZE+UnNHo6Q==\n")
  end
end

class AsymmetricEncryptorWithEncryptedPrivateKeyTest < Test::Unit::TestCase
  def setup
    @asymmetric_encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new(:private_key_file => File.dirname(__FILE__) + '/keys/encrypted_private', :algorithm => 'DES-EDE3-CBC', :password => 'secret')
  end
  
  def test_should_not_be_public
    assert !@asymmetric_encryptor.public?
  end
  
  def test_should_be_private
    assert @asymmetric_encryptor.private?
  end
  
  def test_should_not_be_able_to_encrypt
    assert_raise(PluginAWeek::EncryptedStrings::NoPublicKeyError) {@asymmetric_encryptor.encrypt('test')}
  end
  
  def test_should_be_able_to_decrypt
    assert_equal 'test', @asymmetric_encryptor.decrypt("HbEh0Hwri26S7SWYqO26DBbzfhR1h/0pXYLjSKUpxF5DOaOCtD9oRN748+Na\nrfNaVN5Eg7RUhbRFZE+UnNHo6Q==\n")
  end
end

class AsymmetricEncryptorWithPKCS5CompliancyTest < Test::Unit::TestCase
  def setup
    @asymmetric_encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new(:private_key_file => File.dirname(__FILE__) + '/keys/pkcs5_encrypted_private', :algorithm => 'DES-EDE3-CBC', :password => 'secret', :pkcs5_compliant => true)
  end
  
  def test_should_be_able_to_decrypt
    assert_equal 'test', @asymmetric_encryptor.decrypt("HbEh0Hwri26S7SWYqO26DBbzfhR1h/0pXYLjSKUpxF5DOaOCtD9oRN748+Na\nrfNaVN5Eg7RUhbRFZE+UnNHo6Q==\n")
  end
end

class AsymmetricEncyrptorWithDeprecatedKeyTest < Test::Unit::TestCase
  def setup
    @asymmetric_encryptor = PluginAWeek::EncryptedStrings::AsymmetricEncryptor.new(:private_key_file => File.dirname(__FILE__) + '/keys/encrypted_private', :key => 'secret')
  end
  
  def test_should_set_password
    assert_equal 'secret', @asymmetric_encryptor.password
  end
end
