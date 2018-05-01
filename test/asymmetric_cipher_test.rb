require File.dirname(__FILE__) + '/test_helper'

class NoPrivateKeyErrorTest < Minitest::Test
  def test_should_exist
    refute_nil EncryptedStrings::NoPrivateKeyError
  end
end

class NoPublicKeyErrorTest < Minitest::Test
  def test_should_exist
    refute_nil EncryptedStrings::NoPublicKeyError
  end
end

class AsymmetricCipherByDefaultTest < Minitest::Test
  def setup
    @asymmetric_cipher = EncryptedStrings::AsymmetricCipher.new(:public_key_file => File.dirname(__FILE__) + '/keys/public')
  end

  def test_should_raise_an_exception
    assert_raises(ArgumentError) {EncryptedStrings::AsymmetricCipher.new}
  end

  def test_should_not_have_a_public_key_file
    @asymmetric_cipher = EncryptedStrings::AsymmetricCipher.new(:private_key_file => File.dirname(__FILE__) + '/keys/private')
    assert_nil @asymmetric_cipher.public_key_file
  end

  def test_should_not_have_a_private_key_file
    assert_nil @asymmetric_cipher.private_key_file
  end

  def test_should_not_have_an_algorithm
    assert_nil @asymmetric_cipher.algorithm
  end

  def test_should_not_have_a_password
    assert_nil @asymmetric_cipher.password
  end
end

class AsymmetricCipherWithCustomDefaultsTest < Minitest::Test
  def setup
    @original_default_public_key_file = EncryptedStrings::AsymmetricCipher.default_public_key_file
    @original_default_private_key_file = EncryptedStrings::AsymmetricCipher.default_private_key_file

    EncryptedStrings::AsymmetricCipher.default_public_key_file = File.dirname(__FILE__) + '/keys/public'
    EncryptedStrings::AsymmetricCipher.default_private_key_file = File.dirname(__FILE__) + '/keys/private'

    @asymmetric_cipher = EncryptedStrings::AsymmetricCipher.new
  end

  def test_should_use_default_public_key_file
    assert_equal File.dirname(__FILE__) + '/keys/public', @asymmetric_cipher.public_key_file
  end

  def test_should_use_default_private_key_file
    assert_equal File.dirname(__FILE__) + '/keys/private', @asymmetric_cipher.private_key_file
  end

  def test_should_not_have_an_algorithm
    assert_nil @asymmetric_cipher.algorithm
  end

  def test_should_not_have_a_password
    assert_nil @asymmetric_cipher.password
  end

  def teardown
    EncryptedStrings::AsymmetricCipher.default_public_key_file = @original_default_public_key_file
    EncryptedStrings::AsymmetricCipher.default_private_key_file = @original_default_private_key_file
  end
end

class AsymmetricCipherWithInvalidOptionsTest < Minitest::Test
  def test_should_throw_an_exception
    assert_raises(ArgumentError) {EncryptedStrings::AsymmetricCipher.new(:invalid => true)}
  end
end

class AsymmetricCipherTest < Minitest::Test
  def setup
    @asymmetric_cipher = EncryptedStrings::AsymmetricCipher.new(:public_key_file => File.dirname(__FILE__) + '/keys/public')
  end

  def test_should_be_able_to_decrypt
    assert @asymmetric_cipher.can_decrypt?
  end
end

class AsymmetricCipherWithoutPublicKeyTest < Minitest::Test
  def setup
    @asymmetric_cipher = EncryptedStrings::AsymmetricCipher.new(:public_key_file => nil, :private_key_file => File.dirname(__FILE__) + '/keys/private')
  end

  def test_should_not_be_public
    assert !@asymmetric_cipher.public?
  end

  def test_should_not_be_able_to_encrypt
    assert_raises(EncryptedStrings::NoPublicKeyError) {@asymmetric_cipher.encrypt('test')}
  end
end

class AsymmetricCipherWithPublicKeyTest < Minitest::Test
  def setup
    @asymmetric_cipher = EncryptedStrings::AsymmetricCipher.new(:public_key_file => File.dirname(__FILE__) + '/keys/public')
  end

  def test_should_be_public
    assert @asymmetric_cipher.public?
  end

  def test_should_not_be_private
    assert !@asymmetric_cipher.private?
  end

  def test_should_be_able_to_encrypt
    assert_equal 90, @asymmetric_cipher.encrypt('test').length
  end

  def test_should_not_be_able_to_decrypt
    assert_raises(EncryptedStrings::NoPrivateKeyError) {@asymmetric_cipher.decrypt("HbEh0Hwri26S7SWYqO26DBbzfhR1h/0pXYLjSKUpxF5DOaOCtD9oRN748+Na\nrfNaVN5Eg7RUhbRFZE+UnNHo6Q==\n")}
  end
end

class AsymmetricCipherWithoutPrivateKeyTest < Minitest::Test
  def setup
    @asymmetric_cipher = EncryptedStrings::AsymmetricCipher.new(:private_key_file => nil, :public_key_file => File.dirname(__FILE__) + '/keys/public')
  end

  def test_should_not_be_private
    assert !@asymmetric_cipher.private?
  end

  def test_should_not_be_able_to_decrypt
    assert_raises(EncryptedStrings::NoPrivateKeyError) {@asymmetric_cipher.decrypt("HbEh0Hwri26S7SWYqO26DBbzfhR1h/0pXYLjSKUpxF5DOaOCtD9oRN748+Na\nrfNaVN5Eg7RUhbRFZE+UnNHo6Q==\n")}
  end
end

class AsymmetricCipherWithPrivateKeyTest < Minitest::Test
  def setup
    @asymmetric_cipher = EncryptedStrings::AsymmetricCipher.new(:private_key_file => File.dirname(__FILE__) + '/keys/private')
  end

  def test_should_not_be_public
    assert !@asymmetric_cipher.public?
  end

  def test_should_be_private
    assert @asymmetric_cipher.private?
  end

  def test_not_should_be_able_to_encrypt
    assert_raises(EncryptedStrings::NoPublicKeyError) {@asymmetric_cipher.encrypt('test')}
  end

  def test_should_be_able_to_decrypt
    assert_equal 'test', @asymmetric_cipher.decrypt("HbEh0Hwri26S7SWYqO26DBbzfhR1h/0pXYLjSKUpxF5DOaOCtD9oRN748+Na\nrfNaVN5Eg7RUhbRFZE+UnNHo6Q==\n")
  end
end

class AsymmetricCipherWithEncryptedPrivateKeyTest < Minitest::Test
  def setup
    @asymmetric_cipher = EncryptedStrings::AsymmetricCipher.new(:private_key_file => File.dirname(__FILE__) + '/keys/encrypted_private', :algorithm => 'DES-EDE3-CBC', :password => 'secret')
  end

  def test_should_not_be_public
    assert !@asymmetric_cipher.public?
  end

  def test_should_be_private
    assert @asymmetric_cipher.private?
  end

  def test_should_not_be_able_to_encrypt
    assert_raises(EncryptedStrings::NoPublicKeyError) {@asymmetric_cipher.encrypt('test')}
  end

  def test_should_be_able_to_decrypt
    assert_equal 'test', @asymmetric_cipher.decrypt("HbEh0Hwri26S7SWYqO26DBbzfhR1h/0pXYLjSKUpxF5DOaOCtD9oRN748+Na\nrfNaVN5Eg7RUhbRFZE+UnNHo6Q==\n")
  end
end
