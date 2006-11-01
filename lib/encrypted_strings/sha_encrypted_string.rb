require 'digest/sha1'

# Encrypts a string using a Secure Hash Algorithm (SHA), specifically SHA-1.
#
class SHAEncryptedString < EncryptedString
  # The default salt value to use during encryption
  @@default_salt = 'salt'
  cattr_accessor :default_salt
  
  attr_accessor :salt
  
  # Configuration options:
  # * <tt>salt</tt> - Salt value to use for encryption
  # * <tt>encrypt</tt> - Whether or not to encrypt the data.  Default is true.
  # This should usually only be set if the data is not yet encrypted.
  # 
  def initialize(data, options = {})
    options = options.symbolize_keys
    options.assert_valid_keys(
      :salt,
      :encrypt
    )
    options.reverse_merge!(
      :salt => @@default_salt
    )
    @salt = options[:salt]
    
    super
  end
  
  # Decryption is not supported.
  #
  def supports_decryption?
    false
  end
  
  private
  def encrypt_data(data) #:nodoc:
    Digest::SHA1.hexdigest(data + @salt)
  end
end