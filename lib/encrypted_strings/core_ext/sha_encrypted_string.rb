require 'digest/sha1'

class SHAEncryptedString < EncryptedString
  cattr_accessor :salt
  @@salt = 'salt'
  
  attr_accessor :salt
  
  def initialize(data, options = {})
    options = options.symbolize_keys
    options.assert_valid_keys(
      :salt,
      :encrypt
    )
    options.reverse_merge!(
      :salt => @@salt,
      :encrypt => true
    )
    @salt = options[:salt]
    
    super(options[:encrypt] ? encrypt(data) : data)
  end
  
  #
  def decrypt
    raise NotImplementedError, 'Cannot decrypt an SHA-Encrypted String'
  end
  
  private
  def encrypt(data)
    Digest::SHA1.hexdigest(data + @salt)
  end
end