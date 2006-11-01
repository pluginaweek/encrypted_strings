# Represents a string that has been encrypted.  Certain encryption algorithms
# do not allow for strings to be decrypted.
#
class EncryptedString < String
  # Indicates no key was specified
  # 
  class NoKeyError < StandardError
  end
  
  # Indicates no public key was found
  # 
  class NoPublicKeyError < StandardError
  end
  
  # Indicates no private key was found
  # 
  class NoPrivateKeyError < StandardError
  end
  
  class << self
    # Decrypts the specified value
    # 
    def decrypt(data, options = {})
      options[:encrypt] = false
      self.new(data, options).decrypt
    end
  end
  
  def initialize(data, options) #:nodoc:
    options.reverse_merge!(:encrypt => true)
    
    super(options[:encrypt] ? encrypt_data(data) : data)
  end
  
  # Can this string be decrypted?
  #
  def supports_decryption?
    true
  end
  
  # By default, decryption is not supported
  # 
  def decrypt
    raise NotImplementedError, "Cannot decrypt a #{self.class.name}"
  end
  
  # Tests whether the other object is equal to this one.  If the other object
  # is a String, it's equality will be tested by encrypting it based on the
  # algorithm used in this encrypted string.  If the resulting values are the
  # same, then the strings are equal.
  # 
  # This method should be overriden for algorithms that generate different
  # encrypted strings at different times given the same parameters.
  #
  def ==(other)
    if other.class == String
      is_string_equal?(other)
    elsif EncryptedString === other
      is_string_equal?(other) || other == to_s
    else
      super
    end
  end
  
  private
  def is_string_equal?(value) #:nodoc:
    value = value.to_s if value.class != String
    
    to_s == value || (supports_decryption? ? decrypt == value : to_s == encrypt_data(value))
  end
end