require 'digest/sha1'

module EncryptedStrings
  # Encrypts a string using a Secure Hash Algorithm (SHA), specifically SHA-1.
  # 
  # == Encrypting
  # 
  # To encrypt a string using an SHA cipher, the salt used to seed the
  # algorithm must be specified.  You can define the default for this value
  # like so:
  # 
  #   EncryptedStrings::ShaCipher.default_salt = 'secret'
  # 
  # If these configuration options are not passed in to #encrypt, then the
  # default values will be used.  You can override the default values like so:
  # 
  #   password = 'shhhh'
  #   password.encrypt(:sha, :salt => 'secret')  # => "ae645b35bb5dfea6c9133ac872e6adfa92a3c2bd"
  # 
  # == Decrypting
  # 
  # SHA-encrypted strings cannot be decrypted.  The only way to determine
  # whether an unencrypted value is equal to an SHA-encrypted string is to
  # encrypt the value with the same salt.  For example,
  # 
  #   password = 'shhhh'.encrypt(:sha, :salt => 'secret') # => "3b22cbe4acde873c3efc82681096f3ae69aff828"
  #   input = 'shhhh'.encrypt(:sha, :salt => 'secret')    # => "3b22cbe4acde873c3efc82681096f3ae69aff828"
  #   password == input                                   # => true
  class ShaCipher < Cipher
    class << self
      # The default salt value to use during encryption
      attr_accessor :default_salt
    end
    
    # Set defaults
    @default_salt = 'salt'
    
    # The salt value to use for encryption
    attr_accessor :salt
    
    # Creates a new cipher that uses an SHA encryption strategy.
    # 
    # Configuration options:
    # * +salt+ - Random bytes used as one of the inputs for generating the encrypted string
    def initialize(options = {})
      invalid_options = options.keys - [:salt]
      raise ArgumentError, "Unknown key(s): #{invalid_options.join(", ")}" unless invalid_options.empty?
      
      options = {:salt => ShaCipher.default_salt}.merge(options)
      
      self.salt = options[:salt].to_s
      
      super()
    end
    
    # Decryption is not supported
    def can_decrypt?
      false
    end
    
    # Returns the encrypted value of the data
    def encrypt(data)
      Digest::SHA1.hexdigest(data + salt)
    end
  end
end
