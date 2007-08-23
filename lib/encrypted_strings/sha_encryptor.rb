require 'digest/sha1'

module PluginAWeek #:nodoc:
  module EncryptedStrings
    # Encrypts a string using a Secure Hash Algorithm (SHA), specifically SHA-1.
    # 
    # == Encrypting
    # 
    # To encrypt a string using an SHA algorithm, the salt used to seed the
    # encrypting must be specified.  You can define the default for this
    # value like so:
    # 
    #   PluginAWeek::EncryptedStrings::ShaEncryptor.default_salt = "secret"
    # 
    # If these configuration options are not passed in to #encrypt, then the
    # default values will be used.  You can override the default values like so:
    # 
    #   password = "shhhh"
    #   password.encrypt(:sha, :salt => "my_salt")  # => "ae645b35bb5dfea6c9133ac872e6adfa92a3c2bd"
    # 
    # == Decrypting
    # 
    # SHA-encrypted strings cannot be decrypted.  The only way to determine
    # whether an unencrypted value is equal to an SHA-encrypted string is to
    # encrypt the value with the same salt.  For example,
    # 
    #   password = "shhhh".encrypt(:sha, :salt => "secret") # => "3b22cbe4acde873c3efc82681096f3ae69aff828"
    #   input = "shhhh".encrypt(:sha, :salt => "secret")    # => "3b22cbe4acde873c3efc82681096f3ae69aff828"
    #   password == input                                   # => true
    class ShaEncryptor < Encryptor
      # The default salt value to use during encryption
      @@default_salt = 'salt'
      cattr_accessor :default_salt
      
      attr_accessor :salt
      
      # Configuration options:
      # * <tt>salt</tt> - Salt value to use for encryption
      def initialize(options = {})
        options = options.symbolize_keys
        options.assert_valid_keys(:salt)
        options.reverse_merge!(:salt => @@default_salt)
        @salt = options[:salt]
        
        super()
      end
      
      # Decryption is not supported.
      def can_decrypt?
        false
      end
      
      # Returns the encrypted value of the data
      def encrypt(data)
        Digest::SHA1.hexdigest(data + @salt)
      end
    end
  end
end
