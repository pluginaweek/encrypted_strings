require 'digest/sha1'

module PluginAWeek #:nodoc:
  module EncryptedStrings #:nodoc:
    # Encrypts a string using a Secure Hash Algorithm (SHA), specifically SHA-1.
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