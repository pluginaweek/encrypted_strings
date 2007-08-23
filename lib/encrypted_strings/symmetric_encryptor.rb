require 'encrypted_strings/no_key_error'

module PluginAWeek #:nodoc:
  module EncryptedStrings
    # Symmetric encryption uses a key and a specific algorithm to encrypt the
    # string.  As long as the key and algorithm are known, the string can be
    # decrypted.
    # 
    # Source: http://support.microsoft.com/kb/246071
    # 
    # == Encrypting 
    # 
    # To encrypt a string using a symmetric algorithm, the type of algorithm and
    # key must be specified.  You can define the defaults for these values like
    # so:
    # 
    #   PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_algorithm = "des-ecb"
    #   PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_key = "secret"
    # 
    # If these configuration options are not passed in to #encrypt, then the
    # default values will be used.  You can override the default values like so:
    # 
    #   password = "shhhh"
    #   password.encrypt(:symmetic, :algorithm => "des-ecb", :key => "secret")  # => "sUG6tYSn0mI=\n"
    # 
    # An exception will be raised if no key is specified.
    # 
    # == Decrypting
    # 
    # To decrypt a string using an symmetric algorithm, the type of algorithm
    # and key must also be specified.  Defaults for these values can be defined
    # as show above.
    # 
    # If these configuration options are not passed in to #decrypt, then the
    # default values will be used.  You can override the default values like so:
    # 
    #   password = "sUG6tYSn0mI=\n"
    #   password.decrypt(:symmetic, :algorithm => "des-ecb", :key => "secret") # => "shhhh"
    # 
    # An exception will be raised if no key is specified.
    class SymmetricEncryptor < Encryptor
      # The default algorithm to use for encryption.  Default is DES
      @@default_algorithm = 'DES-EDE3-CBC'
      cattr_accessor :default_algorithm
      
      # The default key to use.  Default is nil
      @@default_key = nil
      cattr_accessor :default_key
      
      attr_accessor :algorithm
      attr_accessor :key
      
      # Configuration options:
      # * <tt>key</tt> - Private key
      # * <tt>algorithm</tt> - Algorithm to use
      def initialize(options = {})
        options = options.symbolize_keys
        options.assert_valid_keys(
          :key,
          :algorithm
        )
        options.reverse_merge!(:key => @@default_key)
        options[:algorithm] ||= @@default_algorithm
        
        @key = options[:key]
        raise NoKeyError if @key.nil?
        
        @algorithm = options[:algorithm]
        
        super()
      end
      
      # Decrypts the current string using the current key and algorithm specified
      def decrypt(data)
        cipher.decrypt(@key)
        decrypted_data = cipher.update(Base64.decode64(data))
        decrypted_data << cipher.final
      end
      
      # Encrypts the current string using the current key and algorithm specified
      def encrypt(data)
        cipher.encrypt(@key)
        encrypted_data = cipher.update(data)
        encrypted_data << cipher.final
        
        Base64.encode64(encrypted_data)
      end
      
      private
      def cipher #:nodoc:
        @cipher ||= OpenSSL::Cipher::Cipher.new(@algorithm)
      end
    end
  end
end
