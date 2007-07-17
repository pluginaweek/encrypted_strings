require 'encrypted_strings/no_key_error'

module PluginAWeek #:nodoc:
  module EncryptedStrings #:nodoc
    # Symmetric encryption uses a key and a specific algorithm to encrypt the
    # string.  As long as the key and algorithm are known, the string can be
    # decrypted.
    # 
    # http://support.microsoft.com/kb/246071
    class SymmetricEncryptor < Encryptor
      # The default algorithm to use for encryption.  Default is DES
      @@default_algorithm = 'DES-EDE3-CBC'
      cattr_accessor :default_algorithm
      
      # The default key to use.  Defualt is nil
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
        options[:algorithm] ||= @@default_algorithm # Saves us from nil values for algorithm
        
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