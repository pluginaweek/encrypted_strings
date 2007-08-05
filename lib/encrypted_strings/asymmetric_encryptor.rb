require 'encrypted_strings/no_private_key_error'
require 'encrypted_strings/no_public_key_error'

module PluginAWeek #:nodoc:
  module EncryptedStrings #:nodoc:
    # Encryption in which the keys used to encrypt/decrypt come in pairs.  Also known
    # as public key encryption.  Anything that's encrypted using the public key can
    # only be decrypted with the same algorithm and a matching private key.
    # Any message that is encrypted with the private key can only be decrypted
    # with the matching public key.
    # 
    # http://support.microsoft.com/kb/246071
    class AsymmetricEncryptor < Encryptor
      # The default private key to use during encryption.  Default is nil.
      @@default_private_key_file = nil
      cattr_accessor :default_private_key_file
      
      # The default public key to use during encryption.  Default is nil.
      @@default_public_key_file = nil
      cattr_accessor :default_public_key_file
      
      # The default algorithm to use.  Default is nil.
      @@default_algorithm = nil
      cattr_accessor :default_algorithm
      
      attr_reader   :private_key_file
      attr_reader   :public_key_file
      attr_accessor :algorithm
      attr_accessor :key
      
      # Configuration options:
      # * <tt>private_key_file</tt> - Encrypted private key file
      # * <tt>public_key_file</tt> - Public key file
      # * <tt>key</tt> - The key to use in the symmetric encryptor
      # * <tt>algorithm</tt> - Algorithm to use symmetrically encrypted strings
      def initialize(options = {})
        options = options.symbolize_keys
        options.assert_valid_keys(
          :private_key_file,
          :public_key_file,
          :key,
          :algorithm
        )
        options.reverse_merge!(
          :private_key_file => @@default_private_key_file,
          :public_key_file => @@default_public_key_file,
          :algorithm => @@default_algorithm
        )
        
        @public_key = @private_key = nil
        @key = options[:key]
        @algorithm  = options[:algorithm]
        
        self.private_key_file = options[:private_key_file]
        self.public_key_file  = options[:public_key_file]
        
        super()
      end
      
      # Encrypts the given data
      def encrypt(data)
        raise NoPublicKeyError, "Public key file: #{@public_key_file}" unless public?
        
        encrypted_data = public_rsa.public_encrypt(data)
        Base64.encode64(encrypted_data)
      end
      
      # Decrypts the given data
      def decrypt(data)
        raise NoPrivateKeyError, "Private key file: #{@private_key_file}" unless private?
        
        decrypted_data = Base64.decode64(data)
        private_rsa.private_decrypt(decrypted_data)
      end
      
      # Sets the location of the private key and loads it
      def private_key_file=(file)
        @private_key_file = file and load_private_key
      end
      
      # Sets the location of the public key and loads it
      def public_key_file=(file)
        @public_key_file = file and load_public_key
      end
      
      # Is this string encrypted using a public key?
      def public?
        return true unless @public_key.nil?
        
        load_public_key
        !@public_key.nil?
      end
      
      # Is this string encrypted using a private key?
      def private?
        return true unless @private_key.nil?
        
        load_private_key
        !@private_key.nil?
      end
      
      private
      def load_private_key #:nodoc:
        @private_rsa = nil
        
        if @private_key_file && File.file?(@private_key_file)
          @private_key = File.open(@private_key_file) {|f| f.read}
        end
      end
      
      def load_public_key #:nodoc:
        @public_rsa = nil
        
        if @public_key_file && File.file?(@public_key_file)
          @public_key = File.open(@public_key_file) {|f| f.read}
        end
      end
      
      # Retrieves private RSA from the encrypted private key
      def private_rsa #:nodoc:
        return @private_rsa ||= OpenSSL::PKey::RSA.new(@private_key) unless @key
        
        private_key = SymmetricEncryptor.new(:key => @key, :algorithm => @algorithm).decrypt(@private_key)
        OpenSSL::PKey::RSA.new(private_key)
      end
      
      # Retrieves the public RSA
      def public_rsa #:nodoc:
        @public_rsa ||= OpenSSL::PKey::RSA.new(@public_key)
      end
    end
  end
end