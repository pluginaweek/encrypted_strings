require 'encrypted_strings/no_private_key_error'
require 'encrypted_strings/no_public_key_error'

module PluginAWeek #:nodoc:
  module EncryptedStrings
    # Encryption in which the keys used to encrypt/decrypt come in pairs.  Also
    # known as public key encryption.  Anything that's encrypted using the
    # public key can only be decrypted with the same algorithm and a matching
    # private key.  Any message that is encrypted with the private key can only
    # be decrypted with the matching public key.
    # 
    # Source: http://support.microsoft.com/kb/246071
    # 
    # == Encrypting 
    # 
    # To encrypt a string using an asymmetric algorithm, the location of the
    # public key file must be specified.  You can define the default for this
    # value like so:
    # 
    #   PluginAWeek::EncryptedStrings::AsymmetricEncryptor.default_public_key_file = "./public.key"
    # 
    # If these configuration options are not passed in to #encrypt, then the
    # default values will be used.  You can override the default values like so:
    # 
    #   password = "shhhh"
    #   password.encrypt(:asymmetric, :public_key_file => "./encrypted_public.key")  # => "INy95irZ8AlHmvc6ZAF/ARsTpbqPIB/4bEAKKOebjsayB7NYWtIzpswvzxqf\nNJ5yyuvxfMODrcg7RimEMFkFlg==\n"
    # 
    # An exception will be raised if either the public key file could not be
    # found or the key could not decrypt the public key file.
    # 
    # == Decrypting
    # 
    # To decrypt a string using an asymmetric algorithm, the location of the
    # private key file must be specified.  If this file is itself encrypted, you
    # must also specify the algorithm and key used to seed the symmetric
    # algorithm that will decrypt the plublic key file.  You can define defaults
    # for these values like so:
    # 
    #   PluginAWeek::EncryptedStrings::AsymmetricEncryptor.default_private_key_file = "./private.key"
    #   PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_algorithm = "DES-EDE3-CBC"
    #   PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_password = "secret"
    # 
    # If these configuration options are not passed in to #decrypt, then the
    # default values will be used.  You can override the default values like so:
    # 
    #   password = "INy95irZ8AlHmvc6ZAF/ARsTpbqPIB/4bEAKKOebjsayB7NYWtIzpswvzxqf\nNJ5yyuvxfMODrcg7RimEMFkFlg==\n"
    #   password.decrypt(:asymmetric, :public_key_file => "./encrypted_public.key", :password => "secret") # => "shhhh"
    # 
    # An exception will be raised if either the private key file could not be
    # found or the key could not decrypt the private key file.
    class AsymmetricEncryptor < Encryptor
      class << self
        # The default private key to use during encryption.  Default is nil.
        attr_accessor :default_private_key_file
        
        # The default public key to use during encryption.  Default is nil.
        attr_accessor :default_public_key_file
        
        # The default algorithm to use.  Default is nil.
        attr_accessor :default_algorithm
      end
      
      # Set defaults
      @default_private_key_file = nil
      @default_public_key_file = nil
      @default_algorithm = nil
      
      # Private key used for decrypting data
      attr_reader :private_key_file
      
      # Public key used for encrypting data
      attr_reader :public_key_file
      
      # The algorithm to use if the key files are encrypted themselves
      attr_accessor :algorithm
      
      # The password used during symmetric decryption of the key files
      attr_accessor :password
      
      # Configuration options:
      # * +private_key_file+ - Encrypted private key file
      # * +public_key_file+ - Public key file
      # * +password+ - The password to use in the symmetric encryptor
      # * +key+ - DEPRECATED. The password to use in the symmetric encryptor
      # * +algorithm+ - Algorithm to use symmetrically encrypted strings
      # * +pkcs5_compliant+ - Whether the generated key/iv should comply to the PKCS #5 standard. Default is false.
      def initialize(options = {})
        invalid_options = options.keys - [:private_key_file, :public_key_file, :password, :key, :algorithm, :pkcs5_compliant]
        raise ArgumentError, "Unknown key(s): #{invalid_options.join(", ")}" unless invalid_options.empty?
        
        options = {
          :private_key_file => self.class.default_private_key_file,
          :public_key_file => self.class.default_public_key_file,
          :algorithm => self.class.default_algorithm
        }.merge(options)
        
        @public_key = @private_key = nil
        
        self.algorithm  = options[:algorithm]
        self.private_key_file = options[:private_key_file]
        self.public_key_file  = options[:public_key_file]
        self.password = options[:password] || options[:key]
        warn(':key option is deprecated and will be removed from encrypted_attributes 0.2.0 (use :password)') if options[:key]
        @pkcs5_compliant = options[:pkcs5_compliant]
        
        raise ArgumentError, 'At least one key file must be specified (:private_key_file or :public_key_file)' unless private_key_file || public_key_file
        
        super()
      end
      
      # Encrypts the given data. If no public key file has been specified, then
      # a NoPublicKeyError will be raised.
      def encrypt(data)
        raise NoPublicKeyError, "Public key file: #{public_key_file}" unless public?
        
        encrypted_data = public_rsa.public_encrypt(data)
        Base64.encode64(encrypted_data)
      end
      
      # Decrypts the given data. If no private key file has been specified, then
      # a NoPrivateKeyError will be raised.
      def decrypt(data)
        raise NoPrivateKeyError, "Private key file: #{private_key_file}" unless private?
        
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
      
      # Does this encryptor have a public key available?
      def public?
        return true if @public_key
        
        load_public_key
        !@public_key.nil?
      end
      
      # Does this encryptor have a private key available?
      def private?
        return true if @private_key
        
        load_private_key
        !@private_key.nil?
      end
      
      private
        # Loads the private key from the configured file
        def load_private_key
          @private_rsa = nil
          
          if private_key_file && File.file?(private_key_file)
            @private_key = File.read(private_key_file)
          end
        end
        
        # Loads the public key from the configured file
        def load_public_key
          @public_rsa = nil
          
          if public_key_file && File.file?(public_key_file)
            @public_key = File.read(public_key_file)
          end
        end
        
        # Retrieves the private RSA from the private key
        def private_rsa
          if password
            options = {:password => password}
            options[:algorithm] = algorithm if algorithm
            options[:pkcs5_compliant] = @pkcs5_compliant if !@pkcs5_compliant.nil?
            
            private_key = @private_key.decrypt(:symmetric, options)
            OpenSSL::PKey::RSA.new(private_key)
          else
            @private_rsa ||= OpenSSL::PKey::RSA.new(@private_key)
          end
        end
        
        # Retrieves the public RSA
        def public_rsa
          @public_rsa ||= OpenSSL::PKey::RSA.new(@public_key)
        end
    end
  end
end
