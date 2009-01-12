module EncryptedStrings
  # Indicates no public key was found
  class NoPublicKeyError < StandardError
  end
  
  # Indicates no private key was found
  class NoPrivateKeyError < StandardError
  end
  
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
  # To encrypt a string using an asymmetric cipher, the location of the
  # public key file must be specified.  You can define the default for this
  # value like so:
  # 
  #   EncryptedStrings::AsymmetricCipher.default_public_key_file = './public.key'
  # 
  # If these configuration options are not passed in to #encrypt, then the
  # default values will be used.  You can override the default values like so:
  # 
  #   password = 'shhhh'
  #   password.encrypt(:asymmetric, :public_key_file => './encrypted_public.key')  # => "INy95irZ8AlHmvc6ZAF/ARsTpbqPIB/4bEAKKOebjsayB7NYWtIzpswvzxqf\nNJ5yyuvxfMODrcg7RimEMFkFlg==\n"
  # 
  # An exception will be raised if either the public key file could not be
  # found or the key could not decrypt the public key file.
  # 
  # == Decrypting
  # 
  # To decrypt a string using an asymmetric cipher, the location of the
  # private key file must be specified.  If this file is itself encrypted, you
  # must also specify the algorithm and password used to seed the symmetric
  # algorithm that will decrypt the plublic key file.  You can define defaults
  # for these values like so:
  # 
  #   EncryptedStrings::AsymmetricCipher.default_private_key_file = './private.key'
  #   EncryptedStrings::SymmetricCipher.default_algorithm = 'DES-EDE3-CBC'
  #   EncryptedStrings::SymmetricCipher.default_password = 'secret'
  # 
  # If these configuration options are not passed in to #decrypt, then the
  # default values will be used.  You can override the default values like so:
  # 
  #   password = "INy95irZ8AlHmvc6ZAF/ARsTpbqPIB/4bEAKKOebjsayB7NYWtIzpswvzxqf\nNJ5yyuvxfMODrcg7RimEMFkFlg==\n"
  #   password.decrypt(:asymmetric, :public_key_file => './encrypted_public.key', :password => 'secret') # => "shhhh"
  # 
  # An exception will be raised if either the private key file could not be
  # found or the password could not decrypt the private key file.
  class AsymmetricCipher < Cipher
    class << self
      # The default private key to use during encryption.  Default is nil.
      attr_accessor :default_private_key_file
      
      # The default public key to use during encryption.  Default is nil.
      attr_accessor :default_public_key_file
    end
    
    # Private key used for decrypting data
    attr_reader :private_key_file
    
    # Public key used for encrypting data
    attr_reader :public_key_file
    
    # The algorithm to use if the key files are encrypted themselves
    attr_accessor :algorithm
    
    # The password used during symmetric decryption of the key files
    attr_accessor :password
    
    # Creates a new cipher that uses an asymmetric encryption strategy.
    # 
    # Configuration options:
    # * <tt>:private_key_file</tt> - Encrypted private key file
    # * <tt>:public_key_file</tt> - Public key file
    # * <tt>:password</tt> - The password to use in the symmetric cipher
    # * <tt>:algorithm</tt> - Algorithm to use symmetrically encrypted strings
    def initialize(options = {})
      invalid_options = options.keys - [:private_key_file, :public_key_file, :algorithm, :password]
      raise ArgumentError, "Unknown key(s): #{invalid_options.join(", ")}" unless invalid_options.empty?
      
      options = {
        :private_key_file => AsymmetricCipher.default_private_key_file,
        :public_key_file => AsymmetricCipher.default_public_key_file
      }.merge(options)
      
      @public_key = @private_key = nil
      
      self.private_key_file = options[:private_key_file]
      self.public_key_file  = options[:public_key_file]
      raise ArgumentError, 'At least one key file must be specified (:private_key_file or :public_key_file)' unless private_key_file || public_key_file
      
      self.algorithm  = options[:algorithm]
      self.password = options[:password]
      
      super()
    end
    
    # Encrypts the given data. If no public key file has been specified, then
    # a NoPublicKeyError will be raised.
    def encrypt(data)
      raise NoPublicKeyError, "Public key file: #{public_key_file}" unless public?
      
      encrypted_data = public_rsa.public_encrypt(data)
      [encrypted_data].pack('m')
    end
    
    # Decrypts the given data. If no private key file has been specified, then
    # a NoPrivateKeyError will be raised.
    def decrypt(data)
      raise NoPrivateKeyError, "Private key file: #{private_key_file}" unless private?
      
      decrypted_data = data.unpack('m')[0]
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
    
    # Does this cipher have a public key available?
    def public?
      return true if @public_key
      
      load_public_key
      !@public_key.nil?
    end
    
    # Does this cipher have a private key available?
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
