require 'encrypted_strings/no_key_error'

module PluginAWeek #:nodoc:
  module EncryptedStrings
    # Symmetric encryption uses a password and a specific algorithm to encrypt
    # the string.  As long as the password and algorithm are known, the string
    # can be decrypted.
    # 
    # Source: http://support.microsoft.com/kb/246071
    # 
    # == Encrypting 
    # 
    # To encrypt a string using a symmetric algorithm, the type of algorithm and
    # password *must* be specified.  You can define the defaults for these
    # values like so:
    # 
    #   PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_algorithm = 'des-ecb'
    #   PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_password = 'secret'
    # 
    # If these configuration options are not passed in to #encrypt, then the
    # default values will be used.  You can override the default values like so:
    # 
    #   password = 'shhhh'
    #   password.encrypt(:symmetric, :algorithm => 'des-ecb', :password => 'secret')  # => "sUG6tYSn0mI=\n"
    # 
    # An exception will be raised if no password is specified.
    # 
    # == Decrypting
    # 
    # To decrypt a string using an symmetric algorithm, the type of algorithm
    # and password must also be specified.  Defaults for these values can be
    # defined as show above.
    # 
    # If these configuration options are not passed in to #decrypt, then the
    # default values will be used.  You can override the default values like so:
    # 
    #   password = "sUG6tYSn0mI=\n"
    #   password.decrypt(:symmetric, :algorithm => 'des-ecb', :password => 'secret') # => "shhhh"
    # 
    # An exception will be raised if no password is specified.
    class SymmetricEncryptor < Encryptor
      class << self
        # The default algorithm to use for encryption.  Default is DES-EDE3-CBC.
        attr_accessor :default_algorithm
        
        # The default password to use for generating the key and initialization
        # vector.  Default is nil.
        attr_accessor :default_password
        
        # DEPRECATED
        def default_key #:nodoc:
          warn("#{self}.default_key is deprecated and will be removed from encrypted_attributes 0.2.0 (use default_password)")
          @default_password
        end
        
        # DEPRECATED
        def default_key=(value) #:nodoc:
          warn("#{self}.default_key= is deprecated and will be removed from encrypted_attributes 0.2.0 (use default_password=)")
          @default_password = value
        end
      end
      
      # Set default values
      @default_algorithm = 'DES-EDE3-CBC'
      @default_password = nil
      
      # The algorithm to use for encryption/decryption
      attr_accessor :algorithm
      
      # The password that generates the key/initialization vector for the
      # algorithm
      attr_accessor :password
      
      # Configuration options:
      # * +algorithm+ - The algorithm to use
      # * +password+ - The secret key to use for generating the key/initialization vector for the algorithm
      # * +key+ - DEPRECATED. The secret key to use for generating the key/initialization vector for the algorithm
      # * +pkcs5_compliant+ - Whether the generated key/iv should comply to the PKCS #5 standard. Default is false.
      def initialize(options = {})
        invalid_options = options.keys - [:algorithm, :password, :key, :pkcs5_compliant]
        raise ArgumentError, "Unknown key(s): #{invalid_options.join(", ")}" unless invalid_options.empty?
        
        options = {
          :algorithm => self.class.default_algorithm,
          :password => self.class.default_password,
          :pkcs5_compliant => false
        }.merge(options)
        
        @pkcs5_compliant = options[:pkcs5_compliant]
        warn('PKCS #5 non-compliancy is deprecated and will be removed from encrypted_attributes 0.2.0') if @pkcs5_compliant == false
        
        self.algorithm = options[:algorithm]
        
        self.password = options[:password] || options[:key]
        warn(':key option is deprecated and will be removed from encrypted_attributes 0.2.0 (use :password)') if options[:key]
        raise NoKeyError if password.nil?
        
        super()
      end
      
      # Decrypts the current string using the current key and algorithm specified
      def decrypt(data)
        cipher = build_cipher(:decrypt)
        cipher.update(Base64.decode64(data)) + cipher.final
      end
      
      # Encrypts the current string using the current key and algorithm specified
      def encrypt(data)
        cipher = build_cipher(:encrypt)
        Base64.encode64(cipher.update(data) + cipher.final)
      end
      
      private
        def build_cipher(type) #:nodoc:
          cipher = OpenSSL::Cipher.new(algorithm)
          cipher.send(type)
          
          if @pkcs5_compliant
            # Use the default PKCS5 key/iv generator algorithm
            cipher.pkcs5_keyivgen(password)
          else
            # To remain backwards-compatible, the deprecated #encrypt/#decrypt
            # calls (which take a single argument, being the password) is replaced
            # with pkcs5_keyivgen.  Internally, this uses "OpenSSL for Ruby rulez!"
            # as the IV/salt.  This is also the case for the number of iterations.
            cipher.pkcs5_keyivgen(password, 'OpenSSL ', 1)
            cipher.iv = 'OpenSSL for Ruby rulez!'
          end
          
          cipher
        end
    end
  end
end
