module EncryptedStrings
  # Indicates no password was specified for the symmetric cipher
  class NoPasswordError < StandardError
  end

  # Symmetric encryption uses a specific algorithm and password to encrypt
  # the string.  As long as the algorithm and password are known, the string
  # can be decrypted.
  #
  # Source: http://support.microsoft.com/kb/246071
  #
  # == Encrypting
  #
  # To encrypt a string using a symmetric cipher, the algorithm and password
  # must be specified.  You can define the defaults for these values like so:
  #
  #   EncryptedStrings::SymmetricCipher.default_algorithm = 'des-ecb'
  #   EncryptedStrings::SymmetricCipher.default_password = 'secret'
  #
  # If these configuration options are not passed in to #encrypt, then the
  # default values will be used.  You can override the default values like so:
  #
  #   password = 'shhhh'
  #   password.encrypt(:symmetric, :algorithm => 'des-ecb', :password => 'secret')  # => "S/sEkViX3v4=\n"
  #
  # An exception will be raised if no password is specified.
  #
  # == Decrypting
  #
  # To decrypt a string using an symmetric cipher, the algorithm and password
  # must be specified.  Defaults for these values can be defined as show above.
  #
  # If these configuration options are not passed in to #decrypt, then the
  # default values will be used.  You can override the default values like so:
  #
  #   password = "S/sEkViX3v4=\n"
  #   password.decrypt(:symmetric, :algorithm => 'des-ecb', :password => 'secret') # => "shhhh"
  #
  # An exception will be raised if no password is specified.
  class SymmetricCipher < Cipher
    class << self
      # The default algorithm to use for encryption.  Default is DES-EDE3-CBC.
      attr_accessor :default_algorithm

      # The default password to use for generating the key and initialization
      # vector.  Default is nil.
      attr_accessor :default_password
    end

    # Set default values
    @default_algorithm = 'DES-EDE3-CBC'

    # The algorithm to use for encryption/decryption
    attr_accessor :algorithm

    # The password that generates the key/initialization vector for the
    # algorithm
    attr_accessor :password

    # Creates a new cipher that uses a symmetric encryption strategy.
    #
    # Configuration options:
    # * <tt>:algorithm</tt> - The algorithm to use for generating the encrypted string
    # * <tt>:password</tt> - The secret value to use for generating the
    #   key/initialization vector for the algorithm
    def initialize(options = {})
      invalid_options = options.keys - [:algorithm, :password]
      raise ArgumentError, "Unknown key(s): #{invalid_options.join(", ")}" unless invalid_options.empty?

      options = {
        :algorithm => SymmetricCipher.default_algorithm,
        :password => SymmetricCipher.default_password
      }.merge(options)

      self.algorithm = options[:algorithm]
      self.password = options[:password]
      raise NoPasswordError if password.nil?

      super()
    end

    # Decrypts the current string using the current key and algorithm specified
    def decrypt(data)
      cipher = build_cipher(:decrypt)
      cipher.update(data.unpack('m')[0]) + cipher.final
    end

    # Encrypts the current string using the current key and algorithm specified
    def encrypt(data)
      cipher = build_cipher(:encrypt)
      [cipher.update(data) + cipher.final].pack('m')
    end

    private
      def build_cipher(type) #:nodoc:
        cipher = OpenSSL::Cipher.new(algorithm).send(type)
        cipher.pkcs5_keyivgen(password)
        cipher
      end
  end
end
