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
  #   EncryptedStrings::ShaCipher.default_algorithm = 'sha512'
  #   EncryptedStrings::ShaCipher.default_salt = 'secret'
  # 
  # If these configuration options are not passed in to #encrypt, then the
  # default values will be used.  You can override the default values like so:
  # 
  #   password = 'shhhh'
  #   password.encrypt(:sha, :salt => 'secret')  # => "ae645b35bb5dfea6c9133ac872e6adfa92a3c2bd"
  # 
  # === Customizations
  # 
  # In addition to customizing the algorithm, you can further tweak how values
  # get encrypted by defining dynamic salts and how to build the value that
  # actually gets hashed.
  # 
  # For example:
  # 
  #   password = 'shhhh'
  #   password.encrypt(:sha,
  #     :salt => lambda {Time.now.to_s},
  #     :builder => lambda {|data, salt| "#{data}|#{salt}"}
  #   )
  # 
  # The above example will generate a salt based on the current time and then
  # use a custom builder for determining how the salt and data get concatenated
  # to determine the value that gets hashed.  This is particularly useful for
  # providing compatibility with legacy systems.
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
      # The default algorithm to use for encryption.  Default is SHA1.
      attr_accessor :default_algorithm
      
      # The default salt value to use during encryption
      attr_accessor :default_salt
      
      # The default algorithm to use for building the value that gets hashed.
      # Default is lambda {|data, salt| "#{data}#{salt}"}.
      attr_accessor :default_builder
    end
    
    # Set defaults
    @default_algorithm = 'SHA1'
    @default_salt = 'salt'
    @default_builder = lambda {|data, salt| "#{data}#{salt}"}
    
    # The algorithm to use for encryption/decryption
    attr_accessor :algorithm
    
    # The salt value to use for encryption
    attr_accessor :salt
    
    # The function to use to build the value that gets hashed
    attr_accessor :builder
    
    # Creates a new cipher that uses an SHA encryption strategy.
    # 
    # Configuration options:
    # * <tt>:algorithm</tt> - The hashing algorithm to use for generating the
    #   encrypted string
    # * <tt>:salt</tt> - Specifies a method, proc or string to call to determine
    #   the random bytes used as one of the inputs for generating the encrypted
    #   string
    # * <tt>:builder</tt> - Specifies a method or proc to call to determine the
    #   actual value that gets hashed.  This takes two arguments: the data and
    #   the salt for the encryption.
    def initialize(options = {})
      invalid_options = options.keys - [:algorithm, :salt, :builder]
      raise ArgumentError, "Unknown key(s): #{invalid_options.join(", ")}" unless invalid_options.empty?
      
      options = {
        :algorithm => ShaCipher.default_algorithm,
        :salt => ShaCipher.default_salt,
        :builder => ShaCipher.default_builder
      }.merge(options)
      
      self.algorithm = options[:algorithm].upcase
      self.salt = salt_value(options[:salt])
      self.builder = options[:builder]
      
      super()
    end
    
    # Decryption is not supported
    def can_decrypt?
      false
    end
    
    # Returns the encrypted value of the data
    def encrypt(data)
      Digest::const_get(algorithm.upcase).hexdigest(build(data, salt))
    end
    
    private
      # Evaluates one of several different types of methods to determine the
      # value of the salt.  Methods can be one of the following types:
      # * Method / Proc
      # * String
      # * Object that responds to :salt
      def salt_value(value)
        if value.is_a?(Proc)
          value.call
        elsif value.respond_to?(:salt)
          value.salt
        else
          value.to_s
        end
      end
      
      # Builds the value to hash based on the data being encrypted and the salt
      # being used to seed the encryption algorithm
      def build(data, salt)
        if builder.is_a?(Proc)
          builder.call(data, salt)
        else
          builder.send(:build, data, salt)
        end
      end
  end
end
