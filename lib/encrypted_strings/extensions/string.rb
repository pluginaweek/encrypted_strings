require 'openssl'
require 'base64'

module PluginAWeek #:nodoc:
  module EncryptedStrings
    module Extensions #:nodoc:
      # Adds support for encryption/decryption of strings
      module String
        def self.included(base) #:nodoc:
          base.class_eval do
            attr_accessor :encryptor
            
            alias_method :equals_without_encryption, :==
            alias_method :==, :equals_with_encryption
          end
        end
        
        # Encrypts the current string using the specified encryption mode.
        # The default encryption mode is sha.
        # 
        # Configuration options are encryption-specific.  See the encryptor
        # class for that mode to find out the options available.
        # 
        # == Example
        # 
        # The following uses SHA mode to encrypt the string:
        # 
        #   password = "shhhh"
        #   password.encrypt  # => "66c85d26dadde7e1db27e15a0776c921e27143bd"
        # 
        # == Custom encryption mode
        # 
        # The following uses Symmetric mode (with a default key) to encrypt the
        # string:
        # 
        #   PluginAWeek::EncryptedStrings::SymmetricEncryptor.default_key = "my_key"
        #   password = "shhhh"
        #   password.encrypt(:symmetric)  # => "jDACXI5hMPI=\n"
        # 
        # == Custom encryption options
        # 
        # Some encryption modes also support additional configuration options
        # that determine how to encrypt the string.  For example, SHA supports
        # a salt which seeds the algorithm:
        # 
        #   password = "shhhh"
        #   password.encrypt(:sha, :salt => "secret") # => "3b22cbe4acde873c3efc82681096f3ae69aff828"
        def encrypt(*args)
          encryptor = encryptor_from_args(*args)
          encrypted_string = encryptor.encrypt(self)
          encrypted_string.encryptor = encryptor
          
          encrypted_string
        end
        
        # Encrypts this string and replaces it with the encrypted value.  This
        # takes the same parameters as #encrypt, but returns the same string
        # instead of a different one.
        # 
        # For example,
        # 
        #   password = "shhhh"
        #   password.encrypt!(:symmetric, :key => "my_key") # => "jDACXI5hMPI=\n"
        #   password                                        # => "jDACXI5hMPI=\n"
        def encrypt!(*args)
          encrypted_string = encrypt(*args)
          self.encryptor = encrypted_string.encryptor
          
          replace(encrypted_string)
        end
        
        # Is this string encrypted?  This will return true if the string is the
        # result of a call to #encrypt or #encrypt! was previously invoked.
        # 
        # For example,
        # 
        #   password = "shhhh"
        #   password.encrypted? # => false
        #   password.encrypt!   # => "66c85d26dadde7e1db27e15a0776c921e27143bd"
        #   password.encrypted? # => true
        def encrypted?
          !@encryptor.nil?
        end
        
        # Decrypts this string.  If this is not a string that was previously encrypted,
        # the encryption algorithm must be specified in the same way the
        # algorithm is specified when encrypting a string.
        def decrypt(*args)
          raise ArgumentError, "An encrypt algorithm must be specified since we can't figure it out" if args.empty? && !@encryptor
          
          encryptor = args.any? ? encryptor_from_args(*args) : (@encryptor || encryptor_from_args(*args))
          encrypted_string = encryptor.decrypt(self)
          encrypted_string.encryptor = nil
          
          encrypted_string
        end
        
        # Decrypts this string and replaces it with the decrypted value  This
        # takes the same parameters as #decrypt, but returns the same string
        # instead of a different one.
        # 
        # For example,
        # 
        #   password = "jDACXI5hMPI=\n"
        #   password.decrypt!(:symmetric, :key => "my_key") # => "shhhh"
        #   password                                        # => "shhhh"
        def decrypt!(*args)
          replace(decrypt(*args))
        end
        
        # Can this string be decrypted?  Strings can only be decrypted if they
        # have previously been decrypted +and+ the encryption algorithm supports
        # decryption.  To determine whether or not the encryption algorithm
        # supports decryption, see the api for the algorithm's encryptor class.
        def can_decrypt?
          encrypted? && @encryptor.can_decrypt?
        end
        
        # Tests whether the other object is equal to this one.  Encrypted strings
        # will be tested not only on their encrypted strings, but also by
        # decrypting them and running tests against the decrypted value.
        # 
        # == Equality with strings
        # 
        #   password = "shhhh"
        #   password.encrypt!   # => "66c85d26dadde7e1db27e15a0776c921e27143bd"
        #   password            # => "66c85d26dadde7e1db27e15a0776c921e27143bd"
        #   password == "shhhh" # => true
        # 
        # == Equality with encrypted strings
        # 
        #   password = "shhhh"
        #   password.encrypt!             # => "66c85d26dadde7e1db27e15a0776c921e27143bd"
        #   password                      # => "66c85d26dadde7e1db27e15a0776c921e27143bd"
        #   password == "shhhh"           # => true
        #   
        #   another_password = "shhhh"
        #   another_password.encrypt!     # => "66c85d26dadde7e1db27e15a0776c921e27143bd"
        #   password == another_password  # => true
        def equals_with_encryption(other)
          if !(is_equal = equals_without_encryption(other)) && String === other
            if encrypted?
              if other.encrypted?
                is_string_equal?(self, other) || is_string_equal?(other, self) || self.can_decrypt? && is_string_equal?(self.decrypt, other) || other.can_decrypt? && is_string_equal?(other.decrypt, self)
              else
                is_string_equal?(other, self)
              end
            else
              if other.encrypted?
                is_string_equal?(self, other)
              else
                false
              end
            end
          else
            is_equal
          end
        end
        
        private
        def is_string_equal?(value, encrypted_value) #:nodoc:
          if encrypted_value.can_decrypt?
            encrypted_value.decrypt.equals_without_encryption(value)
          else
            encrypted_value.equals_without_encryption(encrypted_value.encryptor.encrypt(value))
          end
        end
        
        def encryptor_from_args(*args) #:nodoc:
          options = args.last.is_a?(::Hash) ? args.pop : {}
          mode = (args.first || :sha).to_sym
          "PluginAWeek::EncryptedStrings::#{mode.to_s.classify}Encryptor".constantize.new(options)
        end
      end
    end
  end
end

::String.class_eval do
  include PluginAWeek::EncryptedStrings::Extensions::String
end
