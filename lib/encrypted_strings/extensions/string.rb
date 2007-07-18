require 'openssl'
require 'base64'

module PluginAWeek #:nodoc:
  module EncryptedStrings #:nodoc:
    module Extensions #:nodoc:
      module String
        def self.included(base) #:nodoc:
          base.class_eval do
            attr_accessor :encryptor
            
            alias_method :equals_without_encryption, :==
            alias_method :==, :equals_with_encryption
          end
        end
        
        # Encrypts this string and replaces it with the encrypted value
        def encrypt!(*args)
          encrypted_string = encrypt(*args)
          self.encryptor = encrypted_string.encryptor
          
          replace(encrypted_string)
        end
        
        # Encrypts the current string using the encryption algorithm specified.
        # The default encryption mode is sha.
        # 
        # Configuration options are encryption-specified.  See the encryptor
        # class for that string to find out the options available.
        def encrypt(*args)
          encryptor = encryptor_from_args(*args)
          encrypted_string = encryptor.encrypt(self)
          encrypted_string.encryptor = encryptor
          
          encrypted_string
        end
        
        # Is this string encrypted?
        def encrypted?
          !@encryptor.nil?
        end
        
        # Decrypts this string and replaces it with the decrypted value
        def decrypt!(*args)
          replace(decrypt(*args))
        end
        
        # Decrypts this string.  If this is not a string that was previously encrypted,
        # the encryption algorithm must be specified in the same way the
        # algorithm is specified when encrypting a string.
        def decrypt(*args)
          raise ArgumentError, "An encrypt algorithm must be specified since we can't figure it out" if args.empty? && !@encryptor
          
          encryptor = @encryptor || encryptor_from_args(*args)
          encryptor.decrypt(self)
        end
        
        # Can this string be decrypted?
        def can_decrypt?
          !@encryptor.nil? && @encryptor.can_decrypt?
        end
        
        # Tests whether the other object is equal to this one.  Encrypted strings
        # will be tested not only on their encrypted strings, but also by
        # decrypting them and running tests against the decrypted value
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