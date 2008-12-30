module EncryptedStrings
  module Extensions #:nodoc:
    # Adds support for in-place encryption/decryption of strings
    module String
      def self.included(base) #:nodoc:
        base.class_eval do
          attr_accessor :cipher
          
          alias_method :equals_without_encryption, :==
          alias_method :==, :equals_with_encryption
        end
      end
      
      # Encrypts the current string using the specified cipher.  The default
      # cipher is sha.
      # 
      # Configuration options are cipher-specific.  See each individual cipher
      # class to find out the options available.
      # 
      # == Example
      # 
      # The following uses an SHA cipher to encrypt the string:
      # 
      #   password = 'shhhh'
      #   password.encrypt  # => "66c85d26dadde7e1db27e15a0776c921e27143bd"
      # 
      # == Custom encryption mode
      # 
      # The following uses Symmetric cipher (with a default password) to
      # encrypt the string:
      # 
      #   EncryptedStrings::SymmetricCipher.default_password = 'secret'
      #   password = 'shhhh'
      #   password.encrypt(:symmetric)  # => "jDACXI5hMPI=\n"
      # 
      # == Custom encryption options
      # 
      # Some encryption modes also support additional configuration options
      # that determine how to encrypt the string.  For example, SHA supports
      # a salt which seeds the algorithm:
      # 
      #   password = 'shhhh'
      #   password.encrypt(:sha, :salt => 'secret') # => "3b22cbe4acde873c3efc82681096f3ae69aff828"
      def encrypt(*args)
        cipher = cipher_from_args(*args)
        encrypted_string = cipher.encrypt(self)
        encrypted_string.cipher = cipher
        
        encrypted_string
      end
      
      # Encrypts this string and replaces it with the encrypted value.  This
      # takes the same parameters as #encrypt, but returns the same string
      # instead of a different one.
      # 
      # == Example
      # 
      #   password = 'shhhh'
      #   password.encrypt!(:symmetric, :password => 'secret')  # => "qSg8vOo6QfU=\n"
      #   password                                              # => "qSg8vOo6QfU=\n"
      def encrypt!(*args)
        encrypted_string = encrypt(*args)
        self.cipher = encrypted_string.cipher
        
        replace(encrypted_string)
      end
      
      # Is this string encrypted?  This will return true if the string is the
      # result of a call to #encrypt or #encrypt!.
      # 
      # == Example
      # 
      #   password = 'shhhh'
      #   password.encrypted? # => false
      #   password.encrypt!   # => "66c85d26dadde7e1db27e15a0776c921e27143bd"
      #   password.encrypted? # => true
      def encrypted?
        !cipher.nil?
      end
      
      # Decrypts this string.  If this is not a string that was previously
      # encrypted, the cipher must be specified in the same way that it is
      # when encrypting a string.
      # 
      # == Example
      # 
      # Without being previously encrypted:
      # 
      #   password = "qSg8vOo6QfU=\n"
      #   password.decrypt(:symmetric, :password => 'secret')   # => "shhhh"
      # 
      # After being previously encrypted:
      # 
      #   password = 'shhhh'
      #   password.encrypt!(:symmetric, :password => 'secret')  # => "qSg8vOo6QfU=\n"
      #   password.decrypt                                      # => "shhhh"
      def decrypt(*args)
        raise ArgumentError, 'Cipher cannot be inferred: must specify it as an argument' if args.empty? && !encrypted?
        
        cipher = args.empty? && self.cipher || cipher_from_args(*args)
        encrypted_string = cipher.decrypt(self)
        encrypted_string.cipher = nil
        
        encrypted_string
      end
      
      # Decrypts this string and replaces it with the decrypted value  This
      # takes the same parameters as #decrypt, but returns the same string
      # instead of a different one.
      # 
      # For example,
      # 
      #   password = "qSg8vOo6QfU=\n"
      #   password.decrypt!(:symmetric, :password => 'secret')  # => "shhhh"
      #   password                                              # => "shhhh"
      def decrypt!(*args)
        value = replace(decrypt(*args))
        self.cipher = nil
        value
      end
      
      # Can this string be decrypted?  Strings can only be decrypted if they
      # have previously been decrypted *and* the cipher supports decryption.
      # To determine whether or not the cipher supports decryption, see the
      # api for the cipher.
      def can_decrypt?
        encrypted? && cipher.can_decrypt?
      end
      
      # Tests whether the other object is equal to this one.  Encrypted strings
      # will be tested not only on their encrypted strings, but also by
      # decrypting them and running tests against the decrypted value.
      # 
      # == Equality with strings
      # 
      #   password = 'shhhh'
      #   password.encrypt!   # => "66c85d26dadde7e1db27e15a0776c921e27143bd"
      #   password            # => "66c85d26dadde7e1db27e15a0776c921e27143bd"
      #   password == "shhhh" # => true
      # 
      # == Equality with encrypted strings
      # 
      #   password = 'shhhh'
      #   password.encrypt!             # => "66c85d26dadde7e1db27e15a0776c921e27143bd"
      #   password                      # => "66c85d26dadde7e1db27e15a0776c921e27143bd"
      #   password == 'shhhh'           # => true
      #   
      #   another_password = 'shhhh'
      #   another_password.encrypt!     # => "66c85d26dadde7e1db27e15a0776c921e27143bd"
      #   password == another_password  # => true
      def equals_with_encryption(other)
        if !(is_equal = equals_without_encryption(other)) && String === other
          if encrypted?
            if other.encrypted?
              # We're both encrypted, so check if:
              # (1) The other string is the encrypted value of this string
              # (2) This string is the encrypted value of the other string
              # (3) The other string is the encrypted value of this string, decrypted
              # (4) This string is the encrypted value of the other string, decrypted
              is_string_equal?(self, other) || is_string_equal?(other, self) || self.can_decrypt? && is_string_equal?(self.decrypt, other) || other.can_decrypt? && is_string_equal?(other.decrypt, self)
            else
              # Only we're encrypted
              is_string_equal?(other, self)
            end
          else
            if other.encrypted?
              # Only the other string is encrypted
              is_string_equal?(self, other)
            else
              # Neither are encrypted and equality test didn't work before, so
              # they can't be equal
              false
            end
          end
        else
          # The other value wasn't a string, so we can't check encryption equality
          is_equal
        end
      end
      
      private
        def is_string_equal?(value, encrypted_value) #:nodoc:
          # If the encrypted value can be decrypted, then test against the decrypted value
          if encrypted_value.can_decrypt?
            encrypted_value.decrypt.equals_without_encryption(value)
          else
            # Otherwise encrypt this value based on the cipher used on the encrypted value
            # and test the equality of those strings
            encrypted_value.equals_without_encryption(encrypted_value.cipher.encrypt(value))
          end
        end
        
        # Builds the cipher to use from the given arguments
        def cipher_from_args(*args) #:nodoc:
          options = args.last.is_a?(Hash) ? args.pop : {}
          name = (args.first || :sha).to_s.gsub(/(?:^|_)(.)/) {$1.upcase}
          EncryptedStrings.const_get("#{name}Cipher").new(options)
        end
    end
  end
end

::String.class_eval do
  include EncryptedStrings::Extensions::String
end
