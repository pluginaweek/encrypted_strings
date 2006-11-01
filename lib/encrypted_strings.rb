require 'openssl'
require 'base64'

require File.join('encrypted_strings', 'encrypted_string')
require File.join('encrypted_strings', 'symmetrically_encrypted_string')
require File.join('encrypted_strings', 'asymmetrically_encrypted_string')
require File.join('encrypted_strings', 'sha_encrypted_string')

module PluginAWeek #:nodoc:
  module CoreExtensions #:nodoc:
    module String #:nodoc:
      module EncryptedStrings
        def self.included(base) #:nodoc:
          base.class_eval do
            alias_method :equals_without_encryption, :==
            alias_method :==, :equals_with_encryption
          end
        end
        
        # Encrypts the current string using the encryption algorithm specified.
        # The default encryption mode is sha.
        # 
        # Configuration options are encryption-specified.  See the encryption
        # class for that string to find out the options available.
        #
        def encrypt(*args)
          options = args.last.is_a?(::Hash) ? args.pop : {}
          mode = (args.first || :sha).to_sym
          
          send("encrypt_#{mode}", options)
        end
        
        # Encrypts the string using an SHA algorithm
        # 
        def encrypt_sha(options = {})
          create_encrypted_string(SHAEncryptedString, options)
        end
        
        # Encrypts the string using an asymmetric algorithm
        #
        def encrypt_asymmetrically(options = {})
          create_encrypted_string(AsymmetricallyEncryptedString, options)
        end
        alias_method :encrypt_asymmetric, :encrypt_asymmetrically
        
        # Encrypts the string using a symmetric algorithm
        #
        def encrypt_symmetrically(options = {})
          create_encrypted_string(SymmetricallyEncryptedString, options)
        end
        alias_method :encrypt_symmetric, :encrypt_symmetrically
        
        # Adds support for testing equality with an encrypted string
        #
        def equals_with_encryption(other)
          if other.is_a?(EncryptedString) && self.class == ::String
            other == self
          else
            equals_without_encryption(other)
          end
        end
        
        private
        def create_encrypted_string(klass, options) #:nodoc:
          klass.new(self, options)
        end
      end
    end
  end
end

::String.class_eval do
  include PluginAWeek::CoreExtensions::String::EncryptedStrings
end