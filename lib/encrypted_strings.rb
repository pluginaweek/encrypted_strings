#Copyright (c) 2005 Rick Olson
#
#Permission is hereby granted, free of charge, to any person obtaining
#a copy of this software and associated documentation files (the
#"Software"), to deal in the Software without restriction, including
#without limitation the rights to use, copy, modify, merge, publish,
#distribute, sublicense, and/or sell copies of the Software, and to
#permit persons to whom the Software is furnished to do so, subject to
#the following conditions:
#
#The above copyright notice and this permission notice shall be
#included in all copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
#MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
#LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
#OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
#WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

require 'openssl'
require 'base64'

require File.join('encrypted_strings', 'core_ext', 'encrypted_string')
require File.join('encrypted_strings', 'core_ext', 'symmetrically_encrypted_string')
require File.join('encrypted_strings', 'core_ext', 'asymmetrically_encrypted_string')
require File.join('encrypted_strings', 'core_ext', 'sha_encrypted_string')

require File.join('encrypted_strings', 'active_record', 'encrypts')

class NoKeyError < StandardError
end

class NoPublicKeyError < StandardError
end

class NoPrivateKeyError < StandardError
end

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
        
        #
        #
        def encrypt(*args)
          options = args.last.is_a?(::Hash) ? args.pop : {}
          mode = (args.first || :sha).to_sym
          
          send("encrypt_#{mode}", options)
        end
        
        def encrypt_sha(options = {})
          create_encrypted_string(SHAEncryptedString, options)
        end
        
        #
        #
        def encrypt_asymmetrically(options = {})
          create_encrypted_string(AsymmetricallyEncryptedString, options)
        end
        alias_method :encrypt_asymmetric, :encrypt_asymmetrically
        
        #
        #
        def encrypt_symmetrically(options = {})
          create_encrypted_string(SymmetricallyEncryptedString, options)
        end
        alias_method :encrypt_symmetric, :encrypt_symmetrically
        
        #
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