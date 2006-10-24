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

require File.join('encrypted_strings', 'encrypted_string')
require File.join('encrypted_strings', 'symmetrically_encrypted_string')
require File.join('encrypted_strings', 'asymmetrically_encrypted_string')
require File.join('encrypted_strings', 'sha_encrypted_string')

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
        #
        #
        def encrypt(mode = :sha, options = {})
          options[:encrypt] = true
          
          case mode
            when :sha
              SHAEncryptedString.new(self, options)
            when :asymmetric, :asymmetrical
              AsymmetricallyEncryptedString(self, options)
            when :symmetric, :symmetrical
              SymmetricallyEncryptedString.new(self, options)
            else
              raise ArgumentError, "Invalid encryption mode: #{mode}"
          end
        end
      end
    end
  end
  
  module Encrypts #:nodoc:
    def self.included(base) #:nodoc:
      base.extend(MacroMethods)
    end
    
    module MacroMethods
      #
      #
      def encrypts(attr_name, options = {})
        options.reverse_merge!(
          :mode => :sha
        )
        
        klass = case options.delete(:mode)
          when :sha
            SHAEncryptedString
          when :asymmetric, :asymmetrically
            AsymmetricallyEncryptedString
          when :symmetric, :symmetrically
            SymmetricallyEncryptedString
        end
        
        var_name = "@#{attr_name}"
        
        # Define the reader
        reader_options = options.dup
        reader_options[:encrypt] = false
        define_method(attr_name) do
          if (data = read_attribute(attr_name)) && !data.is_a?(klass)
            data = instance_variable_get(var_name) || instance_variable_set(var_name, klass.new(data, reader_options))
          end
          
          data
        end
        
        # Define the writer
        define_method("#{attr_name}=") do |data|
          unless data.is_a?(EncryptedString)
            data = klass.new(data, options)
          end
          
          write_attribute(attr_name, data)
          instance_variable_set(var_name, klass.new(data, options))
        end
      end
    end
  end
end
