module PluginAWeek #:nodoc:
  module EncryptedStrings
    # Represents an encryptor for strings.  Certain encryption algorithms
    # do not allow for strings to be decrypted.
    class Encryptor
      # Can this string be decrypted?  Default is true.
      def can_decrypt?
        true
      end
      
      # Attempts to decrypt the given data using the current configuration.  By
      # default, decryption is not implemented.
      def decrypt(data)
        raise NotImplementedError, "Decryption is not supported using a(n) #{self.class.name}"
      end
    end
  end
end
