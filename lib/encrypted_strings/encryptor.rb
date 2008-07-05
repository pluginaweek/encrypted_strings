module PluginAWeek #:nodoc:
  module EncryptedStrings
    # Represents the base class for all encryptors.  By default, all encryptors
    # are assumed to be able to decrypt strings.  Note, however, that certain
    # encryption algorithms do not allow decryption.
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
