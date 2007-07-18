module PluginAWeek #:nodoc:
  module EncryptedStrings #:nodoc:
    # Represents an encryptor for strings.  Certain encryption algorithms
    # do not allow for strings to be decrypted.
    class Encryptor
      # Can this string be decrypted?
      def can_decrypt?
        true
      end
      
      # By default, decryption is not supported
      def decrypt(data)
        raise NotImplementedError, "Decryption is not supported using a(n) #{self.class.name}"
      end
    end
  end
end