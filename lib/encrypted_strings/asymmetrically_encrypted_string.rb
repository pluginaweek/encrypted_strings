# Encryption in which the keys used to encrypt/decrypt comin pairs.  Also known
# as public key encryption.  Anything that's encrypted using the public key can
# only be decrypted with the same algorithm and a matching private key.
# Any message that is encrypted with the private key can only be decrypted
# with the matching public key.
# 
# http://support.microsoft.com/kb/246071
#
class AsymmetricallyEncryptedString < EncryptedString
  # The default private key to use during encryption.  Default is nil.
  @@default_private_key_file = nil
  cattr_accessor :default_private_key_file
  
  # The default public key to use during encryption.  Default is nil.
  @@default_public_key_file = nil
  cattr_accessor :default_public_key_file
  
  # The default algorithm to use.  Default is nil.
  @@default_symmetric_algorithm = nil
  cattr_accessor :default_symmetric_algorithm
  
  attr_reader   :private_key_file
  attr_reader   :public_key_file
  attr_accessor :symmetric_algorithm
  attr_accessor :key
  
  # Configuration options:
  # * <tt>private_key_file</tt> - Encrypted private key file
  # * <tt>public_key_file</tt> - Public key file
  # * <tt>symmetric_algorithm</tt> - Algorithm to use symmetrically encrypted strings
  # * <tt>encrypt</tt> - Whether or not to encrypt the data.  Default is true.
  # This should usually only be set if the data is not yet encrypted.
  # 
  def initialize(data, options = {})
    options = options.symbolize_keys
    options.assert_valid_keys(
      :private_key_file,
      :public_key_file,
      :key,
      :symmetric_algorithm,
      :encrypt
    )
    options.reverse_merge!(
      :private_key_file => @@default_private_key_file,
      :public_key_file => @@default_public_key_file,
      :symmetric_algorithm => @@default_symmetric_algorithm
    )
    
    @public_key = @private_key = nil
    
    self.key = options[:key]
    self.private_key_file = options[:private_key_file]
    self.public_key_file  = options[:public_key_file]
    
    super
  end
  
  # Decrypts the current string
  # 
  def decrypt
    raise NoPrivateKeyError, "Private key file: #{@private_key_file}" unless private?
    
    data = Base64.decode64(to_s)
    private_rsa.private_decrypt(data)
  end
  
  # Sets the location of the private key and loads it
  # 
  def private_key_file=(file)
    @private_key_file = file and load_private_key
  end
  
  # Sets the location of the public key and loads it
  def public_key_file=(file)
    @public_key_file = file and load_public_key
  end
  
  # Is this string encrypted using a public key?
  # 
  def public?
    return true unless @public_key.nil?
    
    load_public_key
    !@public_key.nil?
  end
  
  # Is this string encrypted using a private key?
  # 
  def private?
    return true unless @private_key.nil?
    
    load_private_key
    !@private_key.nil?
  end
  
  private
  def encrypt_data(data) #:nodoc:
    raise NoPublicKeyError, "Public key file: #{@public_key_file}" unless public?
    
    data = public_rsa.public_encrypt(data)
    Base64.encode64(data)
  end
  
  def load_private_key #:nodoc:
    @private_rsa = nil
    
    if @private_key_file && File.file?(@private_key_file)
      @private_key = File.open(@private_key_file) {|f| f.read}
    end
  end
  
  def load_public_key #:nodoc:
    @public_rsa = nil
    
    if @public_key_file && File.file?(@public_key_file)
      @public_key = File.open(@public_key_file) {|f| f.read}
    end
  end
  
  # Retrieves private RSA from the encrypted private key
  # 
  def private_rsa #:nodoc:
    return @private_rsa ||= OpenSSL::PKey::RSA.new(@private_key) unless @key
    
    private_key = SymmetricallyEncryptedString.decrypt(@private_key, :key => @key, :algorithm => @algorithm)
    OpenSSL::PKey::RSA.new(private_key)
  end
  
  # Retrieves the public RSA
  # 
  def public_rsa #:nodoc:
    @public_rsa ||= OpenSSL::PKey::RSA.new(@public_key)
  end
end