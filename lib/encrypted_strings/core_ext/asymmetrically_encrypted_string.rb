#
#
class AsymmetricallyEncryptedString < EncryptedString
  #
  cattr_accessor :default_private_key_file
  @@default_private_key_file = nil
  
  #
  cattr_accessor :default_public_key_file
  @@default_public_key_file = nil
  
  #
  cattr_accessor :default_symmetric_algorithm
  @@default_symmetric_algorithm = nil
  
  attr_reader   :private_key_file
  attr_reader   :public_key_file
  attr_accessor :symmetric_algorithm
  
  # Configuration options:
  # * <tt>private_key_file</tt> - encrypted private key file
  # * <tt>public_key_file</tt>  - public key file
  # * <tt>symmetric_algorithm</tt> - algorithm to use for SymmetricSentry
  # 
  def initialize(data, options = {})
    options = options.symbolize_keys
    options.assert_valid_keys(
      :private_key_file,
      :public_key_file,
      :symmetric_algorithm,
      :encrypt
    )
    options.reverse_merge!(
      :private_key_file => @@default_private_key_file,
      :public_key_file => @@default_public_key_file,
      :symmetric_algorithm => @@default_symmetric_algorithm,
      :encrypt => true
    )
    
    @public_key = @private_key = nil
    private_key_file = options[:private_key_file]
    public_key_file  = options[:public_key_file]
    
    super(encrypt(data))
  end
  
  def decrypt
    raise NoPrivateKeyError unless private?
    
    data = Base64.decode64(to_s)
    private_rsa(@key).private_decrypt(data)
  end
  
  def private_key_file=(file)
    @private_key_file = file and load_private_key
  end
  
  def public_key_file=(file)
    @public_key_file = file and load_public_key
  end
  
  # Is this string encrypted using a public key?
  def public?
    return true unless @public_key.nil?
    load_public_key and return @public_key
  end
  
  # Is this string encrypted using a private key?
  def private?
    return true unless @private_key.nil?
    load_private_key and return @private_key
  end
  
  private
  def encryptor
    @encryptor ||= SymmetricSentry.new(:algorithm => @symmetric_algorithm)
  end
  
  def encrypt(data)
    raise NoPublicKeyError unless public?
    
    data = public_rsa.public_encrypt(data)
    Base64.encode64(data)
  end
  
  def load_private_key #:nodoc:
    @private_rsa = nil
    @private_key_file ||= @@default_private_key_file
    if @private_key_file and File.file?(@private_key_file)
      @private_key = File.open(@private_key_file) { |f| f.read }
    end
  end
  
  def load_public_key #:nodoc:
    @public_rsa = nil
    @public_key_file ||= @@default_public_key_file
    if @public_key_file and File.file?(@public_key_file)
      @public_key = File.open(@public_key_file) { |f| f.read }
    end
  end
  
  # retrieves private rsa from encrypted private key
  def private_rsa(key = nil)
    return @private_rsa ||= OpenSSL::PKey::RSA.new(@private_key) unless key
    OpenSSL::PKey::RSA.new(encryptor.decrypt_from_base64(@private_key, key))
  end
  
  # retrieves public rsa
  def public_rsa
    @public_rsa ||= OpenSSL::PKey::RSA.new(@public_key)
  end
end