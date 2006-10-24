#
#
class SymmetricallyEncryptedString < EncryptedString
  #
  @@default_algorithm = 'DES-EDE3-CBC'
  cattr_accessor :default_algorithm
  
  #
  @@default_key = nil
  cattr_accessor :default_key
  
  attr_accessor :algorithm
  attr_accessor :key
  
  #
  #
  def initialize(data, options = {})
    options = options.symbolize_keys
    options.assert_valid_keys(
      :algorithm,
      :key,
      :encrypt
    )
    options.reverse_merge!(
      :algorithm => @@default_algorithm,
      :key => @@default_key,
      :encrypt => false
    )
    
    @key = options[:key]
    raise NoKeyError if @key.nil?
    
    @algorithm = options[:algorithm]
    
    super(options[:encrypt] ? encrypt(data) : data)
  end
  
  #
  #
  def decrypt
    des = encryptor
    des.decrypt(@key)
    text = des.update(Base64.decode64(to_s))
    text << des.final
  end
  
  private
  def encryptor #:nodoc:
    @encryptor ||= OpenSSL::Cipher::Cipher.new(@algorithm)
  end
  
  #
  #
  def encrypt(data)
    des = encryptor
    des.encrypt(@key)
    data = des.update(data)
    data << des.final
    
    Base64.encode64(data)
  end
end