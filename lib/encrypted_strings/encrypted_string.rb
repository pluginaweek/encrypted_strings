#
#
class EncryptedString < String
  #
  #
  def ==(other)
    if other.class == String
      to_s == encrypt(other)
    else
      super
    end
  end
end