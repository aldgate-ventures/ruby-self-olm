require_relative './sas_data'

class SelfCrypto::SAS
  METHODS = %i[decimal emoji]

  def generate(method, info)
    method = method.to_sym
    raise ArgumentError, "Unknown SAS method: #{method}" unless METHODS.include? method

    send method, info
  end

  protected

  def decimal(info)
    bytes = generate_bytes(5, info)
    bits = bytes.unpack1('B39')
    grouped = bits.chars.each_slice(13).map &:join
    grouped.map {|s| s.to_i(2) + 1000}
  end

  def emoji(info)
    bytes = generate_bytes(6, info)
    bits = bytes.unpack1('B42')
    grouped = bits.chars.each_slice(6).map &:join
    grouped.map {|s| EMOJI_TABLE[s.to_i(2)]}.join
  end
end
