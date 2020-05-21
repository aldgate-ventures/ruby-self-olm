require 'base64'

module SelfCrypto

  class GroupMessage

    # @param msg [String] base64 or bytes
    def initialize(msg)
      @value = msg
    end

    # @return [String] bytes
    def to_bytes
      Base64.decode64(value)
    end

    # @return [String] base64
    def to_s
      @value.dup
    end

  end

end
