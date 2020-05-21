require 'base64'

module SelfCrypto

  class GroupMessage

    # @param msg [String] base64 or bytes
    def initialize(msg)
      @value = msg
      @data = JSON.parse(msg)
    end

    # @return [String] bytes
    def to_bytes
      Base64.decode64(value)
    end

    # @return [String] base64
    def to_s
      @value.dup
    end

    def get_message(identity)
      h = @data['recipients'][identity]
      if h['mtype'] == 0
        PreKeyMessage.new(h['ciphertext'])
      else
        Message.new(h['ciphertext'])
      end
    end

  end

end
