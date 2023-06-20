module SelfCrypto

  class Session

    # @param pickle [String] pickled state
    # @param password [String] password used to encrypt pickled state
    # @return [Session]
    def self.from_pickle(pickle, password="")
      Session.new(pickle, password)
    end

  end

end
