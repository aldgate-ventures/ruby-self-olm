require 'minitest/autorun'
require 'minitest/reporters'
require 'self_crypto'

reporter_options = { color: true }
Minitest::Reporters.use! [Minitest::Reporters::DefaultReporter.new(reporter_options)]

describe "Util" do

  describe "ed25519_pk_to_curve25519" do
    account = SelfCrypto::Account.from_seed("pA0H92i1hsp1/egmS/tuEho5PpsAaQYrBd0Tj7bvAPI")
    ed25519_pk = Base64.urlsafe_encode64(Base64.decode64(account.ik['ed25519']), padding: false)
    curve25519_pk = SelfCrypto::Util.ed25519_pk_to_curve25519(ed25519_pk)
    it("should convert"){ _(account.ik['curve25519']).must_equal curve25519_pk }
  end

  describe "xchacha20_poly1305_itef" do
    message = "something"

    key = SelfCrypto::Util.aead_xchacha20poly1305_ietf_keygen
    nonce = SelfCrypto::Util.aead_xchacha20poly1305_ietf_nonce

    ct = SelfCrypto::Util.aead_xchacha20poly1305_ietf_encrypt(key, nonce, message)
    pt = SelfCrypto::Util.aead_xchacha20poly1305_ietf_decrypt(key, nonce, ct)

    it('should decrypt'){ _(pt).must_equal message}
  end

end
