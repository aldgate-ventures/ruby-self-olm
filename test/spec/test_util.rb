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

end
