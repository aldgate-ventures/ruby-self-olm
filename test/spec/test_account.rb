require 'minitest/autorun'
require 'minitest/reporters'
require 'self_crypto'

reporter_options = { color: true }
Minitest::Reporters.use! [Minitest::Reporters::DefaultReporter.new(reporter_options)]

describe "Account" do

  let(:account){ SelfCrypto::Account.new }

  # returns cached one-time-keys which have not yet been marked as published
  #
  describe "#otk" do

    it("returns a Hash"){ _(account.otk['curve25519']).must_be_kind_of Hash }

    describe "return value" do

      describe "before #gen_otk" do

        describe "before #mark_otk" do

          it("is empty"){ _(account.otk['curve25519'].size).must_equal 0 }

        end

        describe "after #mark_otk" do

          before{ account.mark_otk }

          it("is empty"){ _(account.otk['curve25519'].size).must_equal 0 }

        end

      end

      describe "after #gen_otk" do
        let(:n){ 100 }

        before{ account.gen_otk(n) }

        describe "before #mark_otk" do

          it("has n keys"){ _(account.otk['curve25519'].size).must_equal n }

        end

        describe "after #mark_otk" do

          before{ account.mark_otk }

          it("is empty"){ _(account.otk['curve25519'].size).must_equal 0 }

        end

      end

    end

  end

  # creates inbound and outbound sessions
  #
  describe "session factory" do

    let(:remote){ SelfCrypto::Account.new }

    before do
      remote.gen_otk
      account.gen_otk
    end

    describe "#outbound_session" do

      it("creates session") { _(account.outbound_session(remote.ik['curve25519'], remote.otk['curve25519'].values.first)).must_be_kind_of SelfCrypto::Session }

    end

    describe "#inbound_session" do

      let(:remote_session){ remote.outbound_session(account.ik['curve25519'], account.otk['curve25519'].values.first) }
      let(:remote_message){ remote_session.encrypt("hello") }

      it("creates session") { _(account.inbound_session(remote_message)).must_be_kind_of SelfCrypto::Session }

    end

    describe "#inbound_session from known remote" do

      let(:remote_session){ remote.outbound_session(account.ik['curve25519'], account.otk['curve25519'].values.first) }
      let(:remote_message){ remote_session.encrypt("hello") }

      it("creates session") { _(account.inbound_session(remote_message, remote.ik['curve25519'])).must_be_kind_of SelfCrypto::Session }

    end

    describe "#inbound_session from pickled account" do

      let(:remote_session){ remote.outbound_session(account.ik['curve25519'], account.otk['curve25519'].values.first) }
      let(:remote_message){ remote_session.encrypt("hello") }
      let(:pickled_account){ account.to_pickle("test") }
      let(:unpickled_account){ SelfCrypto::Account.from_pickle(pickled_account, "test") }
      it("creates session") { _(unpickled_account.inbound_session(remote_message, remote.ik['curve25519'])).must_be_kind_of SelfCrypto::Session }

    end

  end

end
