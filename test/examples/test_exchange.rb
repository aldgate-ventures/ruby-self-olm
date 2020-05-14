require 'minitest/autorun'
require 'self_olm'

class TestExchange < Minitest::Test

  include SelfOlm

  # Alice -> Bob
  # Alice <- Bob
  def test_exchange

    alice = Account.new
    bob = Account.new

    # Alice wants to send a message to Bob
    alice_msg = "hi bob"

    # Bob generates a one-time-key
    bob.gen_otk

    # Alice must have Bob's identity and one-time-key to make a session
    alice_session = alice.outbound_session(bob.ik['curve25519'], bob.otk['curve25519'].values.first)

    # Bob marks all one-time-keys as published
    bob.mark_otk

    # Alice can encrypt
    encrypted = alice_session.encrypt(alice_msg)
    assert_instance_of PreKeyMessage, encrypted

    # Bob can create a session from this first message
    bob_session = bob.inbound_session(encrypted)

    # Bob can now update his list of marked otk (since he knows one has been used)
    bob.update_otk(bob_session)

    # Bob can decrypt Alice's message
    bob_msg = bob_session.decrypt(encrypted)

    assert_equal alice_msg, bob_msg

    # At this point Bob has received but Alice hasn't
    assert bob_session.has_received?
    refute alice_session.has_received?

    ####

    # Bob can send messages back to Alice
    bob_msg = "hi alice"

    encrypted = bob_session.encrypt(bob_msg)
    assert_instance_of Message, encrypted

    alice_msg = alice_session.decrypt(encrypted)

    assert_equal alice_msg, bob_msg

  end

end
