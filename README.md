ruby_olm
========

A Ruby wrapper for self's fork of olm, a double ratchet implementation from [matrix](https://matrix.org/blog/home/).

## Installation

This gem requires selfs fork of olm to be available before installing this gem.

The gem name is 'self_olm'. The target
needs to be able to build native extensions.

Once installed, require as:

~~~ ruby
require 'self_olm'
~~~

If using locally (i.e. you check out this repository) you may
need to manually compile and clean the extensions like this:

~~~ console
bundle exec rake compile
bundle exec rake clean
~~~

## Characteristics

- Interfaces are not thread safe
- Olm always encodes binary as base64
- Account is unlikely to scale for a large number of one-time-keys

## Example

Alice wants to send a message to Bob:

~~~ ruby
require 'self_olm'

include SelfOlm

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

# Bob can send messages back to Alice    
bob_msg = "hi alice"

encrypted = bob_session.encrypt(bob_msg)
assert_instance_of Message, encrypted

alice_msg = alice_session.decrypt(encrypted)

assert_equal alice_msg, bob_msg
~~~

Account and Session instances can be serialised and deserialised
using the `#to_pickle` and `::from_pickle` methods. This is handy
for saving and restoring state:

~~~ ruby
# save
alice_saved_account = Alice.to_pickle
alice_saved_session = alice_session.to_pickle

# restore
Account.from_pickle(alice_saved_account)
Session.from_pickle(alice_saved_session)
~~~

## Running Tests

~~~ console
bundle exec rake test
~~~

## What is an Olm?

[https://en.wikipedia.org/wiki/Olm](https://en.wikipedia.org/wiki/Olm).

## License

Apache 2.0
