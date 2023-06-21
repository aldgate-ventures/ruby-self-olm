self-crypto-ruby
========

![Build Status](https://github.com/joinself/self-crypto-ruby/actions/workflows/ci.yml/badge.svg?branch=master)

Provides end to end group encryption using `self-olm`, a fork of [matrix](https://matrix.org/blog/home/)'s olm, and `self-omemo`

The original wrapper was forked from [ruby_olm](github.com/14mRh4X0r/ruby_olm)

## Installation

This gem requires selfs fork of olm (self-olm) and omemo (self-omemo) to be available before installing this gem.

The gem name is 'self_crypto'. The target
needs to be able to build native extensions.

Once installed, require as:

~~~ ruby
require 'self_crypto'
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

Setup alice's account:

~~~ruby
require 'file'
require 'self_crypto'

include SelfCrypto

# Setup alices account. This should be stored in memory for all communications

if File.exist?('account.pickle')
  # 1a) if alice's account file exists load the pickle from the file
  alice = Account.from_pickle(File.read('account.pickle'), STORAGE_KEY)
else
  # 1b-i) if create a new account for alice if one doesn't exist already
  alice = Account.from_seed(ALICES_IDENTITY_KEY)

  # 1b-ii) generate some keys for alice and publish them
  alice.gen_otk(100)

  # 1b-iii) convert those keys to json
  keys = alice.otk['curve25519'].map{|k,v| {id: k, type: v}}.to_json

  # 1b-iv) post those keys to POST /v1/identities/alice/devices/1/pre_keys/
  post('/v1/identities/alice/devices/1/pre_keys', keys)

  # 1b-v) store the account to a file
  File.write('account.pickle', alice.to_pickle(STORAGE_KEY))
end

~~~

Send a message from alice to bob:

~~~ruby
# Send a message to bob:1

if File.exist?('bob:1-session.pickle')
  # 2a) if bob's session file exists load the pickle from the file
  session_with_bob = Session.from_pickle(File.read('bob:1-session.pickle'), STORAGE_KEY)
else
  # 2b-i) if you have not previously sent or recevied a message to/from bob,
  #       you must get his identity key from GET /v1/identities/bob/
  ed25519_identity_key = JSON.parse(get('/v1/identities/bob/public_keys/')).first['key']

  # 2b-ii) get a one time key for bob
  one_time_key = JSON.parse(get('/v1/identities/bob/devices/1/pre_key'))['key']

  # 2b-iii) convert bobs ed25519 identity key to a curve25519 key
  curve25519_identity_key = Util.ed25519_pk_to_curve25519(ed25519_identity_key)

  # 2b-iv) create the session with bob
  session_with_bob = alice.outbound_session(curve25519_identity_key, one_time_key)

  # 2b-v) store the session to a file
  File.write('bob:1-session.pickle', session_with_bob.to_pickle(STORAGE_KEY))
end

# 3) create a group session and set the identity of the account youre using
ags = GroupSession.new('alice:1')

# 4) add all recipients and their sessions
ags.add_participant('bob:1', session_with_bob)

# 5) encrypt a message
ct = ags.encrypt('hello')

# 6) do something with the message
puts ct.to_s

~~~

Receive a message from carol:

~~~ruby
# Receive a message from carol:1

ct = "json encoded group message..."

if File.exist?('carol:1-session.pickle')
  # 7a) if carol's session file exists load the pickle from the file
  session_with_carol = Session.from_pickle(File.read('carol:1-session.pickle'), STORAGE_KEY)
else
  # 7b-i) if you have not previously sent or received a message to/from bob,
  #       you should extract the initial message from the group message intended
  #       for your account id.
  m = GroupMessage.new(ct.to_s).get_message('alice:1')

  # 7b-ii) use the initial message to create a session for carol
  session_with_carol = alice.inbound_session(m)

  # 7b-iii) store the session to a file
  File.write('carol:1-session.pickle', session_with_carol.to_pickle(STORAGE_KEY))
end

# 8) create a group session and set the identity of the account you're using
ags = GroupSession.new('alice:1')

# 9) add all recipients and their sessions
ags.add_participant('carol:1', session_with_carol)

# 10) decrypt the message ciphertext
pt = bgs.decrypt("alice:1", ct)

# 11) do something with the message
puts ct.to_s

~~~

## Running Tests

~~~ console
bundle exec rake test
~~~

## What is an Olm?

[https://en.wikipedia.org/wiki/Olm](https://en.wikipedia.org/wiki/Olm).

## License

Apache 2.0
