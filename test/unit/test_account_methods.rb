require 'minitest/autorun'
require 'self_olm'

class TestAccount < Minitest::Test

  include SelfOlm

  def setup
    @state = Account.new
  end

  def test_identity_keys
    assert_instance_of Hash, @state.identity_keys
  end

  def test_one_time_keys
    assert_instance_of Hash, @state.one_time_keys
  end

  def test_generate_one_time_keys
    assert_equal @state, @state.generate_one_time_keys(rand(1..10))
  end

  def test_last_error
    assert_equal OlmError::SUCCESS, @state.last_error
  end

  def test_sign
    assert_instance_of String, @state.sign("hello")
  end

  def test_mark_keys_as_published
    assert_equal @state, @state.mark_keys_as_published
  end

  def test_max_number_of_one_time_keys
    assert_kind_of Integer, @state.max_number_of_one_time_keys
  end

  def test_to_pickle
    assert_kind_of String, @state.to_pickle
  end

  def test_from_pickle
    Account.from_pickle(@state.to_pickle)
  end

  def test_from_pickle_with_key
    Account.from_pickle(@state.to_pickle("hey"), "hey")
  end

  def test_from_pickle_invalid
    assert_raises OlmError::BAD_ACCOUNT_KEY do
      Account.from_pickle("")
    end
  end

  def test_from_pickle_bad_key
    assert_raises OlmError::BAD_ACCOUNT_KEY do
      Account.from_pickle(@state.to_pickle, "hey")
    end
  end

end
