#include "self_omemo.h"
#include "self_crypto.h"

static VALUE last_error(VALUE self) {
    OlmSession * this;
    Data_Get_Struct(self, OlmSession, this);

    return rb_str_new2(self_olm_session_last_error(this));
}

static VALUE initialize(int argc, VALUE * argv, VALUE self) {
    VALUE pickle, password;
    OlmSession * this;
    Data_Get_Struct(self, OlmSession, this);

    (void) rb_scan_args(argc, argv, "11", & pickle, & password);

    if (rb_obj_is_kind_of(pickle, rb_cString) != Qtrue) {
        rb_raise(rb_eTypeError, "pickle must be kind of String");
    }

    if (password != Qnil) {
        if (rb_obj_is_kind_of(password, rb_cString) != Qtrue) {
            rb_raise(rb_eTypeError, "password must be kind of String");
        }
    } else {
        password = rb_str_new2("");
    }

    if (self_olm_unpickle_session(this, RSTRING_PTR(password), RSTRING_LEN(password), RSTRING_PTR(dup_string(pickle)), RSTRING_LEN(pickle)) == -1) {
        raise_olm_error(self_olm_session_last_error(this));
    }

    return self;
}

static VALUE initialize_outbound(VALUE self, VALUE account, VALUE identity, VALUE one_time_key) {
    size_t size;
    OlmSession * this;
    OlmAccount * a;

    Data_Get_Struct(self, OlmSession, this);
    Data_Get_Struct(account, OlmAccount, a);

    size = self_olm_create_outbound_session_random_length(this);

    if (rb_obj_is_instance_of(account, rb_eval_string("SelfCrypto::Account")) != Qtrue) {
        rb_raise(rb_eTypeError, "account must be an instance of SelfCrypto::Account");
    }
    if (rb_obj_is_kind_of(identity, rb_eval_string("String")) != Qtrue) {
        rb_raise(rb_eTypeError, "identity must be kind of String");
    }
    if (rb_obj_is_kind_of(one_time_key, rb_eval_string("String")) != Qtrue) {
        rb_raise(rb_eTypeError, "one_time_key must be kind of String");
    }

    if (self_olm_create_outbound_session(
            this,
            a,
            RSTRING_PTR(identity), RSTRING_LEN(identity),
            RSTRING_PTR(one_time_key), RSTRING_LEN(one_time_key),
            RSTRING_PTR(get_random(size)), size
        ) == -1) {
        raise_olm_error(self_olm_session_last_error(this));
    }

    return self;
}

static VALUE initialize_inbound(int argc, VALUE * argv, VALUE self) {
    VALUE account, one_time_message, identity;

    identity = Qnil;

    (void) rb_scan_args(argc, argv, "21", & account, & one_time_message, & identity);

    OlmSession * this;
    Data_Get_Struct(self, OlmSession, this);

    OlmAccount * a;
    Data_Get_Struct(account, OlmAccount, a);

    if (rb_obj_is_kind_of(one_time_message, rb_eval_string("SelfCrypto::PreKeyMessage")) != Qtrue) {
        rb_raise(rb_eTypeError, "one_time_message must be kind of PreKeyMessage");
    }

    one_time_message = rb_funcall(one_time_message, rb_intern("to_s"), 0);

    if (identity == Qnil) {
        if (self_olm_create_inbound_session(this, a,
                RSTRING_PTR(dup_string(one_time_message)), RSTRING_LEN(one_time_message)
            ) == -1) {
            raise_olm_error(self_olm_session_last_error(this));
        }
    } else {
        if (self_olm_create_inbound_session_from(this, a,
                RSTRING_PTR(identity), RSTRING_LEN(identity),
                RSTRING_PTR(dup_string(one_time_message)), RSTRING_LEN(one_time_message)
            ) == -1) {
            raise_olm_error(self_olm_session_last_error(this));
        }
    }

    return self;
}

static VALUE will_receive(int argc, VALUE * argv, VALUE self) {
    VALUE one_time_message, identity;
    size_t result;
    OlmSession * this;
    Data_Get_Struct(self, OlmSession, this);

    identity = Qnil;

    (void) rb_scan_args(argc, argv, "11", & one_time_message, & identity);

    if (rb_obj_is_kind_of(one_time_message, rb_eval_string("SelfCrypto::PreKeyMessage")) != Qtrue) {
        rb_raise(rb_eTypeError, "one_time_message must be kind of PreKeyMessage");
    }

    one_time_message = rb_funcall(one_time_message, rb_intern("to_s"), 0);

    if (identity == Qnil) {
        result = self_olm_matches_inbound_session(this,
            RSTRING_PTR(dup_string(one_time_message)), RSTRING_LEN(one_time_message)
        );
    } else {
        result = self_olm_matches_inbound_session_from(this,
            RSTRING_PTR(identity), RSTRING_LEN(identity),
            RSTRING_PTR(dup_string(one_time_message)), RSTRING_LEN(one_time_message)
        );
    }

    if (result == -1) {

        raise_olm_error(self_olm_session_last_error(this));
    }

    return (result == 1) ? Qtrue : Qfalse;
}

static VALUE message_type(VALUE self) {
    OlmSession * this;
    VALUE retval;
    Data_Get_Struct(self, OlmSession, this);

    if (self_olm_encrypt_message_type(this) == 0) {
        retval = rb_eval_string("SelfCrypto::PreKeyMessage");
    } else if (self_olm_encrypt_message_type(this) == 1) {
        retval = rb_eval_string("SelfCrypto::Message");
    } else {
        rb_bug("olm_encrypt_message_type()");
    }

    return retval;
}

static VALUE to_pickle(int argc, VALUE * argv, VALUE self) {
    VALUE password, retval;
    OlmSession * this;
    void * ptr;
    size_t size;
    Data_Get_Struct(self, OlmSession, this);

    (void) rb_scan_args(argc, argv, "01", & password);

    password = (password == Qnil) ? rb_str_new2("") : password;

    size = self_olm_pickle_session_length(this);

    if ((ptr = malloc(size)) == NULL) {

        rb_raise(rb_eNoMemError, "%s()", __FUNCTION__);
    }

    if (self_olm_pickle_session(this, RSTRING_PTR(password), RSTRING_LEN(password), ptr, size) != size) {

        free(ptr);
        raise_olm_error(self_olm_session_last_error(this));
    }

    retval = rb_str_new(ptr, size);

    free(ptr);

    return retval;
}

static void _free(void * ptr) {
    free(ptr);
}

static VALUE _alloc(VALUE klass) {
    void *session_buf = calloc(1, self_olm_session_size());
    OlmSession *session = self_olm_session(session_buf);

    return Data_Wrap_Struct(klass, 0, _free, session);
}

void session_init(void) {
    VALUE cRubyOLM = rb_define_module("SelfCrypto");
    VALUE cSession = rb_define_class_under(cRubyOLM, "Session", rb_cObject);
    VALUE cSessionOut = rb_define_class_under(cRubyOLM, "OutboundSession", cSession);
    VALUE cSessionIn = rb_define_class_under(cRubyOLM, "InboundSession", cSession);

    rb_define_alloc_func(cSession, _alloc);

    rb_define_method(cSessionOut, "initialize", initialize_outbound, 3);
    rb_define_method(cSessionIn, "initialize", initialize_inbound, -1);

    rb_define_method(cSession, "initialize", initialize, -1);
    rb_define_method(cSession, "last_error", last_error, 0);
    rb_define_method(cSession, "to_pickle", to_pickle, -1);
    rb_define_method(cSession, "will_receive?", will_receive, -1);
}