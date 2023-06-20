// Copyright 2020 Self Group Ltd. All Rights Reserved.

#include "self_omemo.h"
#include "self_crypto.h"

static VALUE initialize(int argc, VALUE * argv, VALUE self) {
    VALUE identity;
    GroupSession * this;

    Data_Get_Struct(self, GroupSession, this);

    (void) rb_scan_args(argc, argv, "1", & identity);

    if (identity != Qnil) {
        if (rb_obj_is_kind_of(identity, rb_cString) != Qtrue) {
            rb_raise(rb_eTypeError, "identity must be kind of String");
        }
    }

    self_omemo_set_identity(this, RSTRING_PTR(identity));

    return self;
}

static VALUE add_participant(VALUE self, VALUE identity, VALUE session) {
    GroupSession * this;
    OlmSession * s;

    Data_Get_Struct(self, GroupSession, this);
    Data_Get_Struct(session, OlmSession, s);

    if (rb_obj_is_kind_of(identity, rb_eval_string("String")) != Qtrue) {
        rb_raise(rb_eTypeError, "identity must be kind of String");
    }

    if (
        rb_obj_is_instance_of(session, rb_eval_string("SelfCrypto::Session")) != Qtrue &&
        rb_obj_is_instance_of(session, rb_eval_string("SelfCrypto::InboundSession")) != Qtrue &&
        rb_obj_is_instance_of(session, rb_eval_string("SelfCrypto::OutboundSession")) != Qtrue
    ) {
        rb_raise(rb_eTypeError, "session must be an instance of SelfCrypto::Session, SelfCrypto::InboundSession or SelfCrypto::OutboundSession");
    }

    self_omemo_add_group_participant(this, RSTRING_PTR(identity), s);

    return identity;
}

static VALUE group_encrypt(VALUE self, VALUE plaintext) {
    GroupSession * this;
    VALUE ciphertext;
    void * ptr;
    size_t ciphertext_sz;

    Data_Get_Struct(self, GroupSession, this);

    if (rb_obj_is_kind_of(plaintext, rb_eval_string("String")) != Qtrue) {
        rb_raise(rb_eTypeError, "plaintext must be kind of String");
    }

    ciphertext_sz = self_omemo_encrypted_size(this, RSTRING_LEN(plaintext));

    if (ciphertext_sz == 0) {
        rb_raise(rb_eTypeError, "could not get size of encrypted message");
    }

    if ((ptr = malloc(ciphertext_sz)) == NULL) {
        rb_raise(rb_eNoMemError, "%s()", __FUNCTION__);
    }

    ciphertext_sz = self_omemo_encrypt(
        this,
        RSTRING_PTR(plaintext),
        RSTRING_LEN(plaintext),
        ptr,
        ciphertext_sz
    );

    if (ciphertext_sz == 0) {
        free(ptr);
        rb_raise(rb_eTypeError, "failed to encrypt");
    }

    ciphertext = rb_funcall(rb_eval_string("SelfCrypto::GroupMessage"), rb_intern("new"), 1, rb_str_new(ptr, ciphertext_sz));

    free(ptr);

    return ciphertext;
}

static VALUE group_decrypt(VALUE self, VALUE sender, VALUE ciphertext) {
    GroupSession * this;
    VALUE plaintext;
    void * ptr;
    size_t plaintext_sz;

    Data_Get_Struct(self, GroupSession, this);

    if (rb_obj_is_kind_of(sender, rb_eval_string("String")) != Qtrue) {
        rb_raise(rb_eTypeError, "sender must be kind of String");
    }

    if (rb_obj_is_kind_of(ciphertext, rb_eval_string("String")) != Qtrue) {
        rb_raise(rb_eTypeError, "ciphertext must be kind of String");
    }

    plaintext_sz = self_omemo_decrypted_size(this, RSTRING_PTR(ciphertext), RSTRING_LEN(ciphertext));

    if (plaintext_sz == 0) {
        rb_raise(rb_eTypeError, "could not get size of decrypted message");
    }

    if ((ptr = malloc(plaintext_sz)) == NULL) {
        rb_raise(rb_eNoMemError, "%s()", __FUNCTION__);
    }

    plaintext_sz = self_omemo_decrypt(
        this,
        RSTRING_PTR(sender),
        ptr,
        plaintext_sz,
        RSTRING_PTR(ciphertext),
        RSTRING_LEN(ciphertext)
    );

    if (plaintext_sz == 0) {
        free(ptr);
        rb_raise(rb_eTypeError, "failed to decrypt");
    }

    plaintext = rb_str_new(ptr, plaintext_sz);

    free(ptr);

    return plaintext;
}

static void _free(void * ptr) {
    self_omemo_destroy_group_session(ptr);
}

static VALUE _alloc(VALUE klass) {
    GroupSession * this;
    VALUE self;

    self = Data_Wrap_Struct(klass, 0, _free, self_omemo_create_group_session());

    Data_Get_Struct(self, GroupSession, this);

    return self;
}

void group_session_init() {
    VALUE cRubyOLM = rb_define_module("SelfCrypto");
    VALUE cGroupSession = rb_define_class_under(cRubyOLM, "GroupSession", rb_cObject);

    rb_define_alloc_func(cGroupSession, _alloc);

    rb_define_method(cGroupSession, "initialize", initialize, -1);
    rb_define_method(cGroupSession, "add_participant", add_participant, 2);
    rb_define_method(cGroupSession, "encrypt", group_encrypt, 1);
    rb_define_method(cGroupSession, "decrypt", group_decrypt, 2);
}