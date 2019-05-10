#include <ruby.h>
#include <stdlib.h>
#include <olm/pk.h>
#include <olm/olm.h>
#include "ruby_olm.h"

static void _free(void *ptr) {
    olm_clear_pk_decryption(ptr);
    free(ptr);
}

static size_t _size(const void *ptr __attribute__((unused))) {
    return olm_pk_decryption_size();
}

static const rb_data_type_t olm_pk_decryption_type = {
        .wrap_struct_name = "olm_pk_decryption",
        .function = {
                .dmark = NULL,
                .dfree = _free,
                .dsize = _size,
                .reserved = {NULL, NULL}
        },
        .data = NULL,
        .flags = RUBY_TYPED_FREE_IMMEDIATELY
};

static VALUE _alloc(VALUE klass) {
    void *memory = malloc_or_raise(olm_pk_decryption_size());
    return TypedData_Wrap_Struct(klass, &olm_pk_decryption_type, olm_pk_decryption(memory));
}

static VALUE initialize(int argc, VALUE *argv, VALUE self) {
    OlmPkDecryption *this;
    size_t publicKeyLen;
    char *publicKeyPtr;
    VALUE privateKey;
    TypedData_Get_Struct(self, OlmPkDecryption, &olm_pk_decryption_type, this);

    rb_scan_args(argc, argv, "01", &privateKey);

    if (NIL_P(privateKey)) {
        privateKey = get_random(olm_pk_private_key_length());
    } else {
        Check_Type(privateKey, T_STRING);
        if (RSTRING_LEN(privateKey) != olm_pk_private_key_length()) {
            rb_raise(rb_eval_string("ArgumentError"), "private_key has wrong size (must be %lu)", olm_pk_private_key_length());
        }
    }

    publicKeyLen = olm_pk_key_length();
    publicKeyPtr = malloc_or_raise(publicKeyLen);

    if (olm_pk_key_from_private(this,
            publicKeyPtr, publicKeyLen,
            RSTRING_PTR(privateKey), RSTRING_LEN(privateKey)) == olm_error()) {
        free(publicKeyPtr);
        raise_olm_error(olm_pk_decryption_last_error(this));
    }

    rb_iv_set(self, "@public_key", rb_str_new(publicKeyPtr, publicKeyLen));
    free(publicKeyPtr);

    return self;
}

static VALUE decrypt(VALUE self, VALUE pkMessage) {
    OlmPkDecryption *this;
    size_t plaintextLen;
    char *plaintextPtr;
    VALUE ephemeral, mac, ciphertext, retval;
    TypedData_Get_Struct(self, OlmPkDecryption, &olm_pk_decryption_type, this);

    ephemeral = rb_funcall(pkMessage, rb_intern("ephemeral_key"), 0);
    Check_Type(ephemeral, T_STRING);
    mac = rb_funcall(pkMessage, rb_intern("mac"), 0);
    Check_Type(mac, T_STRING);
    ciphertext = rb_funcall(pkMessage, rb_intern("cipher_text"), 0);
    Check_Type(ciphertext, T_STRING);

    plaintextLen = olm_pk_max_plaintext_length(this, RSTRING_LEN(ciphertext));
    plaintextPtr = malloc_or_raise(plaintextLen);

    plaintextLen = olm_pk_decrypt(this,
                       RSTRING_PTR(ephemeral), RSTRING_LEN(ephemeral),
                       RSTRING_PTR(mac), RSTRING_LEN(mac),
                       RSTRING_PTR(ciphertext), RSTRING_LEN(ciphertext),
                       plaintextPtr, plaintextLen);
    if (plaintextLen == olm_error()) {
        free(plaintextPtr);
        raise_olm_error(olm_pk_decryption_last_error(this));
    }

    retval = rb_str_new(plaintextPtr, plaintextLen);
    free(plaintextPtr);

    return retval;
}

static VALUE private_key(VALUE self) {
    OlmPkDecryption *this;
    size_t privkeyLen;
    char *privkeyPtr;
    VALUE retval;
    TypedData_Get_Struct(self, OlmPkDecryption, &olm_pk_decryption_type, this);

    privkeyLen = olm_pk_private_key_length();
    privkeyPtr = malloc_or_raise(privkeyLen);

    if (olm_pk_get_private_key(this, privkeyPtr, privkeyLen) == olm_error()) {
        free(privkeyPtr);
        raise_olm_error(olm_pk_decryption_last_error(this));
    }

    retval = rb_str_new(privkeyPtr, privkeyLen);
    free(privkeyPtr);
    return retval;
}

void pk_decryption_init(VALUE cRubyOlmPK) {
    VALUE cDecryption = rb_define_class_under(cRubyOlmPK, "Decryption", rb_cData);

    rb_define_alloc_func(cDecryption, _alloc);

    rb_define_attr(cDecryption, "public_key", 1, 0);
    rb_define_method(cDecryption, "initialize", initialize, -1);
    rb_define_method(cDecryption, "decrypt", decrypt, 1);
    rb_define_method(cDecryption, "private_key", private_key, 0);
}
