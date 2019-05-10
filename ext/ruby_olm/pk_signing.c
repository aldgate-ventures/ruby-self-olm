#include <ruby.h>
#include <stdlib.h>
#include <olm/pk.h>
#include <olm/olm.h>
#include "ruby_olm.h"

static void _free(void *ptr) {
    olm_clear_pk_signing(ptr);
    free(ptr);
}

static size_t _size(const void *ptr __attribute__((unused))) {
    return olm_pk_signing_size();
}

static const rb_data_type_t olm_pk_signing_type = {
        .wrap_struct_name = "olm_pk_signing",
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
    void *memory = malloc_or_raise(olm_pk_signing_size());
    return TypedData_Wrap_Struct(klass, &olm_pk_signing_type, olm_pk_signing(memory));
}

static VALUE initialize(int argc, VALUE *argv, VALUE self) {
    OlmPkSigning *this;
    size_t publicKeyLen;
    char *publicKeyPtr;
    VALUE privateKey;
    TypedData_Get_Struct(self, OlmPkSigning, &olm_pk_signing_type, this);

    rb_scan_args(argc, argv, "01", &privateKey);

    if (NIL_P(privateKey)) {
        privateKey = get_random(olm_pk_signing_seed_length());
    } else {
        Check_Type(privateKey, T_STRING);
        if (RSTRING_LEN(privateKey) != olm_pk_signing_seed_length()) {
            rb_raise(rb_eval_string("ArgumentError"), "private_key has wrong size (must be %lu)", olm_pk_signing_seed_length());
        }
    }

    publicKeyLen = olm_pk_signing_public_key_length();
    publicKeyPtr = malloc_or_raise(publicKeyLen);

    if (olm_pk_signing_key_from_seed(this,
                                publicKeyPtr, publicKeyLen,
                                RSTRING_PTR(privateKey), RSTRING_LEN(privateKey)) == olm_error()) {
        free(publicKeyPtr);
        raise_olm_error(olm_pk_signing_last_error(this));
    }

    rb_iv_set(self, "@public_key", rb_str_new(publicKeyPtr, publicKeyLen));
    rb_iv_set(self, "@private_key", privateKey);
    free(publicKeyPtr);

    return self;
}

static VALUE sign(VALUE self, VALUE message) {
    OlmPkSigning *this;
    size_t signatureLen;
    char *signaturePtr;
    VALUE retval;
    TypedData_Get_Struct(self, OlmPkSigning, &olm_pk_signing_type, this);

    Check_Type(message, T_STRING);

    signatureLen = olm_pk_signature_length();
    signaturePtr = malloc_or_raise(signatureLen);

    if (olm_pk_sign(this,
            RSTRING_PTR(message), RSTRING_LEN(message),
            signaturePtr, signatureLen) == olm_error()) {
        free(signaturePtr);
        raise_olm_error(olm_pk_signing_last_error(this));
    }

    retval = rb_str_new(signaturePtr, signatureLen);
    free(signaturePtr);
    return retval;
}

void pk_signing_init(VALUE cRubyOlmPK) {
    VALUE cSigning = rb_define_class_under(cRubyOlmPK, "Signing", rb_cData);

    rb_define_alloc_func(cSigning, _alloc);

    rb_define_attr(cSigning, "public_key", 1, 0);
    rb_define_attr(cSigning, "private_key", 1, 0);

    rb_define_method(cSigning, "initialize", initialize, -1);
    rb_define_method(cSigning, "sign", sign, 1);
}