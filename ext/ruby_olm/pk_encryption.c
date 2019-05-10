#include <ruby.h>
#include <stdlib.h>
#include <olm/pk.h>
#include <olm/olm.h>
#include "ruby_olm.h"

static void _free(void *ptr) {
    olm_clear_pk_encryption(ptr);
    free(ptr);
}

static size_t _size(const void *ptr __attribute__((unused))) {
    return olm_pk_encryption_size();
}

static const rb_data_type_t olm_pk_encryption_type = {
        .wrap_struct_name = "olm_pk_encryption",
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
    void *memory = malloc_or_raise(olm_pk_encryption_size());
    return TypedData_Wrap_Struct(klass, &olm_pk_encryption_type, olm_pk_encryption(memory));
}

static VALUE initialize(VALUE self, VALUE recipientKey) {
    OlmPkEncryption *this;
    TypedData_Get_Struct(self, OlmPkEncryption, &olm_pk_encryption_type, this);
    Check_Type(recipientKey, T_STRING);

    if (olm_pk_encryption_set_recipient_key(this,
            RSTRING_PTR(recipientKey), RSTRING_LEN(recipientKey)) == olm_error()) {
        raise_olm_error(olm_pk_encryption_last_error(this));
    }

    return self;
}

static VALUE encrypt(VALUE self, VALUE plaintext) {
    OlmPkEncryption *this;
    size_t ciphertextLen, macLen, ephemeralLen, randomLen;
    char *ciphertextPtr, *macPtr, *ephemeralPtr;
    VALUE retval;
    TypedData_Get_Struct(self, OlmPkEncryption, &olm_pk_encryption_type, this);
    Check_Type(plaintext, T_STRING);

    ciphertextLen = olm_pk_ciphertext_length(this, RSTRING_LEN(plaintext));
    ciphertextPtr = malloc_or_raise(ciphertextLen);
    macLen = olm_pk_mac_length(this);
    macPtr = malloc_or_raise(macLen);
    ephemeralLen = olm_pk_key_length();
    ephemeralPtr = malloc_or_raise(ephemeralLen);
    randomLen = olm_pk_encrypt_random_length(this);

    if (olm_pk_encrypt(this,
            RSTRING_PTR(plaintext), RSTRING_LEN(plaintext),
            ciphertextPtr, ciphertextLen,
            macPtr, macLen,
            ephemeralPtr, ephemeralLen,
            RSTRING_PTR(get_random(randomLen)), randomLen) == olm_error()) {
        free(ephemeralPtr);
        free(macPtr);
        free(ciphertextPtr);
        raise_olm_error(olm_pk_encryption_last_error(this));
    }

    retval = rb_funcall(rb_eval_string("RubyOlm::PK::Message"), rb_intern("new"), 3,
            rb_str_new(ciphertextPtr, ciphertextLen),
            rb_str_new(macPtr, macLen),
            rb_str_new(ephemeralPtr, ephemeralLen));

    free(ephemeralPtr);
    free(macPtr);
    free(ciphertextPtr);

    return retval;
}

void pk_encryption_init(VALUE cRubyOlmPK) {
    VALUE cEncryption = rb_define_class_under(cRubyOlmPK, "Encryption", rb_cData);

    rb_define_alloc_func(cEncryption, _alloc);

    rb_define_method(cEncryption, "initialize", initialize, 1);
    rb_define_method(cEncryption, "encrypt", encrypt, 1);
}
