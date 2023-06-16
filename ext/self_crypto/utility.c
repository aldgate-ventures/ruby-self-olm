#include "self_omemo2.h"
#include "self_crypto.h"

static VALUE random_bytes(VALUE self, VALUE size) {
    void * nonce;

    if (size == Qnil) {
        rb_raise(rb_eStandardError, "must specify a size");
    }

    if ((nonce = malloc(NUM2SIZET(size))) == NULL) {
        rb_raise(rb_eNoMemError, "%s()", __FUNCTION__);
    }

    self_randombytes_buf(nonce, NUM2SIZET(size));

    VALUE n = rb_str_new(nonce, NUM2SIZET(size));

    free(nonce);

    return n;
}

static VALUE aead_xchacha20poly1305_ietf_nonce(VALUE self) {
    void * nonce;

    if ((nonce = malloc(self_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)) == NULL) {
        rb_raise(rb_eNoMemError, "%s()", __FUNCTION__);
    }

    self_randombytes_buf(nonce, self_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    VALUE n = rb_str_new(nonce, self_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    free(nonce);

    return n;
}

static VALUE aead_xchacha20poly1305_ietf_keygen(VALUE self) {
    void * key;

    if ((key = malloc(self_crypto_aead_xchacha20poly1305_ietf_KEYBYTES)) == NULL) {
        rb_raise(rb_eNoMemError, "%s()", __FUNCTION__);
    }

    self_crypto_aead_xchacha20poly1305_ietf_keygen(key);

    VALUE k = rb_str_new(key, self_crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

    free(key);

    return k;
}

static VALUE aead_xchacha20poly1305_ietf_encrypt(VALUE self, VALUE key, VALUE nonce, VALUE plaintext) {
    void * ciphertext;
    unsigned long long ciphertext_len;

    if (key == Qnil) {
        rb_raise(rb_eStandardError, "must specify a key");
    }

    if (nonce == Qnil) {
        rb_raise(rb_eStandardError, "must specify a nonce");
    }

    if (plaintext == Qnil) {
        rb_raise(rb_eStandardError, "must specify plaintext");
    }

    if ((ciphertext = malloc(RSTRING_LEN(plaintext) + self_crypto_aead_xchacha20poly1305_ietf_ABYTES)) == NULL) {
        rb_raise(rb_eNoMemError, "%s()", __FUNCTION__);
    }

    self_crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext, 
        (uint64_t *) &ciphertext_len,
        RSTRING_PTR(plaintext),
        RSTRING_LEN(plaintext),
        NULL,
        0,
        NULL,
        RSTRING_PTR(nonce),
        RSTRING_PTR(key)
    );

    VALUE ct = rb_str_new(ciphertext, ciphertext_len);

    free(ciphertext);

    return ct;
}

static VALUE aead_xchacha20poly1305_ietf_decrypt(VALUE self, VALUE key, VALUE nonce, VALUE ciphertext) {
    void * plaintext;
    unsigned long long plaintext_len;

    if (key == Qnil) {
        rb_raise(rb_eStandardError, "must specify a key");
    }

    if (nonce == Qnil) {
        rb_raise(rb_eStandardError, "must specify a nonce");
    }

    if (ciphertext == Qnil) {
        rb_raise(rb_eStandardError, "must specify ciphertext");
    }

    if ((plaintext = malloc(RSTRING_LEN(ciphertext))) == NULL) {
        rb_raise(rb_eNoMemError, "%s()", __FUNCTION__);
    }

    int status = self_crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext,
        (uint64_t *) &plaintext_len,
        NULL,
        RSTRING_PTR(ciphertext),
        RSTRING_LEN(ciphertext),
        NULL,
        0,
        RSTRING_PTR(nonce),
        RSTRING_PTR(key)
    );

    if (status != 0) {
        rb_raise(rb_eStandardError, "could not authenticate encrypted message");
    }

    VALUE pt = rb_str_new(plaintext, plaintext_len);

    free(plaintext);

    return pt;
}

static VALUE ed25519_pk_to_curve25519(VALUE self, VALUE ed25519_pk) {
    VALUE curve25519_sk;
    void * pk_ptr, * dec_ptr, * enc_ptr;
    size_t pk_sz, dec_sz, enc_sz, success;

    if (rb_obj_is_kind_of(ed25519_pk, rb_eval_string("String")) != Qtrue) {
        rb_raise(rb_eTypeError, "ed25519_pk must be kind of String");
    }

    pk_sz = self_crypto_sign_publickeybytes();

    if ((dec_ptr = malloc(pk_sz)) == NULL) {
        rb_raise(rb_eNoMemError, "%s()", __FUNCTION__);
    }

    success = self_base642bin(
        dec_ptr,
        pk_sz,
        RSTRING_PTR(ed25519_pk),
        RSTRING_LEN(ed25519_pk),
        NULL, &
        dec_sz,
        NULL,
        self_base64_VARIANT_URLSAFE_NO_PADDING
    );

    if (success != 0) {
        free(dec_ptr);
        rb_raise(rb_eTypeError, "could not decode ed25519 public key");
    }

    if ((pk_ptr = malloc(pk_sz)) == NULL) {
        rb_raise(rb_eNoMemError, "%s()", __FUNCTION__);
    }

    success = self_crypto_sign_ed25519_pk_to_curve25519(
        pk_ptr,
        dec_ptr
    );

    free(dec_ptr);

    if (success != 0) {
        free(pk_ptr);
        rb_raise(rb_eTypeError, "could not convert ed25519 public key");
    }

    enc_sz = self_base64_ENCODED_LEN(pk_sz, self_base64_VARIANT_ORIGINAL_NO_PADDING);

    if ((enc_ptr = malloc(enc_sz)) == NULL) {
        rb_raise(rb_eNoMemError, "%s()", __FUNCTION__);
    }

    self_bin2base64(
        enc_ptr,
        enc_sz,
        pk_ptr,
        pk_sz,
        self_base64_VARIANT_ORIGINAL_NO_PADDING
    );

    free(pk_ptr);

    curve25519_sk = rb_str_new_cstr(enc_ptr);

    free(enc_ptr);

    return curve25519_sk;
}

static void _free(void * ptr) {
    free(ptr);
}

void utility_init(void) {
    VALUE cRubyOLM = rb_define_module("SelfCrypto");
    VALUE cUtil = rb_define_module_under(cRubyOLM, "Util");
    
    rb_define_module_function(cUtil, "ed25519_pk_to_curve25519", ed25519_pk_to_curve25519, 1);
    rb_define_module_function(cUtil, "random_bytes", random_bytes, 1);
    rb_define_module_function(cUtil, "aead_xchacha20poly1305_ietf_keygen", aead_xchacha20poly1305_ietf_keygen, 0);
    rb_define_module_function(cUtil, "aead_xchacha20poly1305_ietf_nonce", aead_xchacha20poly1305_ietf_nonce, 0);
    rb_define_module_function(cUtil, "aead_xchacha20poly1305_ietf_encrypt", aead_xchacha20poly1305_ietf_encrypt, 3);
    rb_define_module_function(cUtil, "aead_xchacha20poly1305_ietf_decrypt", aead_xchacha20poly1305_ietf_decrypt, 3);
}