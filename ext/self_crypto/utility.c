#include "self_olm/olm.h"
#include "self_crypto.h"
#include "sodium.h"

static VALUE last_error(VALUE self)
{
    OlmUtility *this;
    Data_Get_Struct(self, OlmUtility, this);

    return rb_str_new2(olm_utility_last_error(this));
}

static VALUE ed25519_verify(VALUE self, VALUE data, VALUE key, VALUE signature)
{
    VALUE retval = Qtrue;
    OlmUtility *this;
    Data_Get_Struct(self, OlmUtility, this);

    if(olm_ed25519_verify(this, RSTRING_PTR(key), RSTRING_LEN(key), RSTRING_PTR(data), RSTRING_LEN(data), RSTRING_PTR(dup_string(signature)), RSTRING_LEN(signature)) == olm_error()){

        retval = Qfalse;
    }

    return retval;
}

static VALUE ed25519_pk_to_curve25519(VALUE self, VALUE ed25519_pk)
{
    VALUE curve25519_sk;
    void  *pk_ptr, *dec_ptr, *enc_ptr;
    size_t pk_sz, dec_sz, enc_sz, success;

    if(rb_obj_is_kind_of(ed25519_pk, rb_eval_string("String")) != Qtrue){
        rb_raise(rb_eTypeError, "ed25519_pk must be kind of String");
    }

    pk_sz = crypto_sign_publickeybytes();

    if((dec_ptr = malloc(pk_sz)) == NULL){
        rb_raise(rb_eNoMemError, "%s()", __FUNCTION__);
    }

    success = sodium_base642bin(
        dec_ptr,
        pk_sz,
        RSTRING_PTR(ed25519_pk),
        RSTRING_LEN(ed25519_pk),
        NULL,
        &dec_sz,
        NULL,
        sodium_base64_VARIANT_ORIGINAL_NO_PADDING
    );

    if(success != 0) {
        free(dec_ptr);
        rb_raise(rb_eTypeError, "could not convert ed25519 public key");
    }

    if((pk_ptr = malloc(pk_sz)) == NULL){
        rb_raise(rb_eNoMemError, "%s()", __FUNCTION__);
    }

    success = crypto_sign_ed25519_pk_to_curve25519(
        pk_ptr,
        dec_ptr
    );

    free(dec_ptr);

    if(success != 0) {
        free(pk_ptr);
        rb_raise(rb_eTypeError, "could not convert ed25519 public key");
    }

    enc_sz = sodium_base64_ENCODED_LEN(pk_sz, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);

    if((enc_ptr = malloc(enc_sz)) == NULL){
        rb_raise(rb_eNoMemError, "%s()", __FUNCTION__);
    }

    sodium_bin2base64(
        enc_ptr,
        enc_sz,
        pk_ptr,
        pk_sz,
        sodium_base64_VARIANT_ORIGINAL_NO_PADDING
    );

    free(pk_ptr);

    curve25519_sk = rb_str_new_cstr(enc_ptr);

    free(enc_ptr);

    return curve25519_sk;
}

static VALUE sha256(VALUE self, VALUE data)
{
    size_t size;
    OlmUtility *this;
    Data_Get_Struct(self, OlmUtility, this);

    size = olm_sha256_length(this);
    uint8_t buf[size];

    (void)olm_sha256(this, RSTRING_PTR(data), RSTRING_LEN(data), buf, size);

    return rb_str_new(buf, size);
}

static void _free(void *ptr)
{
    olm_clear_utility(ptr);
    free(ptr);
}

static VALUE _alloc(VALUE klass)
{
    OlmUtility *this;
    VALUE self;

    self = Data_Wrap_Struct(klass, 0, _free, calloc(1, olm_utility_size()));

    Data_Get_Struct(self, OlmUtility, this);

    (void)olm_utility((void *)this);

    return self;
}

void utility_init(void)
{
    VALUE cRubyOLM = rb_define_module("SelfCrypto");
    VALUE cUtil = rb_define_module_under(cRubyOLM, "Util");
    VALUE cUtility = rb_define_class_under(cRubyOLM, "Utility", rb_cObject);

    rb_define_alloc_func(cUtility, _alloc);

    rb_define_method(cUtility, "sha256", sha256, 1);
    rb_define_method(cUtility, "ed25519_verify", ed25519_verify, 3);
    rb_define_module_function(cUtil, "ed25519_pk_to_curve25519", ed25519_pk_to_curve25519, 1);
}
