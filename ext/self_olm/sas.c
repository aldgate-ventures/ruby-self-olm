#include <ruby.h>
#include <stdlib.h>
#include <olm/olm.h>
#include <olm/sas.h>
#include "self_olm.h"

static VALUE set_other_pubkey(VALUE self, VALUE other_public_key);

static void _free(void *ptr) {
    olm_clear_sas(ptr);
    free(ptr);
}

static size_t _size(const void *ptr __attribute__((unused))) {
    return olm_sas_size();
}

static const rb_data_type_t olm_sas_type = {
        .wrap_struct_name = "olm_sas",
        .function = {
                .dmark = NULL,
                .dfree = _free,
                .dsize = _size,
                .reserved = {NULL}
        },
        .data = NULL,
        .flags = RUBY_TYPED_FREE_IMMEDIATELY
};

static VALUE _alloc(VALUE klass) {
    void *memory = malloc_or_raise(olm_sas_size());
    return TypedData_Wrap_Struct(klass, &olm_sas_type, olm_sas(memory));
}

static void _ensure_other_pubkey(VALUE self) {
    if (NIL_P(rb_iv_get(self, "@other_public_key"))) {
        rb_raise(rb_eRuntimeError, "other_public_key must be set");
    }
}

static VALUE initialize(int argc, VALUE *argv, VALUE self) {
    OlmSAS *this;
    VALUE random;
    VALUE other_pubkey;
    TypedData_Get_Struct(self, OlmSAS, &olm_sas_type, this);

    rb_scan_args(argc, argv, "01", &other_pubkey);

    random = get_random(olm_create_sas_random_length(this));
    if (olm_create_sas(this, RSTRING_PTR(random), RSTRING_LEN(random)) == olm_error()) {
        raise_olm_error(olm_sas_last_error(this));
    }

    // Make sure @other_public_key is set
    rb_iv_set(self, "@other_public_key", Qnil);

    if (!NIL_P(other_pubkey)) {
        set_other_pubkey(self, other_pubkey);
    }

    return self;
}

static VALUE set_other_pubkey(VALUE self, VALUE other_public_key) {
    OlmSAS *this;
    TypedData_Get_Struct(self, OlmSAS, &olm_sas_type, this);
    Check_Type(other_public_key, T_STRING);

    if (RSTRING_LEN(other_public_key) != olm_sas_pubkey_length(this)) {
        rb_raise(rb_eval_string("ArgumentError"), "other_public_key has wrong size (must be %lu)", olm_sas_pubkey_length(this));
    }

    // olm_sas_set_their_key trashes other_public_key, and rb_str_dup only creates a shallow copy.
    VALUE other_public_key_dup = rb_str_new(RSTRING_PTR(other_public_key), RSTRING_LEN(other_public_key));
    if (olm_sas_set_their_key(this, RSTRING_PTR(other_public_key_dup), RSTRING_LEN(other_public_key_dup)) == olm_error()) {
        raise_olm_error(olm_sas_last_error(this));
    }

    rb_iv_set(self, "@other_public_key", other_public_key);
    return other_public_key;
}

static VALUE get_public_key(VALUE self) {
    OlmSAS *this;
    size_t public_key_len;
    char *public_key;
    VALUE retval;
    TypedData_Get_Struct(self, OlmSAS, &olm_sas_type, this);

    public_key_len = olm_sas_pubkey_length(this);
    public_key = malloc_or_raise(public_key_len);

    if (olm_sas_get_pubkey(this, public_key, public_key_len) == olm_error()) {
        free(public_key);
        raise_olm_error(olm_sas_last_error(this));
    }

    retval = rb_str_new(public_key, public_key_len);
    free(public_key);
    return retval;
}

static VALUE generate_bytes(VALUE self, VALUE count, VALUE info) {
    OlmSAS *this;
    size_t output_len;
    char *output;
    VALUE retval;
    TypedData_Get_Struct(self, OlmSAS, &olm_sas_type, this);
    Check_Type(count, T_FIXNUM);
    Check_Type(info, T_STRING);

    output_len = NUM2ULONG(count);
    output = malloc_or_raise(output_len);

    if (olm_sas_generate_bytes(this, RSTRING_PTR(info), RSTRING_LEN(info), output, output_len) == olm_error()) {
        free(output);
        raise_olm_error(olm_sas_last_error(this));
    }

    retval = rb_str_new(output, output_len);
    free(output);
    // Return raw byte string here, higher abstraction in Ruby
    return retval;
}

static VALUE calculate_mac(VALUE self, VALUE message, VALUE info) {
    OlmSAS *this;
    size_t mac_len;
    char *mac;
    VALUE retval;
    TypedData_Get_Struct(self, OlmSAS, &olm_sas_type, this);
    Check_Type(message, T_STRING);
    Check_Type(info, T_STRING);

    mac_len = olm_sas_mac_length(this);
    mac = malloc_or_raise(mac_len);

    if (olm_sas_calculate_mac(this,
                              RSTRING_PTR(message), RSTRING_LEN(message),
                              RSTRING_PTR(info), RSTRING_LEN(info),
                              mac, mac_len) == olm_error()) {
        free(mac);
        raise_olm_error(olm_sas_last_error(this));
    }

    retval = rb_str_new(mac, mac_len);
    free(mac);
    return retval;
}

static VALUE calculate_mac_long_kdf(VALUE self, VALUE message, VALUE info) {
    OlmSAS *this;
    size_t mac_len;
    char *mac;
    VALUE retval;
    TypedData_Get_Struct(self, OlmSAS, &olm_sas_type, this);
    Check_Type(message, T_STRING);
    Check_Type(info, T_STRING);

    mac_len = olm_sas_mac_length(this);
    mac = malloc_or_raise(mac_len);

    if (olm_sas_calculate_mac_long_kdf(this,
                              RSTRING_PTR(message), RSTRING_LEN(message),
                              RSTRING_PTR(info), RSTRING_LEN(info),
                              mac, mac_len) == olm_error()) {
        free(mac);
        raise_olm_error(olm_sas_last_error(this));
    }

    retval = rb_str_new(mac, mac_len);
    free(mac);
    return retval;
}

void sas_init(void) {
    VALUE cSelfOlm = rb_define_module("SelfOlm");
    VALUE cSAS = rb_define_class_under(cSelfOlm, "SAS", rb_cData);

    rb_define_alloc_func(cSAS, _alloc);

    rb_define_attr(cSAS, "other_public_key", 1, 0);
    rb_define_method(cSAS, "other_public_key=", set_other_pubkey, 1);

    rb_define_method(cSAS, "initialize", initialize, -1);
    rb_define_method(cSAS, "public_key", get_public_key, 0);
    rb_define_method(cSAS, "generate_bytes", generate_bytes, 2);
    rb_define_method(cSAS, "calculate_mac", calculate_mac, 2);
    rb_define_method(cSAS, "calculate_mac_long_kdf", calculate_mac_long_kdf, 2);
}
