#include <ruby.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

#include "olm/olm.h"

void account_init(void);
void session_init(void);
void utility_init(void);
void pk_init(void);
void sas_init(void);

static VALUE get_olm_version(VALUE self)
{
    char buffer[20U];
    uint8_t major = 0U;
    uint8_t minor = 0U;
    uint8_t patch = 0U;

    olm_get_library_version(&major, &minor, &patch);

    snprintf(buffer, sizeof(buffer), "%u.%u.%u", major, minor, patch);

    return rb_str_new2(buffer);
}

void Init_self_olm(void)
{
    rb_require("openssl");
    rb_require("json");
    rb_require("self_olm/olm_error");

    rb_define_singleton_method(rb_eval_string("SelfOlm"), "olm_version", get_olm_version, 0);

    account_init();
    session_init();
    utility_init();
    pk_init();
    sas_init();
}

void raise_olm_error(const char *error)
{
    rb_funcall(rb_eval_string("SelfOlm::OlmError"), rb_intern("raise_from_string"), 1, rb_str_new2(error));
}

VALUE get_random(size_t size)
{
    return rb_funcall(rb_eval_string("OpenSSL::Random"), rb_intern("random_bytes"), 1, SIZET2NUM(size));
}

VALUE dup_string(VALUE str)
{
    return rb_str_new(RSTRING_PTR(str), RSTRING_LEN(str));
}

void* malloc_or_raise(size_t len) {
    void * ptr = malloc(len);
    if (ptr == NULL) {
        rb_raise(rb_eNoMemError, "%s()", __FUNCTION__);
    }
    return ptr;
}
