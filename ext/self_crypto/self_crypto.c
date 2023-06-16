#include <ruby.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include "self_omemo2.h"

void account_init(void);
void session_init(void);
void utility_init(void);
void group_session_init(void);

void Init_self_crypto(void) {
    rb_require("json");
    rb_require("self_crypto/olm_error");

    account_init();
    session_init();
    group_session_init();
    utility_init();
}

void raise_olm_error(const char * error) {
    rb_funcall(rb_eval_string("SelfCrypto::OlmError"), rb_intern("raise_from_string"), 1, rb_str_new2(error));
}

VALUE get_random(size_t size) {
    VALUE rand;
    void * ptr;

    if ((ptr = malloc(size)) == NULL) {
        rb_raise(rb_eNoMemError, "%s()", __FUNCTION__);
    }

    self_randombytes_buf(ptr, size);

    rand = rb_str_new(ptr, size);

    free(ptr);

    return rand;
}

VALUE dup_string(VALUE str) {
    return rb_str_new(RSTRING_PTR(str), RSTRING_LEN(str));
}

void * malloc_or_raise(size_t len) {
    void * ptr = malloc(len);
    if (ptr == NULL) {
        rb_raise(rb_eNoMemError, "%s()", __FUNCTION__);
    }
    return ptr;
}