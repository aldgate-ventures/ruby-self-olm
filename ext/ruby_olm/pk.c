#include "olm/pk.h"
#include "ruby_olm.h"

void pk_encryption_init(VALUE cRubyOlmPK);
void pk_decryption_init(VALUE cRubyOlmPK);
void pk_signing_init(VALUE cRubyOlmPK);

void pk_init(void) {
    VALUE cRubyOlm = rb_define_module("RubyOlm");
    VALUE cRubyOlmPK = rb_define_module_under(cRubyOlm, "PK");

    pk_encryption_init(cRubyOlmPK);
    pk_decryption_init(cRubyOlmPK);
    pk_signing_init(cRubyOlmPK);
}
