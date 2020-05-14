#include "olm/pk.h"
#include "self_olm.h"

void pk_encryption_init(VALUE cSelfOlmPK);
void pk_decryption_init(VALUE cSelfOlmPK);
void pk_signing_init(VALUE cSelfOlmPK);

void pk_init(void) {
    VALUE cSelfOlm = rb_define_module("SelfOlm");
    VALUE cSelfOlmPK = rb_define_module_under(cSelfOlm, "PK");

    pk_encryption_init(cSelfOlmPK);
    pk_decryption_init(cSelfOlmPK);
    pk_signing_init(cSelfOlmPK);
}
