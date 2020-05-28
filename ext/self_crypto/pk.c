#include "self_olm/pk.h"
#include "self_crypto.h"

void pk_encryption_init(VALUE cSelfCryptoPK);
void pk_decryption_init(VALUE cSelfCryptoPK);
void pk_signing_init(VALUE cSelfCryptoPK);

void pk_init(void) {
    VALUE cSelfCrypto = rb_define_module("SelfCrypto");
    VALUE cSelfCryptoPK = rb_define_module_under(cSelfCrypto, "PK");

    pk_encryption_init(cSelfCryptoPK);
    pk_decryption_init(cSelfCryptoPK);
    pk_signing_init(cSelfCryptoPK);
}
