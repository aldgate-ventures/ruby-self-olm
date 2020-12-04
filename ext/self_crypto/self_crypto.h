// Copyright 2020 Self Group Ltd. All Rights Reserved.

#ifndef SELF_CRYPTO_H
#define SELF_CRYPTO_H

#include <ruby.h>

/* convert error string to exception and raise it */
void raise_olm_error(const char *error);
VALUE get_random(size_t size);

/* necessary to avoid copy-on-write weirdness */
VALUE dup_string(VALUE str);

void* malloc_or_raise(size_t len) __attribute__((malloc));

#endif
