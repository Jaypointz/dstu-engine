#pragma once

#include <openssl/ossl_typ.h>

/* nid must be a valid, already-registered NID (see kupyna_register_nids). */
EVP_MD *kupyna256_digest_new(int nid);
EVP_MD *kupyna512_digest_new(int nid);
void kupyna_digest_free(EVP_MD *digest);
