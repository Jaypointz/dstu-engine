#ifndef DSTU_ENGINE_KALYNA_CIPHER_H_
#define DSTU_ENGINE_KALYNA_CIPHER_H_

#include <openssl/evp.h>

/* Kalyna-256/256-CBC ("Dstu7624cbc(256)", DSTU 7624:2014): 256-bit block,
 * 256-bit key, standard CBC chaining (PKCS7 padding/block-buffering is left
 * to the generic EVP layer, same as any other block cipher). */
EVP_CIPHER *kalyna256cbc_cipher_new(int nid);
void kalyna_cipher_free(EVP_CIPHER *cipher);

#endif /* DSTU_ENGINE_KALYNA_CIPHER_H_ */
