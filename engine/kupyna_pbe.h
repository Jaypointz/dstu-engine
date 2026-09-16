#ifndef DSTU_ENGINE_KUPYNA_PBE_H_
#define DSTU_ENGINE_KUPYNA_PBE_H_

#include <openssl/evp.h>
#include <openssl/asn1.h>

/* Tell the PBES2 shim which dynamically-registered NIDs correspond to the
 * Dstu7564mac(256/384/512) PRFs. Must be called before dstu_pbes2_keyivgen()
 * can recognize them (NID_undef for any variant that failed to register). */
void dstu_pbe_set_mac_nids(int nid256, int nid384, int nid512);

/*
 * Standard PBKDF2 (RFC 8018 section 5.2) using Dstu7564mac as the PRF.
 * OpenSSL's own PKCS5_v2_PBKDF2_keyivgen_ex has no extension point for a
 * non-HMAC PRF, which is why this exists instead of an EVP_PBE_TYPE_PRF
 * registration (that path assumes every PRF is "some EVP_MD fed to plain
 * HMAC", which Dstu7564mac is not). mac_nbits selects the Kupyna-based MAC
 * variant (256/384/512) and thus the PRF's output block size.
 * Returns 1 on success, 0 on failure.
 */
int dstu7564_pbkdf2(const char *pass, int passlen, const unsigned char *salt, int saltlen,
                    int iter, int mac_nbits, int keylen, unsigned char *out);

/*
 * Replacement EVP_PBE_KEYGEN for (EVP_PBE_TYPE_OUTER, NID_pbes2). Handles
 * the case where the PBES2 KDF is PBKDF2 with a Dstu7564mac PRF (which stock
 * OpenSSL cannot do); every other PBES2 combination (standard HMAC PRFs,
 * scrypt, etc.) is transparently delegated to the real PKCS5_v2_PBE_keyivgen
 * so registering this does not change behavior for anything else.
 */
int dstu_pbes2_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                        ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md, int en_de);

#endif /* DSTU_ENGINE_KUPYNA_PBE_H_ */
