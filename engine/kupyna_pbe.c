/*
 * PBKDF2-with-Dstu7564mac and a PBES2 shim to wire it into OpenSSL's PBE
 * machinery. See kupyna_pbe.h for why this exists instead of a simple
 * EVP_PBE_TYPE_PRF registration.
 */
#include "kupyna_pbe.h"

#include "kupyna/kupyna.h"

#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/err.h>

#include <stdint.h>
#include <string.h>

#define KUPYNA_MAC_MAX_BYTES 64 /* 512-bit MAC, the largest variant */

static int mac256_nid = NID_undef;
static int mac384_nid = NID_undef;
static int mac512_nid = NID_undef;

void dstu_pbe_set_mac_nids(int nid256, int nid384, int nid512)
{
    mac256_nid = nid256;
    mac384_nid = nid384;
    mac512_nid = nid512;
}

static int mac_nbits_for_nid(int nid)
{
    if (nid != NID_undef && nid == mac256_nid)
        return 256;
    if (nid != NID_undef && nid == mac384_nid)
        return 384;
    if (nid != NID_undef && nid == mac512_nid)
        return 512;
    return 0;
}

int dstu7564_pbkdf2(const char *pass, int passlen, const unsigned char *salt, int saltlen,
                    int iter, int mac_nbits, int keylen, unsigned char *out)
{
    size_t hlen = (size_t)(mac_nbits / 8);
    size_t nblocks;
    size_t block;
    kupyna_ctx ctx;
    uint8_t pw[KUPYNA_MAC_MAX_BYTES]; /* password zero-padded/truncated to exactly hlen bytes -
                                        * confirmed against UAPKI's pbkdf2_dstu7564kmac (which does
                                        * this via ba_change_len before dstu7564_init_kmac, whose
                                        * key_len == mac_len is a hard requirement there). */
    size_t pwcopy;

    if (pass == NULL)
    {
        pass = "";
        passlen = 0;
    }
    else if (passlen == -1)
    {
        passlen = (int) strlen(pass);
    }
    if (iter <= 0 || keylen <= 0 || saltlen < 0 || hlen == 0 || hlen > KUPYNA_MAC_MAX_BYTES)
        return 0;
    if (kupyna_init((size_t) mac_nbits, &ctx) != 0)
        return 0;

    memset(pw, 0, sizeof(pw));
    pwcopy = (size_t) passlen < hlen ? (size_t) passlen : hlen;
    memcpy(pw, pass, pwcopy);

    nblocks = ((size_t) keylen + hlen - 1) / hlen;

    for (block = 1; block <= nblocks; ++block)
    {
        uint8_t u[KUPYNA_MAC_MAX_BYTES];
        uint8_t t[KUPYNA_MAC_MAX_BYTES];
        unsigned char *salt_and_index;
        size_t saltidx_len = (size_t) saltlen + 4;
        int i;
        size_t copylen;
        size_t b;

        salt_and_index = OPENSSL_malloc(saltidx_len);
        if (salt_and_index == NULL)
            return 0;
        if (saltlen > 0)
            memcpy(salt_and_index, salt, (size_t) saltlen);
        salt_and_index[saltlen + 0] = (unsigned char)((block >> 24) & 0xFF);
        salt_and_index[saltlen + 1] = (unsigned char)((block >> 16) & 0xFF);
        salt_and_index[saltlen + 2] = (unsigned char)((block >> 8) & 0xFF);
        salt_and_index[saltlen + 3] = (unsigned char)(block & 0xFF);

        if (kupyna_kmac(&ctx, pw, hlen, (size_t) mac_nbits,
                salt_and_index, saltidx_len * 8, u) != 0)
        {
            OPENSSL_free(salt_and_index);
            return 0;
        }
        OPENSSL_free(salt_and_index);
        memcpy(t, u, hlen);

        for (i = 1; i < iter; ++i)
        {
            if (kupyna_kmac(&ctx, pw, hlen, (size_t) mac_nbits,
                    u, hlen * 8, u) != 0)
                return 0;
            for (b = 0; b < hlen; ++b)
                t[b] = (uint8_t)(t[b] ^ u[b]);
        }

        copylen = (size_t) keylen - (block - 1) * hlen;
        if (copylen > hlen)
            copylen = hlen;
        memcpy(out + (block - 1) * hlen, t, copylen);
    }

    return 1;
}

int dstu_pbes2_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                        ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md, int en_de)
{
    PBE2PARAM *pbe2 = NULL;
    PBKDF2PARAM *kdf = NULL;
    int prf_nid;
    int mac_nbits;
    int rv = 0;
    char ciph_name[80];
    const EVP_CIPHER *c;
    unsigned char key[EVP_MAX_KEY_LENGTH];
    int keylen;
    int iter;
    const unsigned char *salt;
    int saltlen;

    (void) md;

    pbe2 = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBE2PARAM), param);
    if (pbe2 == NULL)
        return 0;

    if (OBJ_obj2nid(pbe2->keyfunc->algorithm) == NID_id_pbkdf2)
        kdf = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBKDF2PARAM), pbe2->keyfunc->parameter);

    prf_nid = (kdf != NULL && kdf->prf != NULL) ? OBJ_obj2nid(kdf->prf->algorithm) : NID_hmacWithSHA1;
    mac_nbits = kdf != NULL ? mac_nbits_for_nid(prf_nid) : 0;

    if (mac_nbits == 0)
    {
        /* Not our PRF (or not even PBKDF2): let OpenSSL's real handler deal
         * with it, unchanged. */
        PBKDF2PARAM_free(kdf);
        PBE2PARAM_free(pbe2);
        return PKCS5_v2_PBE_keyivgen(ctx, pass, passlen, param, cipher, md, en_de);
    }

    if (OBJ_obj2txt(ciph_name, sizeof(ciph_name), pbe2->encryption->algorithm, 0) <= 0)
        goto err;
    c = EVP_get_cipherbyname(ciph_name);
    if (c == NULL)
        goto err;
    if (!EVP_CipherInit_ex(ctx, c, NULL, NULL, NULL, en_de))
        goto err;
    if (EVP_CIPHER_asn1_to_param(ctx, pbe2->encryption->parameter) <= 0)
        goto err;

    keylen = EVP_CIPHER_CTX_key_length(ctx);
    if (keylen <= 0 || keylen > (int) sizeof(key))
        goto err;
    if (kdf->keylength && ASN1_INTEGER_get(kdf->keylength) != keylen)
        goto err;
    if (kdf->salt->type != V_ASN1_OCTET_STRING)
        goto err;
    salt = kdf->salt->value.octet_string->data;
    saltlen = kdf->salt->value.octet_string->length;
    iter = ASN1_INTEGER_get(kdf->iter);

    /* Password is used as-is (no BMPString conversion) - confirmed against
     * UAPKI's pbkdf2_dstu7564kmac, which just wraps the raw password bytes. */
    if (!dstu7564_pbkdf2(pass, passlen, salt, saltlen, iter, mac_nbits, keylen, key))
    {
        OPENSSL_cleanse(key, sizeof(key));
        goto err;
    }

    rv = EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, en_de);
    OPENSSL_cleanse(key, sizeof(key));

err:
    PBKDF2PARAM_free(kdf);
    PBE2PARAM_free(pbe2);
    return rv;
}
