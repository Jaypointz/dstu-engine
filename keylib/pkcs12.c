#include "pkcs12.h"

#include "keystore_internal.h"

#include "kupyna/kupyna.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>

#include <string.h>

#define KUPYNA256_SHORT_NAME "kupyna256"

static int fromBags(const STACK_OF(PKCS12_SAFEBAG)* bags, const char* password, size_t passSize, KeyStore* ks, size_t* keyPos, size_t* certPos);
static int countKeysCertsInBags(const STACK_OF(PKCS12_SAFEBAG)* bags, const char* password, size_t passSize, size_t* numKeys, size_t* numCerts);

static int countKeysCertsInBag(const PKCS12_SAFEBAG* bag, const char* password, size_t passSize, size_t* numKeys, size_t* numCerts)
{
    switch (PKCS12_SAFEBAG_get_nid(bag))
    {
        case NID_keyBag:
        case NID_pkcs8ShroudedKeyBag:
            if (numKeys)
                ++*numKeys;
            break;
        case NID_certBag:
            if (numCerts)
                ++*numCerts;
            break;
        case NID_safeContentsBag:
            return countKeysCertsInBags(PKCS12_SAFEBAG_get0_safes(bag), password, passSize, numKeys, numCerts);
    }
    return 1;
}

static int countKeysCertsInBags(const STACK_OF(PKCS12_SAFEBAG)* bags, const char* password, size_t passSize, size_t* numKeys, size_t* numCerts)
{
    int i = 0;
    for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); ++i)
    {
        if (countKeysCertsInBag(sk_PKCS12_SAFEBAG_value(bags, i), password, passSize, numKeys, numCerts) == 0)
            return 0;
    }
    return 1;
}

static int countKeysCerts(const STACK_OF(PKCS7)* safes, const char* password, size_t passSize, size_t* numKeys, size_t* numCerts)
{
    STACK_OF(PKCS12_SAFEBAG)* bags = NULL;
    PKCS7* pkcs7 = NULL;
    int bagNID = 0;
    int i = 0;

    for (i = 0; i < sk_PKCS7_num(safes); ++i)
    {
        pkcs7 = sk_PKCS7_value(safes, i);
        if (pkcs7 == NULL)
            continue;
        bagNID = OBJ_obj2nid(pkcs7->type);
        if (bagNID == NID_pkcs7_data)
            bags = PKCS12_unpack_p7data(pkcs7);
        else if (bagNID == NID_pkcs7_encrypted)
            bags = PKCS12_unpack_p7encdata(pkcs7, password, passSize);
        else
            continue;
        if (bags == NULL)
            return 0;

        if (countKeysCertsInBags(bags, password, passSize, numKeys, numCerts) == 0)
        {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            return 0;
        }

        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    }

    return 1;
}

static int fromBag(const PKCS12_SAFEBAG* bag, const char* password, size_t passSize, KeyStore* ks, size_t* keyPos, size_t* certPos)
{
    EVP_PKEY* pkey = NULL;
    PKCS8_PRIV_KEY_INFO* pkcs8;
    const PKCS8_PRIV_KEY_INFO* pkcs8c = NULL;
    X509* x509 = NULL;

    switch (PKCS12_SAFEBAG_get_nid(bag))
    {
        case NID_keyBag:
            pkcs8c = PKCS12_SAFEBAG_get0_p8inf(bag);
            pkey = EVP_PKCS82PKEY(pkcs8c);
            if (pkey == NULL)
                return 0;
            KeyStoreSetKey(ks, (*keyPos)++, pkey);
            break;
        case NID_pkcs8ShroudedKeyBag:
            pkcs8 = PKCS12_decrypt_skey(bag, password, passSize);
            if (pkcs8 == NULL)
                return 0;
            pkey = EVP_PKCS82PKEY(pkcs8);
            if (pkey == NULL)
            {
                PKCS8_PRIV_KEY_INFO_free(pkcs8);
                return 0;
            }
            KeyStoreSetKey(ks, (*keyPos)++, pkey);
            PKCS8_PRIV_KEY_INFO_free(pkcs8);
            break;
        case NID_certBag:
            x509 = PKCS12_SAFEBAG_get1_cert(bag);
            if (x509 == NULL)
               return 0;
            KeyStoreSetCert(ks, (*certPos)++, x509);
            break;
        case NID_safeContentsBag:
            return fromBags(PKCS12_SAFEBAG_get0_safes(bag), password, passSize, ks, keyPos, certPos);
    }
    return 1;
}

static int fromBags(const STACK_OF(PKCS12_SAFEBAG)* bags, const char* password, size_t passSize, KeyStore* ks, size_t* keyPos, size_t* certPos)
{
    int i = 0;
    for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); ++i)
    {
        if (fromBag(sk_PKCS12_SAFEBAG_value(bags, i), password, passSize, ks, keyPos, certPos) == 0)
            return 0;
    }
    return 1;
}

static int fromSafes(const STACK_OF(PKCS7)* safes, const char* password, size_t passSize, KeyStore* ks, size_t* keyPos, size_t* certPos)
{
    STACK_OF(PKCS12_SAFEBAG)* bags = NULL;
    PKCS7* pkcs7 = NULL;
    int bagNID = 0;
    int i = 0;

    for (i = 0; i < sk_PKCS7_num(safes); ++i)
    {
        pkcs7 = sk_PKCS7_value(safes, i);
        if (pkcs7 == NULL)
            continue;
        bagNID = OBJ_obj2nid(pkcs7->type);
        if (bagNID == NID_pkcs7_data)
            bags = PKCS12_unpack_p7data(pkcs7);
        else if (bagNID == NID_pkcs7_encrypted)
            bags = PKCS12_unpack_p7encdata(pkcs7, password, passSize);
        else
            continue;
        if (bags == NULL)
            return 0;

        if (fromBags(bags, password, passSize, ks, keyPos, certPos) == 0)
        {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            return 0;
        }

        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    }

    return 1;
}

/* Walks one ASN1 TLV: on success *pp is advanced past it, *content/*contentLen
 * describe its value bytes. */
static int getObjectContent(const unsigned char** pp, const unsigned char* end,
                            const unsigned char** content, long* contentLen)
{
    int tag = 0;
    int xclass = 0;
    long len = 0;
    const unsigned char* p = *pp;
    long omax = end - p;

    if (omax <= 0)
        return 0;
    if ((ASN1_get_object(&p, &len, &tag, &xclass, omax) & 0x80) != 0)
        return 0;
    *content = p;
    *contentLen = len;
    *pp = p + len;
    return 1;
}

/* Extracts the raw bytes of PFX.authSafe's content OCTET STRING (the same
 * bytes PKCS12_verify_mac would MAC) without needing access to PKCS12's
 * opaque struct fields - PFX ::= SEQUENCE { version, ContentInfo, MacData? },
 * ContentInfo ::= SEQUENCE { OID contentType, [0] EXPLICIT OCTET STRING }. */
static int extractAuthSafeOctets(const unsigned char* der, long derLen,
                                 const unsigned char** outPtr, long* outLen)
{
    const unsigned char* end = der + derLen;
    const unsigned char* p = der;
    const unsigned char* seqContent = NULL;
    long seqLen = 0;
    const unsigned char* field = NULL;
    long fieldLen = 0;
    const unsigned char* ciContent = NULL;
    long ciLen = 0;
    const unsigned char* explicitContent = NULL;
    long explicitLen = 0;

    if (!getObjectContent(&p, end, &seqContent, &seqLen)) /* outer PFX SEQUENCE */
        return 0;

    p = seqContent;
    if (!getObjectContent(&p, seqContent + seqLen, &field, &fieldLen)) /* version INTEGER */
        return 0;

    if (!getObjectContent(&p, seqContent + seqLen, &ciContent, &ciLen)) /* authSafe ContentInfo SEQUENCE */
        return 0;

    p = ciContent;
    if (!getObjectContent(&p, ciContent + ciLen, &field, &fieldLen)) /* contentType OID */
        return 0;
    if (!getObjectContent(&p, ciContent + ciLen, &explicitContent, &explicitLen)) /* [0] EXPLICIT */
        return 0;

    p = explicitContent;
    return getObjectContent(&p, explicitContent + explicitLen, outPtr, outLen); /* OCTET STRING */
}

/* RFC 7292 Appendix B key derivation using a plain (non-keyed) digest -
 * matches both the generic algorithm and UAPKI's pbkdf1() (uapkic/pbkdf.c),
 * which uses a plain digest here regardless of which hash is selected. */
static int kupynaAppendixBKdf(const EVP_MD* md, const unsigned char* pass, int passLen,
                              const unsigned char* salt, int saltLen, int id,
                              int iterations, int nBytes, unsigned char* out)
{
    int v;
    int u;
    int sLen;
    int pLen;
    int iLen;
    unsigned char* D;
    unsigned char* I;
    unsigned char* Ai;
    unsigned char* B;
    EVP_MD_CTX* ctx;
    int ok = 0;
    int i = 0;
    int produced = 0;

    if (saltLen <= 0)
        return 0;

    v = EVP_MD_block_size(md);
    u = EVP_MD_size(md);
    sLen = v * ((saltLen + v - 1) / v);
    pLen = passLen > 0 ? v * ((passLen + v - 1) / v) : 0;
    iLen = sLen + pLen;
    D = OPENSSL_malloc((size_t) v);
    I = OPENSSL_malloc((size_t) (iLen > 0 ? iLen : 1));
    Ai = OPENSSL_malloc((size_t) u);
    B = OPENSSL_malloc((size_t) v);
    ctx = EVP_MD_CTX_new();

    if (D == NULL || I == NULL || Ai == NULL || B == NULL || ctx == NULL)
        goto err;

    memset(D, (unsigned char) id, (size_t) v);
    for (i = 0; i < sLen; ++i)
        I[i] = salt[i % saltLen];
    for (i = 0; i < pLen; ++i)
        I[sLen + i] = pass[i % passLen];

    while (produced < nBytes)
    {
        int cplen;
        int j;

        if (!EVP_DigestInit_ex(ctx, md, NULL) ||
            !EVP_DigestUpdate(ctx, D, (size_t) v) ||
            !EVP_DigestUpdate(ctx, I, (size_t) iLen) ||
            !EVP_DigestFinal_ex(ctx, Ai, NULL))
            goto err;
        for (j = 1; j < iterations; ++j)
        {
            if (!EVP_DigestInit_ex(ctx, md, NULL) ||
                !EVP_DigestUpdate(ctx, Ai, (size_t) u) ||
                !EVP_DigestFinal_ex(ctx, Ai, NULL))
                goto err;
        }

        cplen = (nBytes - produced) < u ? (nBytes - produced) : u;
        memcpy(out + produced, Ai, (size_t) cplen);
        produced += cplen;
        if (produced >= nBytes)
            break;

        for (j = 0; j < v; ++j)
            B[j] = Ai[j % u];
        for (j = 0; j < iLen; j += v)
        {
            int k;
            int carry = 1;
            for (k = v - 1; k >= 0; --k)
            {
                int sum = I[j + k] + B[k] + carry;
                I[j + k] = (unsigned char) sum;
                carry = sum >> 8;
            }
        }
    }
    ok = 1;

 err:
    EVP_MD_CTX_free(ctx);
    if (D) OPENSSL_clear_free(D, (size_t) v);
    if (I) OPENSSL_clear_free(I, (size_t) (iLen > 0 ? iLen : 1));
    if (Ai) OPENSSL_clear_free(Ai, (size_t) u);
    if (B) OPENSSL_clear_free(B, (size_t) v);
    return ok;
}

/*
 * OpenSSL's PKCS12_verify_mac always computes the integrity MAC as a
 * standard HMAC over an RFC 7292 Appendix B derived key - it has no
 * extension point for anything else. Real-world files using Kupyna-256
 * (DSTU 7564:2014) as the MacData digest instead compute the final MAC via
 * Kupyna's own native keyed-MAC construction (dstu7564kmac) applied
 * directly to the Appendix-B-derived key, not a generic HMAC(ipad/opad)
 * wrapper. Confirmed against the specinfo-ua/UAPKI reference implementation
 * (pkcs12_get_data_and_calc_mac/pbkdf1 in cm-pkcs12/pkcs12-utils.c and
 * uapkic/pbkdf.c) and verified byte-exact against a real-world file.
 *
 * Returns 1 if the MAC matches, 0 if it doesn't, -1 if this isn't a
 * Kupyna-256 MacData (caller should fall back to PKCS12_verify_mac).
 */
static int dstuKupynaVerifyMac(const unsigned char* der, long derLen, PKCS12* p12,
                               const char* password, int passLen)
{
    const ASN1_OCTET_STRING* macOct = NULL;
    const X509_ALGOR* macAlg = NULL;
    const ASN1_OCTET_STRING* saltOct = NULL;
    const ASN1_INTEGER* iterAsn = NULL;
    const ASN1_OBJECT* digestOid = NULL;
    int digestNid = NID_undef;
    long iter = 1;
    const EVP_MD* md = NULL;
    unsigned char* uniPass = NULL;
    int uniLen = 0;
    unsigned char dk[EVP_MAX_MD_SIZE];
    unsigned char mac[EVP_MAX_MD_SIZE];
    const unsigned char* content = NULL;
    long contentLen = 0;
    kupyna_ctx kctx;
    int mdSize;

    if (PKCS12_mac_present(p12) == 0)
        return -1;

    PKCS12_get0_mac(&macOct, &macAlg, &saltOct, &iterAsn, p12);
    if (macAlg == NULL)
        return -1;

    X509_ALGOR_get0(&digestOid, NULL, NULL, macAlg);
    digestNid = digestOid ? OBJ_obj2nid(digestOid) : NID_undef;
    if (digestNid != OBJ_sn2nid(KUPYNA256_SHORT_NAME))
        return -1;

    md = EVP_get_digestbynid(digestNid);
    if (md == NULL)
        return 0;
    mdSize = EVP_MD_size(md);

    iter = iterAsn ? ASN1_INTEGER_get(iterAsn) : 1;
    if (iter <= 0 || saltOct == NULL || macOct == NULL)
        return 0;

    if (!extractAuthSafeOctets(der, derLen, &content, &contentLen))
        return 0;

    if (OPENSSL_asc2uni(password != NULL ? password : "", password != NULL ? passLen : 0,
            &uniPass, &uniLen) == NULL)
        return 0;

    if (!kupynaAppendixBKdf(md, uniPass, uniLen,
            ASN1_STRING_get0_data(saltOct), ASN1_STRING_length(saltOct),
            PKCS12_MAC_ID, (int) iter, mdSize, dk))
    {
        OPENSSL_clear_free(uniPass, (size_t) uniLen);
        return 0;
    }
    OPENSSL_clear_free(uniPass, (size_t) uniLen);

    if (kupyna_init((size_t) mdSize * 8, &kctx) != 0)
        return 0;
    if (kupyna_kmac(&kctx, dk, (size_t) mdSize, (size_t) mdSize * 8,
            content, (size_t) contentLen * 8, mac) != 0)
        return 0;

    if (ASN1_STRING_length(macOct) != mdSize ||
        memcmp(ASN1_STRING_get0_data(macOct), mac, (size_t) mdSize) != 0)
        return 0;

    return 1;
}

int parsePKCS12(const void* data, size_t dataSize, const char* password, size_t passSize, KeyStore** ks)
{
    const unsigned char* ptr = data;
    PKCS12* pkcs12 = d2i_PKCS12(NULL, &ptr, dataSize);
    STACK_OF(PKCS7)* safes = NULL;
    size_t numKeys = 0;
    size_t numCerts = 0;
    size_t keyPos = 0;
    size_t certPos = 0;

    if (pkcs12 == NULL)
        return 0;

    {
        int kupynaMacResult = dstuKupynaVerifyMac((const unsigned char*) data, (long) dataSize,
                pkcs12, password, (int) passSize);
        if (kupynaMacResult == 0 ||
            (kupynaMacResult < 0 && PKCS12_verify_mac(pkcs12, password, passSize) == 0))
        {
            PKCS12_free(pkcs12);
            return 0;
        }
    }

    safes = PKCS12_unpack_authsafes(pkcs12);

    if (safes == NULL)
    {
        PKCS12_free(pkcs12);
        return 0;
    }

    if (countKeysCerts(safes, password, passSize, &numKeys, &numCerts) == 0 ||
        (numKeys == 0 && numCerts == 0))
    {
        sk_PKCS7_pop_free(safes, PKCS7_free);
        PKCS12_free(pkcs12);
        return 0;
    }

    *ks = KeyStoreNew(numKeys, numCerts);

    if (fromSafes(safes, password, passSize, *ks, &keyPos, &certPos) == 0)
    {
        KeyStoreFree(*ks);
        sk_PKCS7_pop_free(safes, PKCS7_free);
        PKCS12_free(pkcs12);
        return 0;
    }

    sk_PKCS7_pop_free(safes, PKCS7_free);
    PKCS12_free(pkcs12);

    return 1;
}

int readPKCS12(FILE* fp, const char* password, size_t passSize, KeyStore** ks)
{
    int res = 0;
    BIO* bio = BIO_new_fp(fp, 0);
    if (!bio)
        return 0;
    res = readPKCS12_bio(bio, password, passSize, ks);
    BIO_free(bio);
    return res;
}

int readPKCS12_bio(BIO* bio, const char* password, size_t passSize, KeyStore** ks)
{
    unsigned char buf[1024];
    BIO *mem = BIO_new(BIO_s_mem());
    size_t total = 0;
    size_t bytes = 0;
    size_t written = 0;
    char* ptr = NULL;
    int res = 0;
    for (;;)
    {
        if (!BIO_read_ex(bio, buf, sizeof(buf), &bytes))
        {
            if (total > 0)
                break;
            BIO_free(mem);
            return 0;
        }
        if (bytes == 0)
            break;
        if (!BIO_write_ex(mem, buf, bytes, &written))
        {
            BIO_free(mem);
            return 0;
        }
        total += bytes;
    }
    bytes = BIO_get_mem_data(mem, &ptr);
    if (bytes == 0 || ptr == NULL)
    {
        BIO_free(mem);
        return 0;
    }
    res = parsePKCS12(ptr, bytes, password, passSize, ks);
    BIO_free(mem);
    return res;
}
