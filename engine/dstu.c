#include "md.h"
#include "kupyna_md.h"
#include "cipher.h"
#include "kalyna_cipher.h"
#include "kupyna_pbe.h"
#include "rbg.h"
#include "pmeth.h"
#include "ameth.h"
#include "err.h"

#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/ossl_typ.h>

#include <string.h>

static const char *engine_dstu_id = "dstu";
static const char *engine_dstu_name = "DSTU engine by Maksym Mamontov";

/* No NID is baked into OpenSSL for Kupyna (DSTU 7564:2014), unlike the other
 * DSTU algorithms here, so it's registered dynamically at bind time instead.
 * Confirmed against the official Ukrainian PKI OID registry (also matches
 * Bouncy Castle's UAObjectIdentifiers.dstu7564digest_256/512). */
#define KUPYNA256_OID "1.2.804.2.1.1.1.1.2.2.1"
#define KUPYNA512_OID "1.2.804.2.1.1.1.1.2.2.3"

/* Also not baked into OpenSSL. "Dstu7624cbc(256)" per the official Ukrainian
 * PKI OID registry (OBJ_ua_pki arc), confirmed against real key material. */
#define KALYNA256CBC_OID "1.2.804.2.1.1.1.1.1.3.5.2"

/* Dstu7564mac(256/384/512): the keyed MAC construction (not HMAC), used as
 * the PBKDF2 PRF by real-world PKCS12 files. Only registered as OIDs (so
 * ASN1 parsing/printing can recognize them) - there's no EVP_MD/EVP_PBE_TYPE_PRF
 * entry for these since neither fits a non-HMAC construction; see
 * kupyna_pbe.c for how PBKDF2 actually uses them. */
#define KUPYNA_MAC256_OID "1.2.804.2.1.1.1.1.2.2.4"
#define KUPYNA_MAC384_OID "1.2.804.2.1.1.1.1.2.2.5"
#define KUPYNA_MAC512_OID "1.2.804.2.1.1.1.1.2.2.6"

static int dstu_nids[] =
{
    NID_dstu4145le, NID_dstu4145be
};
/* Slots 1 and 2 are filled in at bind time if Kupyna NID registration succeeds. */
static int digest_nids[3] =
{
    NID_dstu34311, NID_undef, NID_undef
};
static size_t digest_nids_count = 1;
/* Slot 1 is filled in at bind time if Kalyna NID registration succeeds. */
static int cipher_nids[2] =
{
    NID_dstu28147_cfb, NID_undef
};
static size_t cipher_nids_count = 1;

static const int DSTU_ENGINE_FLAGS =
    ENGINE_METHOD_PKEY_METHS | ENGINE_METHOD_PKEY_ASN1_METHS |
    ENGINE_METHOD_DIGESTS | ENGINE_METHOD_CIPHERS | ENGINE_METHOD_RAND;

static EVP_MD *dstu_md = NULL;
static EVP_CIPHER *dstu_cipher = NULL;
static EVP_PKEY_METHOD *dstu_pkey_methods[] = {NULL, NULL};
static EVP_PKEY_ASN1_METHOD *dstu_asn1_methods[] = {NULL, NULL};

static int kupyna256_nid = NID_undef;
static int kupyna512_nid = NID_undef;
static EVP_MD *kupyna256_md = NULL;
static EVP_MD *kupyna512_md = NULL;

static int kalyna256cbc_nid = NID_undef;
static EVP_CIPHER *kalyna256cbc_cipher = NULL;

static int kupyna_mac256_nid = NID_undef;
static int kupyna_mac384_nid = NID_undef;
static int kupyna_mac512_nid = NID_undef;

static EVP_MD *dstu_md_get()
{
    if (dstu_md == NULL)
        dstu_md = dstu_digest_new();
    return dstu_md;
}

static EVP_MD *kupyna256_md_get()
{
    if (kupyna256_md == NULL && kupyna256_nid != NID_undef)
        kupyna256_md = kupyna256_digest_new(kupyna256_nid);
    return kupyna256_md;
}

static EVP_MD *kupyna512_md_get()
{
    if (kupyna512_md == NULL && kupyna512_nid != NID_undef)
        kupyna512_md = kupyna512_digest_new(kupyna512_nid);
    return kupyna512_md;
}

static EVP_CIPHER *kalyna256cbc_cipher_get()
{
    if (kalyna256cbc_cipher == NULL && kalyna256cbc_nid != NID_undef)
        kalyna256cbc_cipher = kalyna256cbc_cipher_new(kalyna256cbc_nid);
    return kalyna256cbc_cipher;
}

/* Additive and best-effort: failure here must not break the rest of the
 * engine, so it's not folded into dstu_bind()'s all-or-nothing chain. */
static void kupyna_register_nids(void)
{
    kupyna256_nid = OBJ_create(KUPYNA256_OID, "kupyna256", "DSTU 7564:2014 Kupyna-256");
    kupyna512_nid = OBJ_create(KUPYNA512_OID, "kupyna512", "DSTU 7564:2014 Kupyna-512");

    if (kupyna256_nid != NID_undef)
        digest_nids[digest_nids_count++] = kupyna256_nid;
    if (kupyna512_nid != NID_undef)
        digest_nids[digest_nids_count++] = kupyna512_nid;
}

/* Additive and best-effort, same rationale as kupyna_register_nids(). */
static void kalyna_register_nids(void)
{
    kalyna256cbc_nid = OBJ_create(KALYNA256CBC_OID, "dstu7624cbc256", "DSTU 7624:2014 Kalyna-256/256-CBC");

    if (kalyna256cbc_nid != NID_undef)
        cipher_nids[cipher_nids_count++] = kalyna256cbc_nid;
}

/* Additive and best-effort, same rationale as kupyna_register_nids(). Only
 * registers the OIDs (see kupyna_pbe.h) - dstu_pbe_set_mac_nids() tells the
 * PBES2 shim about whichever of these actually registered successfully. */
static void kupyna_mac_register_nids(void)
{
    kupyna_mac256_nid = OBJ_create(KUPYNA_MAC256_OID, "dstu7564mac256", "DSTU 7564:2014 Kupyna MAC-256");
    kupyna_mac384_nid = OBJ_create(KUPYNA_MAC384_OID, "dstu7564mac384", "DSTU 7564:2014 Kupyna MAC-384");
    kupyna_mac512_nid = OBJ_create(KUPYNA_MAC512_OID, "dstu7564mac512", "DSTU 7564:2014 Kupyna MAC-512");
    dstu_pbe_set_mac_nids(kupyna_mac256_nid, kupyna_mac384_nid, kupyna_mac512_nid);
}

static EVP_CIPHER *dstu_cipher_get()
{
    if (dstu_cipher == NULL)
        dstu_cipher = dstu_cipher_new();
    return dstu_cipher;
}

static EVP_PKEY_METHOD *dstu_pkey_meth_get(int nid)
{
    unsigned long long i = 0;
    for (i = 0; i < sizeof(dstu_nids) / sizeof(int); ++i)
    {
        if (nid == dstu_nids[i])
        {
            if (dstu_pkey_methods[i] == NULL)
                dstu_pkey_methods[i] = dstu_pkey_meth_new(nid);
            return dstu_pkey_methods[i];
        }
    }

    return NULL;
}

static EVP_PKEY_ASN1_METHOD *dstu_asn1_meth_get(int nid)
{
    unsigned long long i = 0;
    for (i = 0; i < sizeof(dstu_nids) / sizeof(int); ++i)
    {
        if (nid == dstu_nids[i])
        {
            if (dstu_asn1_methods[i] == NULL)
                dstu_asn1_methods[i] = dstu_asn1_meth_new(nid);
            return dstu_asn1_methods[i];
        }
    }

    return NULL;
}

static int dstu_engine_init(ENGINE *e)
{
    (void) e; // Unused
    return 1;
}

static int dstu_engine_finish(ENGINE *e)
{
    (void) e; // Unused
    dstu_cipher_free(dstu_cipher);
    dstu_digest_free(dstu_md);
    if (kupyna256_md)
        kupyna_digest_free(kupyna256_md);
    if (kupyna512_md)
        kupyna_digest_free(kupyna512_md);
    if (kalyna256cbc_cipher)
        kalyna_cipher_free(kalyna256cbc_cipher);

    ERR_unload_DSTU_strings();

    return 1;
}

static int dstu_digests(ENGINE *e, const EVP_MD **digest, const int **nids,
                        int nid)
{
    (void) e; // Unused
    if (digest && nid)
    {
        if (NID_dstu34311 == nid)
        {
            *digest = dstu_md_get();
            return 1;
        }
        if (kupyna256_nid != NID_undef && nid == kupyna256_nid)
        {
            *digest = kupyna256_md_get();
            return 1;
        }
        if (kupyna512_nid != NID_undef && nid == kupyna512_nid)
        {
            *digest = kupyna512_md_get();
            return 1;
        }
        return 0;
    }
    else
    {
        if (!nids)
            return -1;
        *nids = digest_nids;
        return (int) digest_nids_count;
    }
}

static int dstu_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids,
                        int nid)
{
    (void) e; // Unused
    if (cipher && nid)
    {
        if (NID_dstu28147_cfb == nid)
        {
            *cipher = dstu_cipher_get();
            return 1;
        }
        if (kalyna256cbc_nid != NID_undef && nid == kalyna256cbc_nid)
        {
            *cipher = kalyna256cbc_cipher_get();
            return 1;
        }
        return 0;
    }
    else
    {
        if (!nids)
            return -1;
        *nids = cipher_nids;
        return (int) cipher_nids_count;
    }
}

static int dstu_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids,
                           int nid)
{
    (void) e; // Unused
    if (!pmeth)
    {
        *nids = dstu_nids;
        return sizeof(dstu_nids) / sizeof(int);
    }

    *pmeth = dstu_pkey_meth_get(nid);
    if (*pmeth != NULL)
        return 1;

    return 0;
}

static int dstu_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth,
                           const int **nids, int nid)
{
    (void) e; // Unused
    if (!ameth)
    {
        *nids = dstu_nids;
        return sizeof(dstu_nids) / sizeof(int);
    }

    *ameth = dstu_asn1_meth_get(nid);
    if (*ameth != NULL)
        return 1;

    return 0;
}

static int dstu_bind(ENGINE *e, const char *id)
{
    if (id && strcmp(id, engine_dstu_id))
        return 0;

    kupyna_register_nids();
    kalyna_register_nids();
    kupyna_mac_register_nids();

    if (!ENGINE_set_id(e, engine_dstu_id) ||
        !ENGINE_set_name(e, engine_dstu_name) ||
        !ENGINE_set_init_function(e, dstu_engine_init) ||
        !ENGINE_set_finish_function(e, dstu_engine_finish) ||
        !ENGINE_set_digests(e, dstu_digests) ||
        !ENGINE_set_ciphers(e, dstu_ciphers) ||
        !ENGINE_set_RAND(e, &dstu_rand_meth) ||
        !ENGINE_set_pkey_meths(e, dstu_pkey_meths) ||
        !ENGINE_set_pkey_asn1_meths(e, dstu_asn1_meths) ||
        !ENGINE_set_flags(e, DSTU_ENGINE_FLAGS) ||
        !ENGINE_register_digests(e) ||
        !ENGINE_register_ciphers(e) ||
        !ENGINE_register_pkey_meths(e) ||
        !ENGINE_register_pkey_asn1_meths(e) ||
        !EVP_add_digest(dstu_md_get()) ||
        !EVP_add_cipher(dstu_cipher_get()) ||
        !EVP_PBE_alg_add_type(EVP_PBE_TYPE_PRF, NID_hmacWithDstu34311, -1, NID_dstu34311, NULL) || /* Adding our algorithms to support PBKDF2 */
        /* Shadows NID_pbes2's PBE handler (see kupyna_pbe.c) so PBKDF2 with
         * a Dstu7564mac PRF works; transparently delegates to OpenSSL's own
         * handler for every other PBES2 combination, so this is safe to
         * register unconditionally. */
        !EVP_PBE_alg_add_type(EVP_PBE_TYPE_OUTER, NID_pbes2, -1, -1, dstu_pbes2_keyivgen))
    {
        DSTUerr(DSTU_F_BIND_DSTU, ERR_R_EVP_LIB);
        return 0;
    }

    if (kupyna256_md_get())
        EVP_add_digest(kupyna256_md_get());
    if (kupyna512_md_get())
        EVP_add_digest(kupyna512_md_get());
    if (kalyna256cbc_cipher_get())
        EVP_add_cipher(kalyna256cbc_cipher_get());

    ERR_load_DSTU_strings();

    return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(dstu_bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
