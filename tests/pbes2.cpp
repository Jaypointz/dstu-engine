/*
 * End-to-end test of the PBES2 shim in kupyna_pbe.c: encrypts/decrypts data
 * using PBES2 = PBKDF2(Dstu7564mac-256) + Dstu7624cbc(256) (Kalyna-256/256
 * CBC), the exact algorithm combination found in real-world PKCS12 files
 * provided by Ukrainian CA (Certification Authority) that stock OpenSSL cannot handle.
 * Also checks a standard PBES2 combination (AES-256-CBC + PBKDF2-HMAC-SHA256) still round-trips
 * correctly, since the shim shadows NID_pbes2's PBE handler process-wide.
 */
#include "error.h"

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

using DSTUEngine::OPENSSLError;

namespace
{

void roundTrip(const char* label, X509_ALGOR* algor, const std::string& pass, const std::string& plaintext)
{
    std::vector<unsigned char> ciphertext(plaintext.size() + 64);
    int outl = 0;
    int tmplen = 0;
    int total = 0;

    auto* encCtx = EVP_CIPHER_CTX_new();
    if (EVP_PBE_CipherInit(algor->algorithm, pass.c_str(), (int) pass.size(), algor->parameter, encCtx, 1) <= 0)
        throw std::runtime_error(std::string(label) + ": EVP_PBE_CipherInit (encrypt) failed. " + OPENSSLError());
    if (EVP_EncryptUpdate(encCtx, ciphertext.data(), &outl,
            reinterpret_cast<const unsigned char*>(plaintext.data()), (int) plaintext.size()) == 0)
        throw std::runtime_error(std::string(label) + ": EncryptUpdate failed. " + OPENSSLError());
    total = outl;
    if (EVP_EncryptFinal_ex(encCtx, ciphertext.data() + total, &tmplen) == 0)
        throw std::runtime_error(std::string(label) + ": EncryptFinal failed. " + OPENSSLError());
    total += tmplen;
    EVP_CIPHER_CTX_free(encCtx);

    std::vector<unsigned char> recovered(total + 64);
    int declen = 0;
    int dectotal = 0;

    auto* decCtx = EVP_CIPHER_CTX_new();
    if (EVP_PBE_CipherInit(algor->algorithm, pass.c_str(), (int) pass.size(), algor->parameter, decCtx, 0) <= 0)
        throw std::runtime_error(std::string(label) + ": EVP_PBE_CipherInit (decrypt) failed. " + OPENSSLError());
    if (EVP_DecryptUpdate(decCtx, recovered.data(), &declen, ciphertext.data(), total) == 0)
        throw std::runtime_error(std::string(label) + ": DecryptUpdate failed. " + OPENSSLError());
    dectotal = declen;
    if (EVP_DecryptFinal_ex(decCtx, recovered.data() + dectotal, &declen) == 0)
        throw std::runtime_error(std::string(label) + ": DecryptFinal failed (bad padding?). " + OPENSSLError());
    dectotal += declen;
    EVP_CIPHER_CTX_free(decCtx);

    if ((size_t) dectotal != plaintext.size() ||
        std::memcmp(recovered.data(), plaintext.data(), plaintext.size()) != 0)
        throw std::runtime_error(std::string(label) + ": recovered plaintext mismatch.");

    printf("%s: OK\n", label);
}

void checkKalynaKupynaPbes2(ENGINE* engine)
{
    const int cipherNid = OBJ_sn2nid("dstu7624cbc256");
    const int prfNid = OBJ_sn2nid("dstu7564mac256");
    if (cipherNid == NID_undef || prfNid == NID_undef)
        throw std::runtime_error("checkKalynaKupynaPbes2: algorithms not registered.");

    const auto* cipher = ENGINE_get_cipher(engine, cipherNid);
    if (cipher == nullptr)
        throw std::runtime_error("checkKalynaKupynaPbes2: failed to get cipher. " + OPENSSLError());

    unsigned char salt[16];
    unsigned char iv[32]; /* Kalyna-256/256's block/IV size - too big for
                            * PKCS5_pbe2_set_iv's internal EVP_MAX_IV_LENGTH
                            * (16-byte) stack buffer, so build the PBE2PARAM
                            * by hand instead of using that helper. */
    if (RAND_bytes(salt, sizeof(salt)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1)
        throw std::runtime_error("checkKalynaKupynaPbes2: RAND_bytes failed.");

    auto* kdf = PBKDF2PARAM_new();
    auto* osalt = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(osalt, salt, (int) sizeof(salt));
    kdf->salt->type = V_ASN1_OCTET_STRING;
    kdf->salt->value.octet_string = osalt;
    ASN1_INTEGER_set(kdf->iter, 1000);
    kdf->prf = X509_ALGOR_new();
    X509_ALGOR_set0(kdf->prf, OBJ_nid2obj(prfNid), V_ASN1_NULL, nullptr);

    auto* keyfunc = X509_ALGOR_new();
    keyfunc->algorithm = OBJ_nid2obj(NID_id_pbkdf2);
    ASN1_TYPE_pack_sequence(ASN1_ITEM_rptr(PBKDF2PARAM), kdf, &keyfunc->parameter);
    PBKDF2PARAM_free(kdf);

    auto* pbe2 = PBE2PARAM_new();
    X509_ALGOR_free(pbe2->keyfunc);
    pbe2->keyfunc = keyfunc;
    pbe2->encryption->algorithm = OBJ_nid2obj(cipherNid);
    pbe2->encryption->parameter = ASN1_TYPE_new();
    /* Encode via the cipher's own set_asn1_parameters (SEQUENCE { OCTET
     * STRING iv }, confirmed against real-world key material) rather than
     * duplicating that format here. */
    {
        auto* ivCtx = EVP_CIPHER_CTX_new();
        if (EVP_CipherInit_ex(ivCtx, cipher, engine, nullptr, iv, 0) == 0)
            throw std::runtime_error("checkKalynaKupynaPbes2: iv CipherInit failed. " + OPENSSLError());
        if (EVP_CIPHER_param_to_asn1(ivCtx, pbe2->encryption->parameter) <= 0)
            throw std::runtime_error("checkKalynaKupynaPbes2: param_to_asn1 failed. " + OPENSSLError());
        EVP_CIPHER_CTX_free(ivCtx);
    }

    auto* algor = X509_ALGOR_new();
    algor->algorithm = OBJ_nid2obj(NID_pbes2);
    ASN1_TYPE_pack_sequence(ASN1_ITEM_rptr(PBE2PARAM), pbe2, &algor->parameter);
    PBE2PARAM_free(pbe2);

    roundTrip("Kalyna-256/256-CBC + PBKDF2(Dstu7564mac-256)", algor,
        "correct horse battery staple",
        "This is a private key placeholder, long enough to span more than one Kalyna-256 block.");

    X509_ALGOR_free(algor);
}

void checkStandardPbes2StillWorks()
{
    unsigned char salt[16];
    if (RAND_bytes(salt, sizeof(salt)) != 1)
        throw std::runtime_error("checkStandardPbes2StillWorks: RAND_bytes failed.");

    auto* algor = PKCS5_pbe2_set_iv(EVP_aes_256_cbc(), 1000, salt, sizeof(salt), nullptr, NID_hmacWithSHA256);
    if (algor == nullptr)
        throw std::runtime_error("checkStandardPbes2StillWorks: PKCS5_pbe2_set_iv failed. " + OPENSSLError());

    roundTrip("AES-256-CBC + PBKDF2-HMAC-SHA256 (unaffected)", algor,
        "another password",
        "Standard PBES2 combinations must be unaffected by shadowing NID_pbes2.");

    X509_ALGOR_free(algor);
}

}

int main()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, nullptr);

    if (CONF_modules_load_file("openssl.cnf", nullptr, 0) <= 0)
        throw std::runtime_error("main: failed to load config file. " + OPENSSLError());

    auto* engine = ENGINE_by_id("dstu");
    if (engine == nullptr)
        throw std::runtime_error("main: failed to load engine. " + OPENSSLError());
    if (ENGINE_init(engine) == 0)
        throw std::runtime_error("main: failed to initialize engine. " + OPENSSLError());

    checkKalynaKupynaPbes2(engine);
    checkStandardPbes2StillWorks();

    ENGINE_finish(engine);
    ENGINE_free(engine);

    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();

    return 0;
}
