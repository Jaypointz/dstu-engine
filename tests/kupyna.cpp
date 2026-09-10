/*
 * Validates the Kupyna (DSTU 7564:2014) EVP_MD digests registered by the
 * "dstu" engine against the official reference implementation's test
 * vectors for the empty-string input:
 * https://github.com/Roman-Oliynykov/Kupyna-reference
 * Also validates that a DSTU 4145 key can actually sign/verify using Kupyna
 * as the digest (i.e. that the pmeth.c EVP_PKEY_CTRL_MD relaxation works).
 */
#include "error.h"
#include "block.h"

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

using DSTUEngine::OPENSSLError;
using DSTUEngine::checkBlock;

namespace
{

void checkDigest(ENGINE* engine, const char* shortName, const std::string& expectedHex)
{
    const int nid = OBJ_sn2nid(shortName);
    if (nid == NID_undef)
        throw std::runtime_error(std::string("checkDigest: '") + shortName + "' was not registered.");

    const auto* mdt = ENGINE_get_digest(engine, nid);
    if (mdt == nullptr)
        throw std::runtime_error(std::string("checkDigest: failed to get digest '") + shortName + "'. " + OPENSSLError());

    std::vector<unsigned char> hash(static_cast<size_t>(EVP_MD_size(mdt)));
    unsigned int size = 0;
    if (EVP_Digest("", 0, hash.data(), &size, mdt, engine) == 0)
        throw std::runtime_error(std::string("checkDigest: failed to calculate '") + shortName + "'. " + OPENSSLError());
    if (size != hash.size())
        throw std::runtime_error(std::string("checkDigest: unexpected size for '") + shortName + "'.");

    checkBlock(hash.data(), hash.size(), expectedHex);
}

EVP_PKEY* readPubKey(const std::string& file)
{
    FILE* fp = fopen(file.c_str(), "r");
    if (fp == nullptr)
        throw std::runtime_error("readPubKey: failed to open file '" + file + "'.");
    auto* res = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (res == nullptr)
        throw std::runtime_error("readPubKey: failed to read public key from '" + file + "'. " + OPENSSLError());
    return res;
}

EVP_PKEY* readPrivateKey(const std::string& file, const std::string& password)
{
    std::vector<unsigned char> pwd(password.begin(), password.end());
    FILE* fp = fopen(file.c_str(), "r");
    if (fp == nullptr)
        throw std::runtime_error("readPrivateKey: failed to open file '" + file + "'.");
    auto* res = PEM_read_PrivateKey(fp, nullptr, nullptr, pwd.data());
    fclose(fp);
    if (res == nullptr)
        throw std::runtime_error("readPrivateKey: failed to read private key from '" + file + "'. " + OPENSSLError());
    return res;
}

/* Signs and verifies with a real DSTU 4145 key, using Kupyna as the digest -
 * this is exactly the EVP_PKEY_CTRL_MD path the pmeth.c relaxation opens up. */
void checkSignVerifyWithDigest(ENGINE* engine, const char* digestShortName)
{
    auto* pub = readPubKey("public1.pem");
    auto* priv = readPrivateKey("private1.pem", "123456");
    const auto* md = ENGINE_get_digest(engine, OBJ_sn2nid(digestShortName));
    if (md == nullptr)
    {
        EVP_PKEY_free(pub);
        EVP_PKEY_free(priv);
        throw std::runtime_error(std::string("checkSignVerifyWithDigest: failed to get digest '") + digestShortName + "'.");
    }

    const std::string data = "Kupyna + DSTU 4145 pairing test.";

    auto* signCtx = EVP_MD_CTX_create();
    if (EVP_DigestSignInit(signCtx, nullptr, md, engine, priv) == 0)
        throw std::runtime_error("checkSignVerifyWithDigest: DigestSignInit failed. " + OPENSSLError());
    if (EVP_DigestSignUpdate(signCtx, data.data(), data.size()) == 0)
        throw std::runtime_error("checkSignVerifyWithDigest: DigestSignUpdate failed. " + OPENSSLError());
    size_t sigLen = 0;
    if (EVP_DigestSignFinal(signCtx, nullptr, &sigLen) == 0)
        throw std::runtime_error("checkSignVerifyWithDigest: DigestSignFinal (size) failed. " + OPENSSLError());
    std::vector<unsigned char> sig(sigLen);
    if (EVP_DigestSignFinal(signCtx, sig.data(), &sigLen) == 0)
        throw std::runtime_error("checkSignVerifyWithDigest: DigestSignFinal failed. " + OPENSSLError());
    EVP_MD_CTX_destroy(signCtx);

    auto* verifyCtx = EVP_MD_CTX_create();
    if (EVP_DigestVerifyInit(verifyCtx, nullptr, md, engine, pub) == 0)
        throw std::runtime_error("checkSignVerifyWithDigest: DigestVerifyInit failed. " + OPENSSLError());
    if (EVP_DigestVerifyUpdate(verifyCtx, data.data(), data.size()) == 0)
        throw std::runtime_error("checkSignVerifyWithDigest: DigestVerifyUpdate failed. " + OPENSSLError());
    if (EVP_DigestVerifyFinal(verifyCtx, sig.data(), sig.size()) != 1)
        throw std::runtime_error("checkSignVerifyWithDigest: signature did not verify. " + OPENSSLError());
    EVP_MD_CTX_destroy(verifyCtx);

    EVP_PKEY_free(pub);
    EVP_PKEY_free(priv);
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

    checkDigest(engine, "kupyna256", "CD5101D1CCDF0D1D1F4ADA56E888CD724CA1A0838A3521E7131D4FB78D0F5EB6");
    checkDigest(engine, "kupyna512",
        "656B2F4CD71462388B64A37043EA55DBE445D452AECD46C3298343314EF04019BCFA3F04265A9857F91BE91FCE197096187CEDA78C9C1C021C294A0689198538");

    checkSignVerifyWithDigest(engine, "kupyna256");
    checkSignVerifyWithDigest(engine, "kupyna512");

    ENGINE_finish(engine);
    ENGINE_free(engine);

    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();

    return 0;
}
