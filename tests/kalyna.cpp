/*
 * Validates the Kalyna-256/256-CBC (DSTU 7624:2014, "Dstu7624cbc(256)")
 * EVP_CIPHER registered by the "dstu" engine:
 *  - a raw single-block (no padding, zero IV) encryption against the
 *    official reference implementation's Kalyna-256/256 test vector:
 *    https://github.com/Roman-Oliynykov/Kalyna-reference
 *  - a full encrypt/decrypt round trip (with PKCS7 padding, random-ish IV,
 *    multi-block input) to prove the CBC chaining and EVP block-buffering
 *    plumbing work end to end.
 */
#include "error.h"
#include "block.h"

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/objects.h>

#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

using DSTUEngine::OPENSSLError;
using DSTUEngine::checkBlock;
using DSTUEngine::makeBlock;

namespace
{

const EVP_CIPHER* getCipher(ENGINE* engine, const char* shortName)
{
    const int nid = OBJ_sn2nid(shortName);
    if (nid == NID_undef)
        throw std::runtime_error(std::string("getCipher: '") + shortName + "' was not registered.");

    const auto* cipher = ENGINE_get_cipher(engine, nid);
    if (cipher == nullptr)
        throw std::runtime_error(std::string("getCipher: failed to get cipher '") + shortName + "'. " + OPENSSLError());
    return cipher;
}

/* Single 32-byte block, exercises the raw block transform (kalyna_encipher)
 * through the EVP_CIPHER wrapper directly: an exact-block-size Update()
 * call produces ciphertext with no padding involved (padding is only added
 * by Final(), which is not called here). */
void checkRawBlock(ENGINE* engine)
{
    const auto* cipher = getCipher(engine, "dstu7624cbc256");

    const auto key = makeBlock("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    const auto plaintext = makeBlock("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
    const std::string expectedCiphertextHex =
        "F66E3D570EC92135AEDAE323DCBD2A8CA03963EC206A0D5A88385C24617FD92C";
    unsigned char iv[32] = {0};

    auto* ctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(ctx, cipher, engine, key.data(), iv) == 0)
        throw std::runtime_error("checkRawBlock: EncryptInit failed. " + OPENSSLError());

    std::vector<unsigned char> out(plaintext.size() + 32);
    int outl = 0;
    if (EVP_EncryptUpdate(ctx, out.data(), &outl, plaintext.data(), (int) plaintext.size()) == 0)
        throw std::runtime_error("checkRawBlock: EncryptUpdate failed. " + OPENSSLError());
    EVP_CIPHER_CTX_free(ctx);

    if (outl != (int) plaintext.size())
        throw std::runtime_error("checkRawBlock: unexpected output size.");

    checkBlock(out.data(), (size_t) outl, expectedCiphertextHex);
}

/* Multi-block, non-block-aligned plaintext with PKCS7 padding: proves the
 * generic EVP block-buffering/padding path works with this cipher, and that
 * encrypt then decrypt round-trips back to the original message. */
void checkRoundTrip(ENGINE* engine)
{
    const auto* cipher = getCipher(engine, "dstu7624cbc256");

    const auto key = makeBlock("030A11181F262D343B424950575E656C737A81888F969DA4ABB2B9C0C7CED5DC");
    const auto iv = makeBlock("1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100");
    const std::string message = "Kalyna-256/256-CBC round trip test, deliberately not a multiple of the block size.";

    auto* encCtx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(encCtx, cipher, engine, key.data(), iv.data()) == 0)
        throw std::runtime_error("checkRoundTrip: EncryptInit failed. " + OPENSSLError());

    std::vector<unsigned char> ciphertext(message.size() + 64);
    int outl = 0;
    int total = 0;
    if (EVP_EncryptUpdate(encCtx, ciphertext.data(), &outl,
            reinterpret_cast<const unsigned char*>(message.data()), (int) message.size()) == 0)
        throw std::runtime_error("checkRoundTrip: EncryptUpdate failed. " + OPENSSLError());
    total += outl;
    if (EVP_EncryptFinal_ex(encCtx, ciphertext.data() + total, &outl) == 0)
        throw std::runtime_error("checkRoundTrip: EncryptFinal failed. " + OPENSSLError());
    total += outl;
    EVP_CIPHER_CTX_free(encCtx);

    if (total % 32 != 0)
        throw std::runtime_error("checkRoundTrip: ciphertext not block-aligned; padding didn't run.");

    auto* decCtx = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex(decCtx, cipher, engine, key.data(), iv.data()) == 0)
        throw std::runtime_error("checkRoundTrip: DecryptInit failed. " + OPENSSLError());

    std::vector<unsigned char> recovered(total + 32);
    int declen = 0;
    int dectotal = 0;
    if (EVP_DecryptUpdate(decCtx, recovered.data(), &declen, ciphertext.data(), total) == 0)
        throw std::runtime_error("checkRoundTrip: DecryptUpdate failed. " + OPENSSLError());
    dectotal += declen;
    if (EVP_DecryptFinal_ex(decCtx, recovered.data() + dectotal, &declen) == 0)
        throw std::runtime_error("checkRoundTrip: DecryptFinal failed (bad padding?). " + OPENSSLError());
    dectotal += declen;
    EVP_CIPHER_CTX_free(decCtx);

    if ((size_t) dectotal != message.size() ||
        std::memcmp(recovered.data(), message.data(), message.size()) != 0)
        throw std::runtime_error("checkRoundTrip: recovered plaintext does not match original message.");
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

    checkRawBlock(engine);
    checkRoundTrip(engine);

    ENGINE_finish(engine);
    ENGINE_free(engine);

    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();

    return 0;
}
