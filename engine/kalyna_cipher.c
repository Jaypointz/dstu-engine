/*
 * EVP_CIPHER wrapper around the Kalyna block cipher (DSTU 7624:2014) core in
 * dstulib/kalyna, registering the Kalyna-256/256-CBC variant
 * ("Dstu7624cbc(256)"). PKCS7 padding and CBC chaining are implemented here
 * rather than left to the generic EVP block-buffering path: OpenSSL's
 * legacy EVP_CIPHER_CTX code hard-asserts block_size is 1, 8 or 16
 * (crypto/evp/evp_enc.c), so a 32-byte block cipher must be registered with
 * EVP_CIPH_FLAG_CUSTOM_CIPHER and do all of its own buffering/padding, the
 * same way this engine's DSTU 28147 CFB cipher (cipher.c) manages its own
 * partial-block state instead of relying on the generic path. The 16-byte
 * EVP_MAX_IV_LENGTH is also too small for our 32-byte IV, so EVP_CIPH_CUSTOM_IV
 * is set and the IV is kept in our own context instead of the CTX's built-in
 * (too-small) iv field.
 */
#include "kalyna_cipher.h"

#include "kalyna/kalyna.h"

#include <openssl/asn1.h>
#include <openssl/evp.h>

#include <stdint.h>
#include <string.h>

#define KALYNA256_BLOCK_SIZE 32 /* 256 bits */
#define KALYNA256_KEY_SIZE 32   /* 256 bits */
#define KALYNA256_BLOCK_WORDS (KALYNA256_BLOCK_SIZE / 8)

struct kalyna256cbc_ctx
{
    kalyna_ctx cipher;
    int have_key;
    unsigned char iv[KALYNA256_BLOCK_SIZE];      /* current CBC chaining value */
    unsigned char pending[KALYNA256_BLOCK_SIZE]; /* input bytes not yet forming a full block */
    size_t pending_len;                          /* 0..31 */
    unsigned char held[KALYNA256_BLOCK_SIZE];    /* decrypt only: last decrypted block, held back for de-padding */
    int held_valid;                              /* decrypt only */
};

static void kalyna_cbc_encrypt_block(struct kalyna256cbc_ctx *kctx, const unsigned char *in_block, unsigned char *out_block)
{
    unsigned char xored[KALYNA256_BLOCK_SIZE];
    uint64_t words_in[KALYNA256_BLOCK_WORDS];
    uint64_t words_out[KALYNA256_BLOCK_WORDS];
    size_t i;

    for (i = 0; i < KALYNA256_BLOCK_SIZE; ++i)
        xored[i] = (unsigned char)(in_block[i] ^ kctx->iv[i]);
    memcpy(words_in, xored, sizeof(words_in));
    kalyna_encipher(words_in, &kctx->cipher, words_out);
    memcpy(out_block, words_out, KALYNA256_BLOCK_SIZE);
    memcpy(kctx->iv, out_block, KALYNA256_BLOCK_SIZE);
}

static void kalyna_cbc_decrypt_block(struct kalyna256cbc_ctx *kctx, const unsigned char *in_block, unsigned char *out_block)
{
    uint64_t words_in[KALYNA256_BLOCK_WORDS];
    uint64_t words_out[KALYNA256_BLOCK_WORDS];
    unsigned char prev_iv[KALYNA256_BLOCK_SIZE];
    size_t i;

    memcpy(prev_iv, kctx->iv, KALYNA256_BLOCK_SIZE);
    memcpy(kctx->iv, in_block, KALYNA256_BLOCK_SIZE);
    memcpy(words_in, in_block, sizeof(words_in));
    kalyna_decipher(words_in, &kctx->cipher, words_out);
    memcpy(out_block, words_out, KALYNA256_BLOCK_SIZE);
    for (i = 0; i < KALYNA256_BLOCK_SIZE; ++i)
        out_block[i] = (unsigned char)(out_block[i] ^ prev_iv[i]);
}

static int kalyna256cbc_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    struct kalyna256cbc_ctx *kctx = (struct kalyna256cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    (void) enc;

    if (key)
    {
        uint64_t key_words[KALYNA256_BLOCK_WORDS];
        memcpy(key_words, key, sizeof(key_words));
        if (kalyna_init(256, 256, &kctx->cipher) != 0)
            return 0;
        kalyna_key_expand(key_words, &kctx->cipher);
        kctx->have_key = 1;
    }

    if (iv)
        memcpy(kctx->iv, iv, KALYNA256_BLOCK_SIZE);

    kctx->pending_len = 0;
    kctx->held_valid = 0;

    return 1;
}

/* out must have room for at least inl + KALYNA256_BLOCK_SIZE bytes. */
static int kalyna256cbc_encrypt(struct kalyna256cbc_ctx *kctx, unsigned char *out,
                                const unsigned char *in, size_t inl)
{
    size_t produced = 0;
    size_t remaining = inl;

    if (in == NULL) /* Final: pad the last (possibly empty) partial block. */
    {
        unsigned char block[KALYNA256_BLOCK_SIZE];
        unsigned char pad = (unsigned char)(KALYNA256_BLOCK_SIZE - kctx->pending_len);
        size_t i;

        memcpy(block, kctx->pending, kctx->pending_len);
        for (i = kctx->pending_len; i < KALYNA256_BLOCK_SIZE; ++i)
            block[i] = pad;
        kalyna_cbc_encrypt_block(kctx, block, out);
        kctx->pending_len = 0;
        return KALYNA256_BLOCK_SIZE;
    }

    if (kctx->pending_len > 0)
    {
        size_t need = KALYNA256_BLOCK_SIZE - kctx->pending_len;
        if (remaining < need)
        {
            memcpy(kctx->pending + kctx->pending_len, in, remaining);
            kctx->pending_len += remaining;
            return 0;
        }
        memcpy(kctx->pending + kctx->pending_len, in, need);
        kalyna_cbc_encrypt_block(kctx, kctx->pending, out + produced);
        produced += KALYNA256_BLOCK_SIZE;
        in += need;
        remaining -= need;
        kctx->pending_len = 0;
    }

    while (remaining >= KALYNA256_BLOCK_SIZE)
    {
        kalyna_cbc_encrypt_block(kctx, in, out + produced);
        produced += KALYNA256_BLOCK_SIZE;
        in += KALYNA256_BLOCK_SIZE;
        remaining -= KALYNA256_BLOCK_SIZE;
    }

    if (remaining > 0)
    {
        memcpy(kctx->pending, in, remaining);
        kctx->pending_len = remaining;
    }

    return (int) produced;
}

/* out must have room for at least inl + KALYNA256_BLOCK_SIZE bytes. */
static int kalyna256cbc_decrypt(struct kalyna256cbc_ctx *kctx, unsigned char *out,
                                const unsigned char *in, size_t inl)
{
    size_t produced = 0;
    size_t remaining = inl;

    if (in == NULL) /* Final: validate and strip PKCS7 padding on the held-back block. */
    {
        unsigned char pad;
        size_t i;

        if (!kctx->held_valid || kctx->pending_len != 0)
            return -1;

        pad = kctx->held[KALYNA256_BLOCK_SIZE - 1];
        if (pad == 0 || pad > KALYNA256_BLOCK_SIZE)
            return -1;
        for (i = 0; i < pad; ++i)
        {
            if (kctx->held[KALYNA256_BLOCK_SIZE - 1 - i] != pad)
                return -1;
        }

        memcpy(out, kctx->held, KALYNA256_BLOCK_SIZE - pad);
        return (int)(KALYNA256_BLOCK_SIZE - pad);
    }

    if (kctx->pending_len > 0)
    {
        size_t need = KALYNA256_BLOCK_SIZE - kctx->pending_len;
        if (remaining < need)
        {
            memcpy(kctx->pending + kctx->pending_len, in, remaining);
            kctx->pending_len += remaining;
            return 0;
        }
        memcpy(kctx->pending + kctx->pending_len, in, need);
        in += need;
        remaining -= need;
        kctx->pending_len = 0;

        if (kctx->held_valid)
        {
            memcpy(out + produced, kctx->held, KALYNA256_BLOCK_SIZE);
            produced += KALYNA256_BLOCK_SIZE;
        }
        kalyna_cbc_decrypt_block(kctx, kctx->pending, kctx->held);
        kctx->held_valid = 1;
    }

    while (remaining >= KALYNA256_BLOCK_SIZE)
    {
        if (kctx->held_valid)
        {
            memcpy(out + produced, kctx->held, KALYNA256_BLOCK_SIZE);
            produced += KALYNA256_BLOCK_SIZE;
        }
        kalyna_cbc_decrypt_block(kctx, in, kctx->held);
        kctx->held_valid = 1;
        in += KALYNA256_BLOCK_SIZE;
        remaining -= KALYNA256_BLOCK_SIZE;
    }

    if (remaining > 0)
    {
        memcpy(kctx->pending, in, remaining);
        kctx->pending_len = remaining;
    }

    return (int) produced;
}

static int kalyna256cbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                  const unsigned char *in, size_t inl)
{
    struct kalyna256cbc_ctx *kctx = (struct kalyna256cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);

    if (!kctx->have_key)
        return -1;

    if (EVP_CIPHER_CTX_encrypting(ctx))
        return kalyna256cbc_encrypt(kctx, out, in, inl);
    else
        return kalyna256cbc_decrypt(kctx, out, in, inl);
}

static int kalyna256cbc_cleanup(EVP_CIPHER_CTX *ctx)
{
    (void) ctx;
    return 1;
}

/*
 * Custom ASN1 IV codec, storing/reading the IV via our own context instead
 * of the default EVP_CIPHER_get/set_asn1_iv path: that default assumes the
 * IV fits in EVP_CIPHER_CTX's built-in 16-byte (EVP_MAX_IV_LENGTH) buffer,
 * which our 32-byte IV does not. Encoded as SEQUENCE { OCTET STRING iv },
 * confirmed against real-world PKCS12 key material (same pattern as this
 * engine's DSTU 28147 CFB cipher in cipher.c, minus the sbox field).
 */
#define KALYNA256CBC_ASN1_PARAM_SIZE (2 + 2 + KALYNA256_BLOCK_SIZE)

static int kalyna256cbc_set_asn1_parameters(EVP_CIPHER_CTX *ctx, ASN1_TYPE *type)
{
    struct kalyna256cbc_ctx *kctx = (struct kalyna256cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    unsigned char params[KALYNA256CBC_ASN1_PARAM_SIZE];
    ASN1_STRING seq;

    params[0] = V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED;
    params[1] = 2 + KALYNA256_BLOCK_SIZE;
    params[2] = V_ASN1_OCTET_STRING;
    params[3] = KALYNA256_BLOCK_SIZE;
    memcpy(&params[4], kctx->iv, KALYNA256_BLOCK_SIZE);

    seq.type = V_ASN1_SEQUENCE;
    seq.length = sizeof(params);
    seq.flags = 0;
    seq.data = params;

    if (ASN1_TYPE_set1(type, V_ASN1_SEQUENCE, &seq))
        return 1;
    return -1;
}

static int kalyna256cbc_get_asn1_parameters(EVP_CIPHER_CTX *ctx, ASN1_TYPE *type)
{
    struct kalyna256cbc_ctx *kctx = (struct kalyna256cbc_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    const unsigned char *data;

    if (type->type != V_ASN1_SEQUENCE || type->value.sequence == NULL ||
        type->value.sequence->length != KALYNA256CBC_ASN1_PARAM_SIZE)
        return -1;

    data = type->value.sequence->data;
    if (data[2] != V_ASN1_OCTET_STRING || data[3] != KALYNA256_BLOCK_SIZE)
        return -1;

    memcpy(kctx->iv, data + 4, KALYNA256_BLOCK_SIZE);
    return 1;
}

EVP_CIPHER *kalyna256cbc_cipher_new(int nid)
{
    /* block_size is declared as 1 (not the real 32) because this cipher is
     * fully self-buffering (EVP_CIPH_FLAG_CUSTOM_CIPHER): OpenSSL's legacy
     * EVP_CIPHER_CTX code asserts block_size is one of 1/8/16 regardless of
     * that flag, so 32 cannot be declared even though it's never consulted
     * for chunking once CUSTOM_CIPHER is set. */
    EVP_CIPHER *res = EVP_CIPHER_meth_new(nid, 1, KALYNA256_KEY_SIZE);
    if (res == NULL)
        return NULL;
    if (!EVP_CIPHER_meth_set_iv_length(res, KALYNA256_BLOCK_SIZE) ||
        !EVP_CIPHER_meth_set_flags(res, EVP_CIPH_CBC_MODE | EVP_CIPH_CUSTOM_IV |
            EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_ALWAYS_CALL_INIT) ||
        !EVP_CIPHER_meth_set_init(res, kalyna256cbc_init) ||
        !EVP_CIPHER_meth_set_do_cipher(res, kalyna256cbc_do_cipher) ||
        !EVP_CIPHER_meth_set_cleanup(res, kalyna256cbc_cleanup) ||
        !EVP_CIPHER_meth_set_set_asn1_params(res, kalyna256cbc_set_asn1_parameters) ||
        !EVP_CIPHER_meth_set_get_asn1_params(res, kalyna256cbc_get_asn1_parameters) ||
        !EVP_CIPHER_meth_set_impl_ctx_size(res, sizeof(struct kalyna256cbc_ctx)))
    {
        EVP_CIPHER_meth_free(res);
        return NULL;
    }
    return res;
}

void kalyna_cipher_free(EVP_CIPHER *cipher)
{
    if (cipher)
        EVP_CIPHER_meth_free(cipher);
}
