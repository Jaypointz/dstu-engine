/*
 * EVP_MD wrapper around the Kupyna hash function (DSTU 7564:2014) core in
 * dstulib/kupyna. Unlike the GOST 34.311 digest in md.c, Kupyna's reference
 * implementation is one-shot (whole message in, whole hash out), so this
 * wrapper buffers everything seen across update() calls and only actually
 * computes the hash in final().
 */
#include "kupyna_md.h"

#include "kupyna/kupyna.h"

#include <openssl/evp.h>
#include <openssl/crypto.h>

#include <stdint.h>
#include <string.h>

struct kupyna_digest_ctx
{
    size_t hash_nbits; /* resolved from the EVP_MD's NID on first init() */
    unsigned char *buf;
    size_t len;
    size_t cap;
};

static size_t kupyna_hash_nbits_for(const EVP_MD_CTX *ctx)
{
    return (size_t)EVP_MD_size(EVP_MD_CTX_md(ctx)) * 8;
}

static int kupyna_md_init(EVP_MD_CTX *ctx)
{
    struct kupyna_digest_ctx *c = EVP_MD_CTX_md_data(ctx);
    if (c->buf)
        OPENSSL_free(c->buf);
    memset(c, 0, sizeof(*c));
    c->hash_nbits = kupyna_hash_nbits_for(ctx);
    return 1;
}

static int kupyna_md_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    struct kupyna_digest_ctx *c = EVP_MD_CTX_md_data(ctx);
    if (count == 0)
        return 1;
    if (count > SIZE_MAX - c->len) /* c->len + count would overflow */
        return 0;
    if (c->len + count > c->cap)
    {
        size_t new_cap = c->cap ? c->cap * 2 : 4096;
        unsigned char *new_buf;
        while (new_cap < c->len + count)
        {
            if (new_cap > SIZE_MAX / 2)
                return 0; /* doubling would overflow */
            new_cap *= 2;
        }
        new_buf = OPENSSL_realloc(c->buf, new_cap);
        if (!new_buf)
            return 0;
        c->buf = new_buf;
        c->cap = new_cap;
    }
    memcpy(c->buf + c->len, data, count);
    c->len += count;
    return 1;
}

static int kupyna_md_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    struct kupyna_digest_ctx *c = EVP_MD_CTX_md_data(ctx);
    kupyna_ctx kctx;
    if (c->len > SIZE_MAX / 8) /* c->len * 8 would overflow */
        return 0;
    if (kupyna_init(c->hash_nbits, &kctx) != 0)
        return 0;
    kupyna_hash(&kctx, c->buf, c->len * 8, md);
    return 1;
}

static int kupyna_md_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    struct kupyna_digest_ctx *to_ctx = EVP_MD_CTX_md_data(to);
    const struct kupyna_digest_ctx *from_ctx = EVP_MD_CTX_md_data(from);
    if (!to_ctx || !from_ctx)
        return 1;
    to_ctx->hash_nbits = from_ctx->hash_nbits;
    to_ctx->len = from_ctx->len;
    to_ctx->cap = from_ctx->len; /* shrink to exactly what's needed */
    to_ctx->buf = to_ctx->cap ? OPENSSL_malloc(to_ctx->cap) : NULL;
    if (to_ctx->cap && !to_ctx->buf)
        return 0;
    if (to_ctx->len)
        memcpy(to_ctx->buf, from_ctx->buf, from_ctx->len);
    return 1;
}

static int kupyna_md_cleanup(EVP_MD_CTX *ctx)
{
    struct kupyna_digest_ctx *c = EVP_MD_CTX_md_data(ctx);
    if (c->buf)
        OPENSSL_free(c->buf);
    memset(c, 0, sizeof(*c));
    return 1;
}

static EVP_MD *kupyna_digest_new(int nid, size_t hash_nbits, int input_blocksize)
{
    EVP_MD *res = EVP_MD_meth_new(nid, 0);
    if (res == NULL)
        return NULL;
    if (!EVP_MD_meth_set_result_size(res, (int)(hash_nbits / 8)) ||
        !EVP_MD_meth_set_input_blocksize(res, input_blocksize) ||
        !EVP_MD_meth_set_app_datasize(res, sizeof(struct kupyna_digest_ctx)) ||
        !EVP_MD_meth_set_flags(res, 0) ||
        !EVP_MD_meth_set_init(res, kupyna_md_init) ||
        !EVP_MD_meth_set_update(res, kupyna_md_update) ||
        !EVP_MD_meth_set_final(res, kupyna_md_final) ||
        !EVP_MD_meth_set_copy(res, kupyna_md_copy) ||
        !EVP_MD_meth_set_cleanup(res, kupyna_md_cleanup))
    {
        EVP_MD_meth_free(res);
        return NULL;
    }
    return res;
}

EVP_MD *kupyna256_digest_new(int nid)
{
    return kupyna_digest_new(nid, 256, 64);
}

EVP_MD *kupyna512_digest_new(int nid)
{
    return kupyna_digest_new(nid, 512, 128);
}

void kupyna_digest_free(EVP_MD *digest)
{
    EVP_MD_meth_free(digest);
}
