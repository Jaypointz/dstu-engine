/*
 * Kalyna block cipher (DSTU 7624:2014).
 * Ported from the reference implementation by Ruslan Kiianchuk, Ruslan
 * Mordvinov and Roman Oliynykov: https://github.com/Roman-Oliynykov/Kalyna-reference
 * S-boxes, MDS matrices, key schedule and round structure are unchanged from
 * the reference. Identifiers/typing were adapted to this project's
 * conventions, the reference's malloc/free-based scratch buffers were
 * replaced with fixed-size arrays sized for the largest supported variant,
 * and the reference's runtime big-endian byte-swap path was dropped (like
 * the Kupyna port, this engine only targets little-endian platforms).
 */
#ifndef DSTU_KALYNA_H_
#define DSTU_KALYNA_H_

#include <stdint.h>
#include <stddef.h>

#define KALYNA_MAX_NB 8  /* 64-bit words per block, largest (512-bit) block */
#define KALYNA_MAX_NK 8  /* 64-bit words per key, largest (512-bit) key */
#define KALYNA_MAX_NR 18 /* rounds, largest (512-bit) key */

typedef struct kalyna_ctx_st
{
    size_t nb; /* 64-bit words per block */
    size_t nk; /* 64-bit words per key */
    size_t nr; /* number of encipher/decipher rounds */
    uint64_t state[KALYNA_MAX_NB];
    uint64_t round_keys[KALYNA_MAX_NR + 1][KALYNA_MAX_NB];
} kalyna_ctx;

/*
 * block_nbits/key_nbits must be one of the (block, key) combinations defined
 * by DSTU 7624:2014: (128,128), (128,256), (256,256), (256,512), (512,512).
 * Returns 0 on success, non-zero on an unsupported combination.
 */
int kalyna_init(size_t block_nbits, size_t key_nbits, kalyna_ctx *ctx);

/* Compute round keys from the enciphering key (ctx->nk 64-bit words). */
void kalyna_key_expand(const uint64_t *key, kalyna_ctx *ctx);

/* Encipher one block (ctx->nb 64-bit words) of plaintext. */
void kalyna_encipher(const uint64_t *plaintext, kalyna_ctx *ctx, uint64_t *ciphertext);

/* Decipher one block (ctx->nb 64-bit words) of ciphertext. */
void kalyna_decipher(const uint64_t *ciphertext, kalyna_ctx *ctx, uint64_t *plaintext);

#endif /* DSTU_KALYNA_H_ */
