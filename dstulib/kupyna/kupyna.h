/*
 * Kupyna hash function (DSTU 7564:2014).
 * Ported from the reference implementation by Ruslan Kiianchuk, Ruslan
 * Mordvinov and Roman Oliynykov: https://github.com/Roman-Oliynykov/Kupyna-reference
 * Algorithm logic (rounds, padding, output transformation) is unchanged from
 * the reference; only identifiers were renamed and typing made explicit to
 * fit this project's conventions. Only the plain hash (no keyed KMAC) is
 * ported, since that's all an EVP_MD digest needs.
 *
 * Note: like the reference, AddRoundConstantQ reinterprets the state as an
 * array of 64-bit words and relies on a little-endian target (true for every
 * platform this engine currently targets).
 */
#ifndef DSTU_KUPYNA_H_
#define DSTU_KUPYNA_H_

#include <stdint.h>
#include <stddef.h>

#define KUPYNA_ROWS 8
#define KUPYNA_NB_512 8    /* columns in state for <=256-bit hash code */
#define KUPYNA_NB_1024 16  /* columns in state for <=512-bit hash code */
#define KUPYNA_STATE_BYTE_SIZE_512 (KUPYNA_ROWS * KUPYNA_NB_512)
#define KUPYNA_STATE_BYTE_SIZE_1024 (KUPYNA_ROWS * KUPYNA_NB_1024)

typedef struct kupyna_ctx_st
{
    uint8_t state[KUPYNA_NB_1024][KUPYNA_ROWS];
    size_t nbytes;      /* bytes currently in state (512/8 or 1024/8) */
    size_t data_nbytes;
    uint8_t padding[KUPYNA_STATE_BYTE_SIZE_1024 * 2];
    size_t pad_nbytes;
    size_t hash_nbits;
    int columns;
    int rounds;
} kupyna_ctx;

/* hash_nbits must be a multiple of 8, in (0, 512]. Returns 0 on success. */
int kupyna_init(size_t hash_nbits, kupyna_ctx *ctx);

/* One-shot hash of a whole (bit-length addressable) message. */
void kupyna_hash(kupyna_ctx *ctx, const uint8_t *data, size_t msg_nbits, uint8_t *hash_code);

#endif /* DSTU_KUPYNA_H_ */
