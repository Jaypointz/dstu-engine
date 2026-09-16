/*
 * Kupyna hash function (DSTU 7564:2014).
 * Ported from the reference implementation by Ruslan Kiianchuk, Ruslan
 * Mordvinov and Roman Oliynykov: https://github.com/Roman-Oliynykov/Kupyna-reference
 * Round logic, padding formula, output transformation and KMAC are
 * unchanged; only identifiers/typing were adapted to this project's
 * conventions.
 */
#include "kupyna.h"
#include "tables.h"

#include <stdlib.h>
#include <string.h>

#define KUPYNA_NR_512 10   /* rounds for 512-bit state */
#define KUPYNA_NR_1024 14  /* rounds for 1024-bit state */
#define KUPYNA_REDUCTION_POLYNOMIAL 0x011d /* x^8 + x^4 + x^3 + x^2 + 1 */
#define KUPYNA_BITS_IN_BYTE 8

int kupyna_init(size_t hash_nbits, kupyna_ctx *ctx)
{
    if ((hash_nbits % 8 != 0) || (hash_nbits > 512))
        return -1;

    if (hash_nbits <= 256)
    {
        ctx->rounds = KUPYNA_NR_512;
        ctx->columns = KUPYNA_NB_512;
        ctx->nbytes = KUPYNA_STATE_BYTE_SIZE_512;
    }
    else
    {
        ctx->rounds = KUPYNA_NR_1024;
        ctx->columns = KUPYNA_NB_1024;
        ctx->nbytes = KUPYNA_STATE_BYTE_SIZE_1024;
    }
    ctx->hash_nbits = hash_nbits;
    memset(ctx->state, 0, ctx->nbytes);
    /* Set init value according to the specification. */
    ctx->state[0][0] = (uint8_t)ctx->nbytes;
    return 0;
}

static void kupyna_sub_bytes(uint8_t state[KUPYNA_NB_1024][KUPYNA_ROWS], int columns)
{
    int i, j;
    for (i = 0; i < KUPYNA_ROWS; ++i)
    {
        for (j = 0; j < columns; ++j)
            state[j][i] = kupyna_sboxes[i % 4][state[j][i]];
    }
}

static void kupyna_shift_bytes(uint8_t state[KUPYNA_NB_1024][KUPYNA_ROWS], int columns)
{
    int i, j;
    uint8_t temp[KUPYNA_NB_1024];
    int shift = -1;
    for (i = 0; i < KUPYNA_ROWS; ++i)
    {
        if ((i == KUPYNA_ROWS - 1) && (columns == KUPYNA_NB_1024))
            shift = 11;
        else
            ++shift;

        for (j = 0; j < columns; ++j)
            temp[(j + shift) % columns] = state[j][i];
        for (j = 0; j < columns; ++j)
            state[j][i] = temp[j];
    }
}

static uint8_t kupyna_multiply_gf(uint8_t x, uint8_t y)
{
    int i;
    uint8_t r = 0;
    uint8_t hbit;
    for (i = 0; i < KUPYNA_BITS_IN_BYTE; ++i)
    {
        if ((y & 0x1) == 1)
            r ^= x;
        hbit = (uint8_t)(x & 0x80);
        x = (uint8_t)(x << 1);
        if (hbit == 0x80)
            x = (uint8_t)(x ^ KUPYNA_REDUCTION_POLYNOMIAL);
        y = (uint8_t)(y >> 1);
    }
    return r;
}

static void kupyna_mix_columns(uint8_t state[KUPYNA_NB_1024][KUPYNA_ROWS], int columns)
{
    int i, row, col, b;
    uint8_t product;
    uint8_t result[KUPYNA_ROWS];
    for (col = 0; col < columns; ++col)
    {
        for (row = KUPYNA_ROWS - 1; row >= 0; --row)
        {
            product = 0;
            for (b = KUPYNA_ROWS - 1; b >= 0; --b)
                product = (uint8_t)(product ^ kupyna_multiply_gf(state[col][b], kupyna_mds_matrix[row][b]));
            result[row] = product;
        }
        for (i = 0; i < KUPYNA_ROWS; ++i)
            state[col][i] = result[i];
    }
}

static void kupyna_add_round_constant_p(uint8_t state[KUPYNA_NB_1024][KUPYNA_ROWS], int columns, int round)
{
    int i;
    for (i = 0; i < columns; ++i)
        state[i][0] = (uint8_t)(state[i][0] ^ (i * 0x10) ^ round);
}

static void kupyna_add_round_constant_q(uint8_t state[KUPYNA_NB_1024][KUPYNA_ROWS], int columns, int round)
{
    int j;
    uint64_t *s = (uint64_t *)state;
    for (j = 0; j < columns; ++j)
    {
        s[j] = s[j] + (0x00F0F0F0F0F0F0F3ULL ^
                ((((uint64_t)(columns - j - 1) * 0x10ULL) ^ (uint64_t)round) << (7 * 8)));
    }
}

static void kupyna_permute_p(kupyna_ctx *ctx, uint8_t state[KUPYNA_NB_1024][KUPYNA_ROWS])
{
    int i;
    for (i = 0; i < ctx->rounds; ++i)
    {
        kupyna_add_round_constant_p(state, ctx->columns, i);
        kupyna_sub_bytes(state, ctx->columns);
        kupyna_shift_bytes(state, ctx->columns);
        kupyna_mix_columns(state, ctx->columns);
    }
}

static void kupyna_permute_q(kupyna_ctx *ctx, uint8_t state[KUPYNA_NB_1024][KUPYNA_ROWS])
{
    int i;
    for (i = 0; i < ctx->rounds; ++i)
    {
        kupyna_add_round_constant_q(state, ctx->columns, i);
        kupyna_sub_bytes(state, ctx->columns);
        kupyna_shift_bytes(state, ctx->columns);
        kupyna_mix_columns(state, ctx->columns);
    }
}

static void kupyna_pad(kupyna_ctx *ctx, const uint8_t *data, size_t msg_nbits)
{
    size_t i;
    int mask;
    int pad_bit;
    int extra_bits;
    size_t zero_nbytes;
    size_t msg_nbytes = msg_nbits / KUPYNA_BITS_IN_BYTE;
    size_t nblocks = msg_nbytes / ctx->nbytes;
    const uint8_t *pad_start;

    ctx->pad_nbytes = msg_nbytes - (nblocks * ctx->nbytes);
    ctx->data_nbytes = msg_nbytes - ctx->pad_nbytes;
    pad_start = data + ctx->data_nbytes;

    extra_bits = (int)(msg_nbits % KUPYNA_BITS_IN_BYTE);
    if (extra_bits)
        ctx->pad_nbytes += 1;

    memcpy(ctx->padding, pad_start, ctx->pad_nbytes);

    if (extra_bits)
    {
        mask = ~(0xFF >> extra_bits);
        pad_bit = 1 << (7 - extra_bits);
        ctx->padding[ctx->pad_nbytes - 1] = (uint8_t)((ctx->padding[ctx->pad_nbytes - 1] & mask) | pad_bit);
    }
    else
    {
        ctx->padding[ctx->pad_nbytes] = 0x80;
        ctx->pad_nbytes += 1;
    }

    zero_nbytes = ((size_t)(0 - msg_nbits - 97) % (ctx->nbytes * KUPYNA_BITS_IN_BYTE)) / KUPYNA_BITS_IN_BYTE;
    memset(ctx->padding + ctx->pad_nbytes, 0, zero_nbytes);
    ctx->pad_nbytes += zero_nbytes;

    for (i = 0; i < (96 / 8); ++i, ++ctx->pad_nbytes)
    {
        if (i < sizeof(size_t))
            ctx->padding[ctx->pad_nbytes] = (uint8_t)(msg_nbits >> (i * 8));
        else
            ctx->padding[ctx->pad_nbytes] = 0;
    }
}

static void kupyna_digest(kupyna_ctx *ctx, const uint8_t *data)
{
    size_t b;
    int i, j;
    uint8_t temp1[KUPYNA_NB_1024][KUPYNA_ROWS];
    uint8_t temp2[KUPYNA_NB_1024][KUPYNA_ROWS];

    for (b = 0; b < ctx->data_nbytes; b += ctx->nbytes)
    {
        for (i = 0; i < KUPYNA_ROWS; ++i)
        {
            for (j = 0; j < ctx->columns; ++j)
            {
                temp1[j][i] = (uint8_t)(ctx->state[j][i] ^ data[b + (size_t)j * KUPYNA_ROWS + (size_t)i]);
                temp2[j][i] = data[b + (size_t)j * KUPYNA_ROWS + (size_t)i];
            }
        }
        kupyna_permute_p(ctx, temp1);
        kupyna_permute_q(ctx, temp2);
        for (i = 0; i < KUPYNA_ROWS; ++i)
        {
            for (j = 0; j < ctx->columns; ++j)
                ctx->state[j][i] = (uint8_t)(ctx->state[j][i] ^ temp1[j][i] ^ temp2[j][i]);
        }
    }

    /* Process extra bytes in padding. */
    for (b = 0; b < ctx->pad_nbytes; b += ctx->nbytes)
    {
        for (i = 0; i < KUPYNA_ROWS; ++i)
        {
            for (j = 0; j < ctx->columns; ++j)
            {
                temp1[j][i] = (uint8_t)(ctx->state[j][i] ^ ctx->padding[b + (size_t)j * KUPYNA_ROWS + (size_t)i]);
                temp2[j][i] = ctx->padding[b + (size_t)j * KUPYNA_ROWS + (size_t)i];
            }
        }
        kupyna_permute_p(ctx, temp1);
        kupyna_permute_q(ctx, temp2);
        for (i = 0; i < KUPYNA_ROWS; ++i)
        {
            for (j = 0; j < ctx->columns; ++j)
                ctx->state[j][i] = (uint8_t)(ctx->state[j][i] ^ temp1[j][i] ^ temp2[j][i]);
        }
    }
}

static void kupyna_trunc(kupyna_ctx *ctx, uint8_t *hash_code)
{
    size_t hash_nbytes = ctx->hash_nbits / KUPYNA_BITS_IN_BYTE;
    memcpy(hash_code, (uint8_t *)ctx->state + ctx->nbytes - hash_nbytes, hash_nbytes);
}

static void kupyna_output_transformation(kupyna_ctx *ctx, uint8_t *hash_code)
{
    int i, j;
    uint8_t temp[KUPYNA_NB_1024][KUPYNA_ROWS];
    memcpy(temp, ctx->state, KUPYNA_ROWS * KUPYNA_NB_1024);
    kupyna_permute_p(ctx, temp);
    for (i = 0; i < KUPYNA_ROWS; ++i)
    {
        for (j = 0; j < ctx->columns; ++j)
            ctx->state[j][i] = (uint8_t)(ctx->state[j][i] ^ temp[j][i]);
    }
    kupyna_trunc(ctx, hash_code);
}

void kupyna_hash(kupyna_ctx *ctx, const uint8_t *data, size_t msg_nbits, uint8_t *hash_code)
{
    /* Reinitialize internal state. */
    memset(ctx->state, 0, ctx->nbytes);
    ctx->state[0][0] = (uint8_t)ctx->nbytes;

    kupyna_pad(ctx, data, msg_nbits);
    kupyna_digest(ctx, data);
    kupyna_output_transformation(ctx, hash_code);
}

int kupyna_kmac(kupyna_ctx *ctx, const uint8_t *key, size_t key_nbytes, size_t digest_nbits, const uint8_t *data, size_t msg_nbits, uint8_t *mac)
{
    size_t total_nbytes;
    uint8_t *input;
    size_t i = 0;
    kupyna_ctx kpad;
    kupyna_ctx mpad;

    /* Reinitialize internal state. */
    memset(ctx->state, 0, ctx->nbytes);
    ctx->state[0][0] = (uint8_t)ctx->nbytes;

    if (digest_nbits != 256 && digest_nbits != 384 && digest_nbits != 512)
        return -1;

    kupyna_init(digest_nbits, &kpad);
    kupyna_init(digest_nbits, &mpad);

    /* Key is padded at its own (arbitrary) length, same as the message -
     * not artificially treated as exactly digest_nbits bits, matching real
     * key.length/password-length independent usage (e.g. as a PBKDF2 PRF). */
    kupyna_pad(&kpad, key, key_nbytes * 8);
    kupyna_pad(&mpad, data, msg_nbits);

    total_nbytes = kpad.pad_nbytes + mpad.pad_nbytes + key_nbytes;
    if (kpad.data_nbytes > 0)
        total_nbytes += kpad.data_nbytes;
    if (mpad.data_nbytes > 0)
        total_nbytes += mpad.data_nbytes;

    input = calloc(total_nbytes, sizeof(uint8_t));
    if (input == NULL)
        return -1;

    if (kpad.data_nbytes > 0)
    {
        memcpy(input, key, kpad.data_nbytes);
        i += kpad.data_nbytes;
    }
    memcpy(&input[i], kpad.padding, kpad.pad_nbytes);
    i += kpad.pad_nbytes;
    if (mpad.data_nbytes > 0)
    {
        memcpy(&input[i], data, mpad.data_nbytes);
        i += mpad.data_nbytes;
    }
    memcpy(&input[i], mpad.padding, mpad.pad_nbytes);
    i += mpad.pad_nbytes;
    memcpy(&input[i], key, key_nbytes);
    /* Invert key. */
    while (i < total_nbytes)
    {
        input[i] = (uint8_t)(input[i] ^ 0xFF);
        ++i;
    }

    kupyna_hash(ctx, input, total_nbytes * 8, mac);
    free(input);
    return 0;
}
