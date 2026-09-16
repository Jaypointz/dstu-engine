/*
 * Kalyna block cipher (DSTU 7624:2014).
 * Ported from the reference implementation by Ruslan Kiianchuk, Ruslan
 * Mordvinov and Roman Oliynykov: https://github.com/Roman-Oliynykov/Kalyna-reference
 * Round logic, key schedule and constants are unchanged; only identifiers,
 * typing and buffer ownership were adapted to this project's conventions
 * (see kalyna.h for details).
 */
#include "kalyna.h"
#include "tables.h"

#include <string.h>

#define KALYNA_REDUCTION_POLYNOMIAL 0x011d /* x^8 + x^4 + x^3 + x^2 + 1 */
#define KALYNA_INDEX(table, row, col) ((table)[(size_t)(row) + (size_t)(col) * sizeof(uint64_t)])

int kalyna_init(size_t block_nbits, size_t key_nbits, kalyna_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));

    if (block_nbits == 128)
    {
        ctx->nb = 2;
        if (key_nbits == 128) { ctx->nk = 2; ctx->nr = 10; }
        else if (key_nbits == 256) { ctx->nk = 4; ctx->nr = 14; }
        else return -1;
    }
    else if (block_nbits == 256)
    {
        ctx->nb = 4;
        if (key_nbits == 256) { ctx->nk = 4; ctx->nr = 14; }
        else if (key_nbits == 512) { ctx->nk = 8; ctx->nr = 18; }
        else return -1;
    }
    else if (block_nbits == 512)
    {
        ctx->nb = 8;
        if (key_nbits == 512) { ctx->nk = 8; ctx->nr = 18; }
        else return -1;
    }
    else
    {
        return -1;
    }
    return 0;
}

static void kalyna_sub_bytes(kalyna_ctx *ctx)
{
    size_t i;
    const uint64_t *s = ctx->state;
    for (i = 0; i < ctx->nb; ++i)
    {
        ctx->state[i] = (uint64_t)kalyna_sboxes_enc[0][s[i] & 0xFFULL] |
            ((uint64_t)kalyna_sboxes_enc[1][(s[i] >> 8) & 0xFFULL] << 8) |
            ((uint64_t)kalyna_sboxes_enc[2][(s[i] >> 16) & 0xFFULL] << 16) |
            ((uint64_t)kalyna_sboxes_enc[3][(s[i] >> 24) & 0xFFULL] << 24) |
            ((uint64_t)kalyna_sboxes_enc[0][(s[i] >> 32) & 0xFFULL] << 32) |
            ((uint64_t)kalyna_sboxes_enc[1][(s[i] >> 40) & 0xFFULL] << 40) |
            ((uint64_t)kalyna_sboxes_enc[2][(s[i] >> 48) & 0xFFULL] << 48) |
            ((uint64_t)kalyna_sboxes_enc[3][(s[i] >> 56) & 0xFFULL] << 56);
    }
}

static void kalyna_inv_sub_bytes(kalyna_ctx *ctx)
{
    size_t i;
    const uint64_t *s = ctx->state;
    for (i = 0; i < ctx->nb; ++i)
    {
        ctx->state[i] = (uint64_t)kalyna_sboxes_dec[0][s[i] & 0xFFULL] |
            ((uint64_t)kalyna_sboxes_dec[1][(s[i] >> 8) & 0xFFULL] << 8) |
            ((uint64_t)kalyna_sboxes_dec[2][(s[i] >> 16) & 0xFFULL] << 16) |
            ((uint64_t)kalyna_sboxes_dec[3][(s[i] >> 24) & 0xFFULL] << 24) |
            ((uint64_t)kalyna_sboxes_dec[0][(s[i] >> 32) & 0xFFULL] << 32) |
            ((uint64_t)kalyna_sboxes_dec[1][(s[i] >> 40) & 0xFFULL] << 40) |
            ((uint64_t)kalyna_sboxes_dec[2][(s[i] >> 48) & 0xFFULL] << 48) |
            ((uint64_t)kalyna_sboxes_dec[3][(s[i] >> 56) & 0xFFULL] << 56);
    }
}

static void kalyna_shift_rows(kalyna_ctx *ctx)
{
    int row, col, shift = -1;
    const int nb = (int)ctx->nb;
    uint8_t *state = (uint8_t *)ctx->state;
    uint8_t nstate[KALYNA_MAX_NB * sizeof(uint64_t)];

    for (row = 0; row < (int)sizeof(uint64_t); ++row)
    {
        if (row % ((int)sizeof(uint64_t) / nb) == 0)
            shift += 1;
        for (col = 0; col < nb; ++col)
            KALYNA_INDEX(nstate, row, (col + shift) % nb) = KALYNA_INDEX(state, row, col);
    }

    memcpy(state, nstate, ctx->nb * sizeof(uint64_t));
}

static void kalyna_inv_shift_rows(kalyna_ctx *ctx)
{
    int row, col, shift = -1;
    const int nb = (int)ctx->nb;
    uint8_t *state = (uint8_t *)ctx->state;
    uint8_t nstate[KALYNA_MAX_NB * sizeof(uint64_t)];

    for (row = 0; row < (int)sizeof(uint64_t); ++row)
    {
        if (row % ((int)sizeof(uint64_t) / nb) == 0)
            shift += 1;
        for (col = 0; col < nb; ++col)
            KALYNA_INDEX(nstate, row, col) = KALYNA_INDEX(state, row, (col + shift) % nb);
    }

    memcpy(state, nstate, ctx->nb * sizeof(uint64_t));
}

static uint8_t kalyna_multiply_gf(uint8_t x, uint8_t y)
{
    int i;
    uint8_t r = 0, hbit;
    for (i = 0; i < 8; ++i)
    {
        if ((y & 0x1) == 1)
            r ^= x;
        hbit = (uint8_t)(x & 0x80);
        x = (uint8_t)(x << 1);
        if (hbit == 0x80)
            x = (uint8_t)(x ^ KALYNA_REDUCTION_POLYNOMIAL);
        y = (uint8_t)(y >> 1);
    }
    return r;
}

static void kalyna_matrix_multiply(kalyna_ctx *ctx, const uint8_t matrix[8][8])
{
    int col, row, b;
    const int nb = (int)ctx->nb;
    uint8_t product;
    uint64_t result;
    const uint8_t *state = (const uint8_t *)ctx->state;

    for (col = 0; col < nb; ++col)
    {
        result = 0;
        for (row = (int)sizeof(uint64_t) - 1; row >= 0; --row)
        {
            product = 0;
            for (b = (int)sizeof(uint64_t) - 1; b >= 0; --b)
                product = (uint8_t)(product ^ kalyna_multiply_gf(KALYNA_INDEX(state, b, col), matrix[row][b]));
            result |= (uint64_t)product << (row * (int)sizeof(uint64_t));
        }
        ctx->state[col] = result;
    }
}

static void kalyna_mix_columns(kalyna_ctx *ctx) { kalyna_matrix_multiply(ctx, kalyna_mds_matrix); }
static void kalyna_inv_mix_columns(kalyna_ctx *ctx) { kalyna_matrix_multiply(ctx, kalyna_mds_inv_matrix); }

static void kalyna_encipher_round(kalyna_ctx *ctx)
{
    kalyna_sub_bytes(ctx);
    kalyna_shift_rows(ctx);
    kalyna_mix_columns(ctx);
}

static void kalyna_decipher_round(kalyna_ctx *ctx)
{
    kalyna_inv_mix_columns(ctx);
    kalyna_inv_shift_rows(ctx);
    kalyna_inv_sub_bytes(ctx);
}

static void kalyna_add_round_key(size_t round, kalyna_ctx *ctx)
{
    size_t i;
    for (i = 0; i < ctx->nb; ++i)
        ctx->state[i] = ctx->state[i] + ctx->round_keys[round][i];
}

static void kalyna_sub_round_key(size_t round, kalyna_ctx *ctx)
{
    size_t i;
    for (i = 0; i < ctx->nb; ++i)
        ctx->state[i] = ctx->state[i] - ctx->round_keys[round][i];
}

static void kalyna_add_round_key_expand(const uint64_t *value, kalyna_ctx *ctx)
{
    size_t i;
    for (i = 0; i < ctx->nb; ++i)
        ctx->state[i] = ctx->state[i] + value[i];
}

static void kalyna_xor_round_key(size_t round, kalyna_ctx *ctx)
{
    size_t i;
    for (i = 0; i < ctx->nb; ++i)
        ctx->state[i] = ctx->state[i] ^ ctx->round_keys[round][i];
}

static void kalyna_xor_round_key_expand(const uint64_t *value, kalyna_ctx *ctx)
{
    size_t i;
    for (i = 0; i < ctx->nb; ++i)
        ctx->state[i] = ctx->state[i] ^ value[i];
}

static void kalyna_rotate(size_t state_size, uint64_t *state_value)
{
    size_t i;
    uint64_t temp = state_value[0];
    for (i = 1; i < state_size; ++i)
        state_value[i - 1] = state_value[i];
    state_value[state_size - 1] = temp;
}

static void kalyna_shift_left(size_t state_size, uint64_t *state_value)
{
    size_t i;
    for (i = 0; i < state_size; ++i)
        state_value[i] <<= 1;
}

static void kalyna_rotate_left(size_t state_size, uint64_t *state_value)
{
    size_t rotate_bytes = 2 * state_size + 3;
    size_t bytes_num = state_size * sizeof(uint64_t);
    uint8_t *bytes = (uint8_t *)state_value;
    uint8_t buffer[2 * KALYNA_MAX_NB * sizeof(uint64_t)]; /* rotate_bytes <= 2*KALYNA_MAX_NB+3 */

    memcpy(buffer, bytes, rotate_bytes);
    memmove(bytes, bytes + rotate_bytes, bytes_num - rotate_bytes);
    memcpy(bytes + bytes_num - rotate_bytes, buffer, rotate_bytes);
}

static void kalyna_key_expand_kt(const uint64_t *key, kalyna_ctx *ctx, uint64_t *kt)
{
    uint64_t k0[KALYNA_MAX_NB];
    uint64_t k1[KALYNA_MAX_NB];

    memset(ctx->state, 0, ctx->nb * sizeof(uint64_t));
    ctx->state[0] += ctx->nb + ctx->nk + 1;

    if (ctx->nb == ctx->nk)
    {
        memcpy(k0, key, ctx->nb * sizeof(uint64_t));
        memcpy(k1, key, ctx->nb * sizeof(uint64_t));
    }
    else
    {
        memcpy(k0, key, ctx->nb * sizeof(uint64_t));
        memcpy(k1, key + ctx->nb, ctx->nb * sizeof(uint64_t));
    }

    kalyna_add_round_key_expand(k0, ctx);
    kalyna_encipher_round(ctx);
    kalyna_xor_round_key_expand(k1, ctx);
    kalyna_encipher_round(ctx);
    kalyna_add_round_key_expand(k0, ctx);
    kalyna_encipher_round(ctx);
    memcpy(kt, ctx->state, ctx->nb * sizeof(uint64_t));
}

static void kalyna_key_expand_even(const uint64_t *key, const uint64_t *kt, kalyna_ctx *ctx)
{
    size_t i;
    uint64_t initial_data[KALYNA_MAX_NK];
    uint64_t kt_round[KALYNA_MAX_NB];
    uint64_t tmv[KALYNA_MAX_NB];
    size_t round = 0;

    memcpy(initial_data, key, ctx->nk * sizeof(uint64_t));
    for (i = 0; i < ctx->nb; ++i)
        tmv[i] = 0x0001000100010001ULL;

    for (;;)
    {
        memcpy(ctx->state, kt, ctx->nb * sizeof(uint64_t));
        kalyna_add_round_key_expand(tmv, ctx);
        memcpy(kt_round, ctx->state, ctx->nb * sizeof(uint64_t));

        memcpy(ctx->state, initial_data, ctx->nb * sizeof(uint64_t));

        kalyna_add_round_key_expand(kt_round, ctx);
        kalyna_encipher_round(ctx);
        kalyna_xor_round_key_expand(kt_round, ctx);
        kalyna_encipher_round(ctx);
        kalyna_add_round_key_expand(kt_round, ctx);

        memcpy(ctx->round_keys[round], ctx->state, ctx->nb * sizeof(uint64_t));

        if (ctx->nr == round)
            break;

        if (ctx->nk != ctx->nb)
        {
            round += 2;

            kalyna_shift_left(ctx->nb, tmv);

            memcpy(ctx->state, kt, ctx->nb * sizeof(uint64_t));
            kalyna_add_round_key_expand(tmv, ctx);
            memcpy(kt_round, ctx->state, ctx->nb * sizeof(uint64_t));

            memcpy(ctx->state, initial_data + ctx->nb, ctx->nb * sizeof(uint64_t));

            kalyna_add_round_key_expand(kt_round, ctx);
            kalyna_encipher_round(ctx);
            kalyna_xor_round_key_expand(kt_round, ctx);
            kalyna_encipher_round(ctx);
            kalyna_add_round_key_expand(kt_round, ctx);

            memcpy(ctx->round_keys[round], ctx->state, ctx->nb * sizeof(uint64_t));

            if (ctx->nr == round)
                break;
        }
        round += 2;
        kalyna_shift_left(ctx->nb, tmv);
        kalyna_rotate(ctx->nk, initial_data);
    }
}

static void kalyna_key_expand_odd(kalyna_ctx *ctx)
{
    size_t i;
    for (i = 1; i < ctx->nr; i += 2)
    {
        memcpy(ctx->round_keys[i], ctx->round_keys[i - 1], ctx->nb * sizeof(uint64_t));
        kalyna_rotate_left(ctx->nb, ctx->round_keys[i]);
    }
}

void kalyna_key_expand(const uint64_t *key, kalyna_ctx *ctx)
{
    uint64_t kt[KALYNA_MAX_NB];
    kalyna_key_expand_kt(key, ctx, kt);
    kalyna_key_expand_even(key, kt, ctx);
    kalyna_key_expand_odd(ctx);
}

void kalyna_encipher(const uint64_t *plaintext, kalyna_ctx *ctx, uint64_t *ciphertext)
{
    size_t round = 0;
    memcpy(ctx->state, plaintext, ctx->nb * sizeof(uint64_t));

    kalyna_add_round_key(round, ctx);
    for (round = 1; round < ctx->nr; ++round)
    {
        kalyna_encipher_round(ctx);
        kalyna_xor_round_key(round, ctx);
    }
    kalyna_encipher_round(ctx);
    kalyna_add_round_key(ctx->nr, ctx);

    memcpy(ciphertext, ctx->state, ctx->nb * sizeof(uint64_t));
}

void kalyna_decipher(const uint64_t *ciphertext, kalyna_ctx *ctx, uint64_t *plaintext)
{
    size_t round = ctx->nr;
    memcpy(ctx->state, ciphertext, ctx->nb * sizeof(uint64_t));

    kalyna_sub_round_key(round, ctx);
    for (round = ctx->nr - 1; round > 0; --round)
    {
        kalyna_decipher_round(ctx);
        kalyna_xor_round_key(round, ctx);
    }
    kalyna_decipher_round(ctx);
    kalyna_sub_round_key(0, ctx);

    memcpy(plaintext, ctx->state, ctx->nb * sizeof(uint64_t));
}
