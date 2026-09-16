/*
 * S-boxes and MDS-matrices for the Kalyna block cipher (DSTU 7624:2014).
 * Ported verbatim from the reference implementation by Ruslan Kiianchuk,
 * Ruslan Mordvinov and Roman Oliynykov:
 * https://github.com/Roman-Oliynykov/Kalyna-reference
 */
#ifndef DSTU_KALYNA_TABLES_H_
#define DSTU_KALYNA_TABLES_H_

#include <stdint.h>

extern const uint8_t kalyna_mds_matrix[8][8];
extern const uint8_t kalyna_mds_inv_matrix[8][8];

extern const uint8_t kalyna_sboxes_enc[4][256];
extern const uint8_t kalyna_sboxes_dec[4][256];

#endif /* DSTU_KALYNA_TABLES_H_ */
