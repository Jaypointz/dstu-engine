/*
 * S-boxes and MDS-matrix for the Kupyna hash function (DSTU 7564:2014).
 * Ported verbatim from the reference implementation by Ruslan Kiianchuk,
 * Ruslan Mordvinov and Roman Oliynykov:
 * https://github.com/Roman-Oliynykov/Kupyna-reference
 */
#ifndef DSTU_KUPYNA_TABLES_H_
#define DSTU_KUPYNA_TABLES_H_

#include <stdint.h>

extern const uint8_t kupyna_mds_matrix[8][8];
extern const uint8_t kupyna_sboxes[4][256];

#endif /* DSTU_KUPYNA_TABLES_H_ */
