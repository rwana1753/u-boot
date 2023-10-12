#ifndef __LZ77_H__
#define __LZ77_H__
/*
 *  A mini subset of the LZ77 real-time data decompression library
 *
 *  Copyright (C) 1997-2023 Sukjin Kong <sjkong@coasia.com>
 */

//
// Decompression algorithm begins here
//
#define BIT_BUF_LEN	32
#define MAX_MATCH	256
#define THRESHOLD	3
#define CODE_BIT	16
#define BAD_TBL		-1

//
// C: Char&Len Set; P: Position Set; T: exTra Set
//
#define NC		(0xff + MAX_MATCH + 2 - THRESHOLD)
#define C_BIT		9
#define EFI_P_BIT	4
#define MAX_PBIT	5
#define T_BIT		5
#define MAX_NP		((1U << MAX_PBIT) - 1)
#define NT		(CODE_BIT + 3)
#if NT > MAX_NP
#define NP NT
#else
#define NP MAX_NP
#endif

struct scr_data {
	uint8_t *src_addr;	// Starting address of compressed data
	uint8_t *dst_addr;	// Starting address of decompressed data
	uint32_t src_idx;
	uint32_t dst_idx;
	uint16_t bit_cnt;
	uint32_t bit_buf;
	uint32_t sub_bit_buf;
	uint16_t blk_len;
	uint32_t org_len;
	uint32_t cmp_len;
	uint16_t bad_tbl_flg;
	uint16_t lt[2 * NC - 1];
	uint16_t rt[2 * NC - 1];
	uint8_t c_len[NC];
	uint8_t p_len[NP];
	uint16_t c_tbl[4096];
	uint16_t p_tbl[256];
};

/* decompress lz77 format */
int lz77_decompress(void *src, uint32_t src_len,
            void *dst, uint32_t dst_len,
            void *scr, uint32_t scr_len);

/*
 * Return values (< 0 = Error)
 */
#define LZ77_E_OK		0
#define LZ77_E_INVALID_PARAM	(-2)
#define LZ77_E_OUT_OF_RESOURCES	(-9)

#endif
