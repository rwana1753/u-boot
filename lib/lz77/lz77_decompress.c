/*
 *  LZ77 Decompressor
 *
 *  Copyright (C) 2023 Sukjin Kong <sjkong@coasia.com>
 */

#include <common.h>
#include <lz77/lz77.h>
#include <log.h>
#include <stdint.h>

static uint16_t p_bit = EFI_P_BIT;

static void fill_buf(struct scr_data *data, uint16_t num_bit)
{
	data->bit_buf = (uint32_t)(((uint64_t)data->bit_buf) << num_bit);

	while (num_bit > data->bit_cnt) {
		data->bit_buf |= (uint32_t)(((uint64_t)data->sub_bit_buf) << (num_bit = (uint16_t)(num_bit - data->bit_cnt)));

		if (data->cmp_len > 0) {
			//
			// Get 1 byte into SubBitBuf
			//
			data->cmp_len--;
			data->sub_bit_buf = data->src_addr[data->src_idx++];
			data->bit_cnt = 8;
		} else {
			//
			// No more bits from the source, just pad zero bit.
			//
			data->sub_bit_buf = 0;
			data->bit_cnt = 8;
		}
	}

	data->bit_cnt = (uint16_t)(data->bit_cnt - num_bit);
	data->bit_buf |= data->sub_bit_buf >> data->bit_cnt;
}

static uint32_t get_bit(struct scr_data *data, uint16_t num_bit)
{
	uint32_t out_bit;

	out_bit = (uint32_t)(data->bit_buf >> (BIT_BUF_LEN - num_bit));

	fill_buf(data, num_bit);

	return out_bit;
}

static uint16_t make_tbl(struct scr_data *data, uint16_t num_char,
			uint8_t *bit_len, uint16_t tbl_bit, uint16_t *tbl)
{
	uint16_t cnt[17];
	uint16_t start[18];
	uint16_t wei[17];
	uint16_t idx;
	uint16_t sub_idx;
	uint16_t rem_bit;
	uint16_t avail;
	uint16_t mask;
	uint16_t max_tbl_len;
	
	for (idx = 1; idx <= 16; idx++) {
		cnt[idx] = 0;
	}

	for (idx = 0; idx < num_char; idx++) {
		if (bit_len[idx] > 16) {
			return (uint16_t)BAD_TBL;
		}

		cnt[bit_len[idx]]++;
	}

	start[1] = 0;

	for (idx = 1; idx <= 16; idx++) {
		start[idx + 1] = (uint16_t)(start[idx] + (cnt[idx] << (16 - idx)));
	}

	if (start[17] != 0) {
		/*(1U << 16)*/
		return (uint16_t)BAD_TBL;
	}

	rem_bit = (uint16_t)(16 - tbl_bit);

	for (idx = 1; idx <= tbl_bit; idx++) {
		start[idx] >>= rem_bit;
		wei[idx] = (uint16_t)(1U << (tbl_bit - idx));
	}

	while (idx <= 16) {
		wei[idx] = (uint16_t)(1U << (16 - idx));
		idx++;
	}

	idx = (uint16_t)(start[tbl_bit + 1] >> rem_bit);

	if (idx != 0) {
		sub_idx = (uint16_t)(1U << tbl_bit);

		while (idx != sub_idx) {
			tbl[idx++] = 0;
		}
	}

	avail = num_char;
	mask = (uint16_t)(1U << (15 - tbl_bit));
	max_tbl_len = (uint16_t)(1U << tbl_bit);

	return LZ77_E_OK;
}

static uint32_t decode_p(struct scr_data *data)
{
	uint16_t val;
	uint32_t mask;
	uint32_t pos;

	val = data->p_tbl[data->bit_buf >> (BIT_BUF_LEN - 8)];

	if (val >= MAX_NP) {
		mask = 1U << (BIT_BUF_LEN - 1- 8);

		do {
			if (data->bit_buf & mask) {
				val = data->rt[val];
			} else {
				val = data->lt[val];
			}

			mask >>= 1;
		} while (val >= MAX_NP);
	}

	//
	// Advance what we have read
	//
	fill_buf(data, data->p_len[val]);

	pos = val;

	if (val > 1) {
		pos = (uint32_t)((1U << (val - 1)) + get_bit(data, (uint16_t)(val - 1)));
	}

	return pos;
}

static uint16_t read_p_len(struct scr_data *data, uint16_t num_sym,
			uint16_t num_bit, uint16_t spc)
{
	uint16_t num;
	uint16_t char_c;
	uint16_t idx;
	uint32_t mask;

	assert(num_sym <= NP);

	num = (uint16_t)get_bit(data, num_bit);

	if (num == 0) {
		char_c = (uint16_t)get_bit(data, num_bit);

		for (idx = 0; idx < 256; idx++) {
			data->p_tbl[idx] = char_c;
		}

		for (idx = 0; idx < num_sym; idx++) {
			data->p_len[idx] = 0;
		}

		return LZ77_E_OK;
	}

	idx = 0;

	while (idx < num && idx < NP) {
		char_c = (uint16_t)(data->bit_buf >> (BIT_BUF_LEN - 3));

		if (char_c == 7) {
			mask = 1U << (BIT_BUF_LEN - 1 - 3);

			while (mask & data->bit_buf) {
				mask >>= 1;
				char_c += 1;
			}
		}

		fill_buf(data, (uint16_t)((char_c < 7) ? 3: char_c - 3));

		data->p_len[idx++] = (uint8_t)char_c;

		if (idx == spc) {
			char_c = (uint16_t)get_bit(data, 2);
			char_c--;

			while ((int16_t)(char_c) >= 0 && idx < NP) {
				data->p_len[idx++] = 0;
				char_c--;
			}
		}
	}

	while (idx < num && idx < NP) {
		data->p_len[idx++] = 0;
	}

	return make_tbl(data, num, data->p_len, 8, data->p_tbl);
}

static void read_c_len(struct scr_data *data)
{
	uint16_t num;
	uint16_t char_c;
	uint16_t idx;
	uint32_t mask;
	
	num = (uint16_t)get_bit(data, C_BIT);

	if (num == 0) {
		char_c = (uint16_t)get_bit(data, C_BIT);

		for (idx = 0; idx < NC; idx++) {
			data->c_len[idx] = 0;
		}

		for (idx = 0; idx < 4096; idx++) {
			data->c_tbl[idx] = char_c;
		}

		return;
	}

	idx =0;

	while (idx < num) {
		char_c = data->p_tbl[data->bit_buf >> (BIT_BUF_LEN - 8)];

		if (char_c >= NT) {
			mask = 1U << (BIT_BUF_LEN - 1 - 8);

			do {
				if (mask & data->bit_buf) {
					char_c = data->rt[char_c];
				} else {
					char_c = data->lt[char_c];
				}

				mask >>= 1;
			} while (char_c >= NT);
		}

		//
		// Advance what we have read
		//
		fill_buf(data, data->p_len[char_c]);

		if (char_c <= 2) {
			if (char_c == 0) {
				char_c =1;
			} else if (char_c == 1) {
				char_c = (uint16_t)(get_bit(data, 4) + 3); 
			} else if (char_c == 2) {
				char_c = (uint16_t)(get_bit(data, C_BIT) + 20);
			}

			char_c--;

			while ((uint16_t)(char_c) >= 0) {//
				data->c_len[idx++] = 0;
				char_c--;
			}
		} else {
			data->c_len[idx++] = (uint8_t)(char_c - 2);
		}
	}

	while (idx < NC) {
		data->c_len[idx++] = 0;
	}

	make_tbl(data, NC, data->c_len, 12, data->c_tbl);
}

static uint16_t decode_c(struct scr_data *data)
{
	uint16_t idx;
	uint32_t mask;

	if (data->blk_len == 0) {
		//
		// Starting a new block
		//
		data->blk_len = (uint16_t)get_bit(data, 16);
		data->bad_tbl_flg = read_p_len(data, NT, T_BIT, 3);

		if (data->bad_tbl_flg != 0) {
			return LZ77_E_OK;
		}

		read_c_len(data);
		data->bad_tbl_flg = read_p_len(data, MAX_NP, p_bit, (uint16_t)(-1));//

		if (data->bad_tbl_flg != 0) {
			return LZ77_E_OK;
		}
	}

	data->blk_len--;
	idx = data->c_tbl[data->bit_buf >> (BIT_BUF_LEN - 12)];

	if (idx >= NC) {
		mask = 1U << (BIT_BUF_LEN - 1 - 12);//

		do {
			if (data->bit_buf & mask) {
				idx = data->rt[idx];
			} else {
				idx = data->lt[idx];
			}

			mask >>= 1;
		} while (idx >= NC);
	}

	//
	// Advance what we have read
	//
	fill_buf(data, data->c_len[idx]);

	return idx;
}

static void decode(struct scr_data *data)
{
	uint16_t byte_rem;
	uint32_t data_idx;
	uint16_t char_c;

	byte_rem = (uint16_t)(-1);//
	data_idx = 0;

	while(1) {
		char_c = decode_c(data);

		if (data->bad_tbl_flg != 0) {
			return;
		}

		if (char_c < 256) {
			//
			// Process an Original character
			//
			data->dst_addr[data->dst_idx++] = (uint8_t)char_c;

			if (data->dst_idx >=  data->org_len) {
				return;
			}
		} else {
			//
			// Process a Pointer
			//
			char_c = (uint16_t)(char_c - (UINT8_MAX + 1 - THRESHOLD));
			byte_rem = char_c;
			data_idx = data->dst_idx - decode_p(data) - 1;
			byte_rem--;

			while ((int16_t)byte_rem >= 0) {
				if (data->dst_idx >= data->org_len) {
					return;
				}

				data->dst_addr[data->dst_idx++] = data->dst_addr[data_idx++];
				byte_rem--;
			}

			//
			// Once mOutBuf is fully filled, directly return
			//
			if (data->dst_idx >= data->org_len) {
				return;
			}
		}
	}
}

int lz77_decompress(void *src, uint32_t src_len,
            void *dst, uint32_t dst_len,
            void *scr, uint32_t scr_len)
{
	struct scr_data *data;
	uint8_t *start = src;
	uint8_t *send = dst;
	uint32_t org_len;
	uint32_t cmp_len;
	uint32_t idx;

	if (scr_len < sizeof(struct scr_data)) {
		return LZ77_E_INVALID_PARAM;
	}

	data = (struct scr_data *)scr;

	if (src_len < 8) {
		return LZ77_E_INVALID_PARAM;
	}

	org_len = start[4] + (start[5] << 8) + (start[6] << 16) + (start[7] << 24);
	cmp_len = start[0] + (start[1] << 8) + (start[2] << 16) + (start[3] << 24);

	if (src_len < cmp_len + 8 || (cmp_len + 8) < 8) {
		return LZ77_E_INVALID_PARAM;
	}

	if (dst_len != org_len) {
		return LZ77_E_INVALID_PARAM;
	}

	start = start + 8;

	for (idx = 0; idx < sizeof(struct scr_data); idx++) {
		((uint8_t *)data)[idx] = 0;
	}

	data->src_addr = start;
	data->dst_addr = send;
	data->org_len = org_len;
	data->cmp_len = cmp_len;

	//
	// Fill the first BITBUFSIZ bits
	//
	fill_buf(data, BIT_BUF_LEN);

	//
	// Decompress it
	//
	decode(data);

	return LZ77_E_OK;
}
