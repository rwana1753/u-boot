// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2023 Sukjin Kong <sjkong@coasia.com>
 * Copyright (c) 2023, CoAsia Nexell Co.,Ltd.
 */

#define LOG_CATEGORY LOGC_EFI

#include <common.h>
#include <efi_loader.h>
#include <efi_decompress.h>
#include <log.h>
#include <asm/global_data.h>
#include <lz77/lz77.h>

DECLARE_GLOBAL_DATA_PTR;

const efi_guid_t efi_guid_decompress_protocol = EFI_DECOMPRESS_PROTOCOL_GUID;

/**
 * efi_getinfo() - get information about size of destination and scratch
 * to decompress source buffer
 * This function implement the Decompress() service of the EFI decompress
 * protocol. See the UEFI spec for details.
 *
 * @this:		decompress protocol instance
 * @source:		source buffer
 * @source_size:	source buffer size
 * @destination_size:	destination buffer size
 * @scratch_size:	scratch buffer size
 * Return:		status code
 */
static efi_status_t EFIAPI efi_getinfo(struct efi_decompress_protocol *this,
			void *source,
			uint32_t source_size,
			uint32_t *destination_size,
			uint32_t *scratch_size)
{
	efi_status_t ret = EFI_SUCCESS;
	uint8_t *src = source;
	uint32_t compressed_size;

	EFI_ENTRY("%p, %p, %x, %p, %p", this, source, source_size,
		  destination_size, scratch_size);

	if (!this) {
		ret = EFI_INVALID_PARAMETER;
		goto back;
	}

	if (source_size < 8) {
		ret = EFI_INVALID_PARAMETER;
		goto back;
	}

	compressed_size = src[0] + (src[1] << 8) + (src[2] << 16) + (src[3] << 24);
	*destination_size = src[4] + (src[5] << 8) + (src[6] << 16) + (src[7] << 24);

	if (source_size < compressed_size + 8 || (compressed_size + 8) < 8) {
		ret = EFI_INVALID_PARAMETER;
		goto back;
	}

	*scratch_size = sizeof(struct scr_data);

back:
	return EFI_EXIT(ret);
}

/**
 * efi_decompress() - decompress source buffer into destination buffer
 *
 * This function implement the Decompress() service of the EFI decompress
 * protocol. See the UEFI spec for details.
 *
 * @this:		decompress protocol instance
 * @source:		source buffer
 * @source_size:	source buffer size
 * @destination:	destination buffer
 * @destination_size:	destination buffer size
 * @scratch:	scratch buffer
 * @scratch_size:	scratch buffer size
 * Return:		status code
 */
static efi_status_t EFIAPI efi_decompress(struct efi_decompress_protocol *this,
			void *source,
			uint32_t source_size,
			void *destination,
			uint32_t destination_size,
			void *scratch,
			uint32_t scratch_size)
{
	efi_status_t status = EFI_SUCCESS;

	EFI_ENTRY("%p, %p, %x, %p, %x, %p, %x", this, source, source_size,
		  destination, destination_size, scratch, scratch_size);

	if (!this || !source_size || !destination_size || !scratch_size) {
		status = EFI_INVALID_PARAMETER;
		goto back;
	}

	lz77_decompress(source, source_size,
				   destination, destination_size,
				   scratch, scratch_size);

back:
	return EFI_EXIT(status);
}

static const struct efi_decompress_protocol efi_decompress_protocol = {
	.getinfo = efi_getinfo,
	.decompress = efi_decompress,
};

/**
 * efi_decompress_register() - register EFI_DECOMPRESS_PROTOCOL
 *
 * If a LZ77 algolithm is available, the Decompress Protocol is
 * registered.
 *
 * Return:	An error status is only returned if adding the protocol fails.
 */
efi_status_t efi_decompress_register(void)
{
	efi_status_t ret;

	ret = efi_add_protocol(efi_root, &efi_guid_decompress_protocol,
			       (void *)&efi_decompress_protocol);
	if (ret != EFI_SUCCESS)
		log_err("Cannot install EFI_DECOMPRESS_PROTOCOL\n");

	return ret;
}
