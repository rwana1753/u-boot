/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2023 Sukjin Kong <sjkong@coasia.com>
 * Copyright (c) 2023, CoAsia Nexell
 */

#if !defined _EFI_DECOMPRESS_H_
#define _EFI_DECOMPRESS_H_

#include <efi.h>
#include <efi_api.h>

/* EFI decompress protocol related GUID definitions */
#define EFI_DECOMPRESS_PROTOCOL_GUID \
	EFI_GUID(0xd8117cfe, 0x94a6, 0x11d4, \
		 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d)

struct efi_decompress_protocol {
	efi_status_t (EFIAPI *getinfo)(
			struct efi_decompress_protocol *this,
			void *source,
			uint32_t source_size,
			uint32_t *destination_size,
			uint32_t *scratch_size);
	efi_status_t (EFIAPI *decompress)(
			struct efi_decompress_protocol *this,
			void *source,
			uint32_t source_size,
			void *destination,
			uint32_t destination_size,
			void *scratch,
			uint32_t scratch_size);
};

#endif /* _EFI_DECOMPRESS_H_ */
