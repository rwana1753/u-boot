/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2023 Sukjin Kong <sjkong@coasia.com>
 * Copyright (c) 2023, CoAsia Nexell
 */

#if !defined _EFI_HASH2_H_
#define _EFI_HASH2_H_

#include <efi.h>
#include <efi_api.h>

/* EFI hash2 protocol related GUID definitions */
#define EFI_HASH2_PROTOCOL_GUID \
	EFI_GUID(0x55b1d734, 0xc5e1, 0x49db, \
		 0x96, 0x47, 0xb1, 0x6a, 0xfb, 0x0e, 0x30, 0x5b)

#define EFI_HASH_ALGORITHM_MD5_GUID \
	EFI_GUID(0x0af7c79c, 0x65b5, 0x4319, \
		 0xb0, 0xae, 0x44, 0xec, 0x48, 0x4e, 0x4a, 0xd7)

#define EFI_HASH_ALGORITHM_SHA1_GUID \
	EFI_GUID(0x2ae9d80f, 0x3fb2, 0x4095, \
		 0xb7, 0xb1, 0xe9, 0x31, 0x57, 0xb9, 0x46, 0xb6)

#define EFI_HASH_ALGORITHM_SHA224_GUID \
	EFI_GUID(0x8df01a06, 0x9bd5, 0x4bf7, \
		 0xb0, 0x21, 0xdb, 0x4f, 0xd9, 0xcc, 0xf4, 0x5b)

#define EFI_HASH_ALGORITHM_SHA256_GUID \
	EFI_GUID(0x51aa59de, 0xfdf2, 0x4ea3, \
		 0xbc, 0x63, 0x87, 0x5f, 0xb7, 0x84, 0x2e, 0xe9)

#define EFI_HASH_ALGORITHM_SHA384_GUID \
	EFI_GUID(0xefa96432, 0xde33, 0x4dd2, \
		 0xae, 0xe6, 0x32, 0x8c, 0x33, 0xdf, 0x77, 0x7a)

#define EFI_HASH_ALGORITHM_SHA512_GUID \
	EFI_GUID(0xcaa4381e, 0x750c, 0x4770, \
		 0xb8, 0x70, 0x7a, 0x23, 0xb4, 0xe4, 0x21, 0x30)

#define EFI_HASH_ALGORITHM_SHA1_NOPAD_GUID \
	EFI_GUID(0x24c5dc2f, 0x53e2, 0x40ca, \
		 0x9e, 0xd6, 0xa5, 0xd9, 0xa4, 0x9f, 0x46, 0x3b)

#define EFI_HASH_ALGORITHM_SHA256_NOPAD_GUID \
	EFI_GUID(0x8628752a, 0x6cb7, 0x4814, \
		 0x96, 0xfc, 0x24, 0xa8, 0x15, 0xac, 0x22, 0x26)

#define EFI_MD5_HASH_SIZE		16
#define EFI_SHA1_HASH_SIZE		20
#define EFI_SHA224_HASH_SIZE	28
#define EFI_SHA256_HASH_SIZE	32
#define EFI_SHA384_HASH_SIZE	48
#define EFI_SHA512_HASH_SIZE	64

typedef uint8_t efi_md5_hash2[EFI_MD5_HASH_SIZE];
typedef uint8_t efi_sha1_hash2[EFI_SHA1_HASH_SIZE];
typedef uint8_t efi_sha224_hash2[EFI_SHA224_HASH_SIZE];
typedef uint8_t efi_sha256_hash2[EFI_SHA256_HASH_SIZE];
typedef uint8_t efi_sha384_hash2[EFI_SHA384_HASH_SIZE];
typedef uint8_t efi_sha512_hash2[EFI_SHA512_HASH_SIZE];

union efi_hash2_output {
	efi_md5_hash2 md5_hash;
	efi_sha1_hash2 sha1_hash; 
	efi_sha224_hash2 sha224_hash;
	efi_sha256_hash2 sha256_hash;
	efi_sha384_hash2 sha384_hash;
	efi_sha512_hash2 sha512_hash;
};

struct efi_hash2_protocol {
	efi_status_t (EFIAPI *get_hash_size)(
			struct efi_hash2_protocol *this,
			efi_guid_t *hash_algorithm,
			efi_uintn_t *hash_size);
	efi_status_t (EFIAPI *hash)(
			struct efi_hash2_protocol *this,
			efi_guid_t *hash_algorithm,
			uint8_t *message,
			efi_uintn_t message_size,
			union efi_hash2_output *hash);
	efi_status_t (EFIAPI *hash_init)(
			struct efi_hash2_protocol *this,
			efi_guid_t *hash_algorithm);
	efi_status_t (EFIAPI *hash_update)(
			struct efi_hash2_protocol *this,
			uint8_t *message,
			efi_uintn_t message_size);
	efi_status_t (EFIAPI *hash_final)(
			struct efi_hash2_protocol *this,
			union efi_hash2_output *hash);
};

#endif /* _EFI_HASH2_H_ */
