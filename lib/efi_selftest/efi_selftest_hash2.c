// SPDX-License-Identifier: GPL-2.0+
/*
 * efi_selftest_hash2
 *
 * Copyright (c) 2023 Sukjin Kong <sjkong@coasia.com>
 *
 * Test the EFI_HASH2_PROTOCOL
 */

#include <efi_selftest.h>
#include <efi_hash2.h>

static struct efi_boot_services *boottime;
static efi_guid_t guid_hash2 = EFI_HASH2_PROTOCOL_GUID;
static efi_guid_t guid_md5 = EFI_HASH_ALGORITHM_MD5_GUID;
static efi_guid_t guid_sha1 = EFI_HASH_ALGORITHM_SHA1_GUID;
static efi_guid_t guid_sha224 = EFI_HASH_ALGORITHM_SHA224_GUID;
static efi_guid_t guid_sha256 = EFI_HASH_ALGORITHM_SHA256_GUID;
static efi_guid_t guid_sha384 = EFI_HASH_ALGORITHM_SHA384_GUID;
static efi_guid_t guid_sha512 = EFI_HASH_ALGORITHM_SHA512_GUID;
static efi_guid_t guid_sha1_np = EFI_HASH_ALGORITHM_SHA1_NOPAD_GUID;
static efi_guid_t guid_sha256_np = EFI_HASH_ALGORITHM_SHA256_NOPAD_GUID;

#define EFI_HASH_TEST_MSG	"King Kong"

/**
 * efi_st_hash2_setup() - setup test
 *
 * @handle:	handle of the loaded image
 * @systable:	system table
 * @return:	status code
 */
static int efi_st_hash2_setup(const efi_handle_t img_handle,
			     const struct efi_system_table *systable)
{
	boottime = systable->boottime;

	return EFI_ST_SUCCESS;
}

/**
 * efi_st_hash2_execute() - execute test
 *
 * Generate the hash value of the EFI_HASH22_PROTOCOL.
 *
 * Return:	status code
 */
static int efi_st_hash2_execute(void)
{
	struct efi_hash2_protocol *hash2;
	efi_status_t ret;
	uint8_t efi_st_msg[] = EFI_HASH_TEST_MSG;
	efi_uintn_t efi_st_msg_len = sizeof(efi_st_msg);
	union efi_hash2_output *hash;
	efi_uintn_t efi_st_hash_len;

	ret = boottime->locate_protocol(&guid_hash2, NULL, (void **)&hash2);
	if (ret != EFI_SUCCESS) {
		efi_st_error("HASH2 protocol is not available.\n");
		return EFI_ST_FAILURE;
	}

	ret = hash2->get_hash_size(hash2, &guid_md5, &efi_st_hash_len);
	if (ret == EFI_UNSUPPORTED) {
		efi_st_error("hash2->get_hash_size unsupported\n");
		return EFI_ST_FAILURE;
	} else if (ret == EFI_BUFFER_TOO_SMALL) {
		efi_st_error("hash2->get_hash_size on small buffer failed\n");
		return EFI_ST_FAILURE;
	}
	ret = hash2->get_hash_size(hash2, &guid_sha1, &efi_st_hash_len);
	if (ret == EFI_UNSUPPORTED) {
		efi_st_error("hash2->get_hash_size unsupported\n");
		return EFI_ST_FAILURE;
	} else if (ret == EFI_BUFFER_TOO_SMALL) {
		efi_st_error("hash2->get_hash_size on small buffer failed\n");
		return EFI_ST_FAILURE;
	}
	ret = hash2->get_hash_size(hash2, &guid_sha224, &efi_st_hash_len);
	if (ret != EFI_UNSUPPORTED) {
		efi_st_error("hash2->get_hash_size unsupported\n");
		return EFI_ST_FAILURE;
	} else if (ret == EFI_BUFFER_TOO_SMALL) {
		efi_st_error("hash2->get_hash_size on small buffer failed\n");
		return EFI_ST_FAILURE;
	}
	ret = hash2->get_hash_size(hash2, &guid_sha256, &efi_st_hash_len);
	if (ret == EFI_UNSUPPORTED) {
		efi_st_error("hash2->get_hash_size unsupported\n");
		return EFI_ST_FAILURE;
	} else if (ret == EFI_BUFFER_TOO_SMALL) {
		efi_st_error("hash2->get_hash_size on small buffer failed\n");
		return EFI_ST_FAILURE;
	}
	ret = hash2->get_hash_size(hash2, &guid_sha384, &efi_st_hash_len);
	if (ret == EFI_UNSUPPORTED) {
		efi_st_error("hash2->get_hash_size unsupported\n");
		return EFI_ST_FAILURE;
	} else if (ret == EFI_BUFFER_TOO_SMALL) {
		efi_st_error("hash2->get_hash_size on small buffer failed\n");
		return EFI_ST_FAILURE;
	}
	ret = hash2->get_hash_size(hash2, &guid_sha512, &efi_st_hash_len);
	if (ret == EFI_UNSUPPORTED) {
		efi_st_error("hash2->get_hash_size unsupported\n");
		return EFI_ST_FAILURE;
	} else if (ret == EFI_BUFFER_TOO_SMALL) {
		efi_st_error("hash2->get_hash_size on small buffer failed\n");
		return EFI_ST_FAILURE;
	}
	ret = hash2->get_hash_size(hash2, &guid_sha1_np, &efi_st_hash_len);
	if (ret == EFI_UNSUPPORTED) {
		efi_st_error("hash2->get_hash_size unsupported\n");
		return EFI_ST_FAILURE;
	} else if (ret == EFI_BUFFER_TOO_SMALL) {
		efi_st_error("hash2->get_hash_size on small buffer failed\n");
		return EFI_ST_FAILURE;
	}
	ret = hash2->get_hash_size(hash2, &guid_sha256_np, &efi_st_hash_len);
	if (ret == EFI_UNSUPPORTED) {
		efi_st_error("hash2->get_hash_size unsupported\n");
		return EFI_ST_FAILURE;
	} else if (ret == EFI_BUFFER_TOO_SMALL) {
		efi_st_error("hash2->get_hash_size on small buffer failed\n");
		return EFI_ST_FAILURE;
	}

	ret = hash2->hash(hash2, &guid_md5, efi_st_msg, efi_st_msg_len, hash);
	if (ret == EFI_UNSUPPORTED) {
		efi_st_error("hash2->hash unsupported\n");
		return EFI_ST_FAILURE;
	} else if (ret == EFI_INVALID_PARAMETER) {
		efi_st_error("hash2->hash failed\n");
		return EFI_ST_FAILURE;
	}
	ret = hash2->hash(hash2, &guid_sha1, efi_st_msg, efi_st_msg_len, hash);
	if (ret == EFI_UNSUPPORTED) {
		efi_st_error("hash2->hash unsupported\n");
		return EFI_ST_FAILURE;
	} else if (ret == EFI_INVALID_PARAMETER) {
		efi_st_error("hash2->hash failed\n");
		return EFI_ST_FAILURE;
	}
	ret = hash2->hash(hash2, &guid_sha224, efi_st_msg, efi_st_msg_len, hash);
	if (ret != EFI_UNSUPPORTED) {
		efi_st_error("hash2->hash unsupported\n");
		return EFI_ST_FAILURE;
	} else if (ret == EFI_INVALID_PARAMETER) {
		efi_st_error("hash2->hash failed\n");
		return EFI_ST_FAILURE;
	}
	ret = hash2->hash(hash2, &guid_sha256, efi_st_msg, efi_st_msg_len, hash);
	if (ret == EFI_UNSUPPORTED) {
		efi_st_error("hash2->hash unsupported\n");
		return EFI_ST_FAILURE;
	} else if (ret == EFI_INVALID_PARAMETER) {
		efi_st_error("hash2->hash failed\n");
		return EFI_ST_FAILURE;
	}
	ret = hash2->hash(hash2, &guid_sha384, efi_st_msg, efi_st_msg_len, hash);
	if (ret == EFI_UNSUPPORTED) {
		efi_st_error("hash2->hash unsupported\n");
		return EFI_ST_FAILURE;
	} else if (ret == EFI_INVALID_PARAMETER) {
		efi_st_error("hash2->hash failed\n");
		return EFI_ST_FAILURE;
	}
	ret = hash2->hash(hash2, &guid_sha512, efi_st_msg, efi_st_msg_len, hash);
	if (ret == EFI_UNSUPPORTED) {
		efi_st_error("hash2->hash unsupported\n");
		return EFI_ST_FAILURE;
	} else if (ret == EFI_INVALID_PARAMETER) {
		efi_st_error("hash2->hash failed\n");
		return EFI_ST_FAILURE;
	}
	ret = hash2->hash(hash2, &guid_sha1_np, efi_st_msg, efi_st_msg_len, hash);
	if (ret == EFI_UNSUPPORTED) {
		efi_st_error("hash2->hash unsupported\n");
		return EFI_ST_FAILURE;
	} else if (ret == EFI_INVALID_PARAMETER) {
		efi_st_error("hash2->hash failed\n");
		return EFI_ST_FAILURE;
	}
	ret = hash2->hash(hash2, &guid_sha256_np, efi_st_msg, efi_st_msg_len, hash);
	if (ret == EFI_UNSUPPORTED) {
		efi_st_error("hash2->hash unsupported\n");
		return EFI_ST_FAILURE;
	} else if (ret == EFI_INVALID_PARAMETER) {
		efi_st_error("hash2->hash failed\n");
		return EFI_ST_FAILURE;
	}
	
	return EFI_ST_SUCCESS;
}

EFI_UNIT_TEST(hash2) = {
	.name = "hash2",
	.phase = EFI_EXECUTE_BEFORE_BOOTTIME_EXIT,
	.execute = efi_st_hash2_execute,
	.setup = efi_st_hash2_setup,
};
