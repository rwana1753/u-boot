// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2023 Sukjin Kong <sjkong@coasia.com>
 * Copyright (c) 2023, CoAsia Nexell Co.,Ltd.
 */

#define LOG_CATEGORY LOGC_EFI

#include <common.h>
#include <efi_loader.h>
#include <efi_hash2.h>
#include <log.h>
#include <asm/global_data.h>
#include <u-boot/sha1.h>
#include <u-boot/sha256.h>
#include <u-boot/sha512.h>
#include <u-boot/md5.h>
#include <efi_selftest.h>//

DECLARE_GLOBAL_DATA_PTR;

const efi_guid_t efi_guid_hash2_protocol = EFI_HASH2_PROTOCOL_GUID;
const efi_guid_t efi_guid_md5_protocol = EFI_HASH_ALGORITHM_MD5_GUID;
const efi_guid_t efi_guid_sha1_protocol = EFI_HASH_ALGORITHM_SHA1_GUID;
const efi_guid_t efi_guid_sha224_protocol = EFI_HASH_ALGORITHM_SHA224_GUID;
const efi_guid_t efi_guid_sha256_protocol = EFI_HASH_ALGORITHM_SHA256_GUID;
const efi_guid_t efi_guid_sha384_protocol = EFI_HASH_ALGORITHM_SHA384_GUID;
const efi_guid_t efi_guid_sha512_protocol = EFI_HASH_ALGORITHM_SHA512_GUID;
const efi_guid_t efi_guid_sha1_np_protocol = EFI_HASH_ALGORITHM_SHA1_NOPAD_GUID;
const efi_guid_t efi_guid_sha256_np_protocol = EFI_HASH_ALGORITHM_SHA256_NOPAD_GUID;

efi_guid_t *efi_guid_hash_protocol;
void *ctxp;

sha1_context ctx_sha1;
sha256_context ctx_sha256;
sha512_context ctx_sha512;

/**
 * efi_get_hash_size() - get size of specific hash algorithm
 *
 * This function implement the GetHashSize() service of the EFI hash2 protocol.
 * See the UEFI spec for details.
 *
 * @this:			hash algorithm protocol instance
 * @hash_algorithm:			specific hash algorithm
 * @hash_size:		size of hash alogorithm
 * Return:			status code
 */
static efi_status_t EFIAPI efi_get_hash_size(
			struct efi_hash2_protocol *this,
			efi_guid_t *hash_algorithm,
			efi_uintn_t *hash_size)
{
	efi_status_t status = EFI_SUCCESS;

	EFI_ENTRY("%p, %p", this, hash_size);

	if (!this) {
		status = EFI_INVALID_PARAMETER;
		goto back;
	}

	efi_guid_hash_protocol = hash_algorithm;
	EFI_PRINT("HASH algorithm %pUl\n", efi_guid_hash_protocol);

	if (guidcmp(efi_guid_hash_protocol, &efi_guid_md5_protocol) == 0) {
		*hash_size = EFI_MD5_HASH_SIZE;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha1_protocol) == 0) {
        *hash_size = EFI_SHA1_HASH_SIZE;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha224_protocol) == 0) {
		*hash_size = 0;
		status = EFI_UNSUPPORTED;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha256_protocol) == 0) {
        *hash_size = EFI_SHA256_HASH_SIZE;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha384_protocol) == 0) {
        *hash_size = EFI_SHA384_HASH_SIZE;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha512_protocol) == 0) {
        *hash_size = EFI_SHA512_HASH_SIZE;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha1_np_protocol) == 0) {
        *hash_size = EFI_SHA256_HASH_SIZE;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha256_np_protocol) == 0) {
        *hash_size = EFI_SHA256_HASH_SIZE;
		goto back;
	} else {
		status = EFI_BUFFER_TOO_SMALL;
		goto back;
	}

back:
	return EFI_EXIT(status);
}

/**
 * efi_hash() - get value of specific hash algorithm
 *
 * This function implement the Hash() service of the EFI hash2 protocol.
 * See the UEFI spec for details.
 *
 * @this:			hash algorithm protocol instance
 * @hash_algorithm:			specific hash algorithm
 * @message:		start of messaage
 * @message_size:	size of message
 * @hash:			hash output
 * Return:			status code
 */
static efi_status_t EFIAPI efi_hash(
			struct efi_hash2_protocol *this,
			efi_guid_t *hash_algorithm,
			uint8_t *message,
			efi_uintn_t message_size,
			union efi_hash2_output *hash)
{
	efi_status_t status = EFI_SUCCESS;

	EFI_ENTRY("%p, %p, %p, %lx, %p", this, hash_algorithm, message, message_size, hash);

	if (!this) {
		status = EFI_INVALID_PARAMETER;
		goto back;
	}

	efi_guid_hash_protocol = hash_algorithm;
	EFI_PRINT("HASH algorithm %pUl\n", efi_guid_hash_protocol);

	if (guidcmp(efi_guid_hash_protocol, &efi_guid_md5_protocol) == 0) {
		md5(message, message_size, (unsigned char *)hash);
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha1_protocol) == 0) {
        sha1_starts(&ctx_sha1);
        sha1_update(&ctx_sha1, message, message_size);
        sha1_finish(&ctx_sha1, (uint8_t *)hash);
        ctxp = &ctx_sha1;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha224_protocol) == 0) {
		status = EFI_UNSUPPORTED;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha256_protocol) == 0) {
	    sha256_starts(&ctx_sha256);
        sha256_update(&ctx_sha256, message, message_size);
        sha256_finish(&ctx_sha256, (uint8_t *)hash);
        ctxp = &ctx_sha256;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha384_protocol) == 0) {
        sha384_starts(&ctx_sha512);
        sha384_update(&ctx_sha512, message, message_size);
        sha384_finish(&ctx_sha512, (uint8_t *)hash);
        ctxp = &ctx_sha512;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha512_protocol) == 0) {
        sha512_starts(&ctx_sha512);
        sha512_update(&ctx_sha512, message, message_size);
        sha512_finish(&ctx_sha512, (uint8_t *)hash);
        ctxp = &ctx_sha512;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha1_np_protocol) == 0) {
        sha1_starts(&ctx_sha1);
        sha1_update(&ctx_sha1, message, message_size);
        sha1_finish(&ctx_sha1, (uint8_t *)hash);
        ctxp = &ctx_sha1;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha256_np_protocol) == 0) {
        sha256_starts(&ctx_sha256);
        sha256_update(&ctx_sha256, message, message_size);
        sha256_finish(&ctx_sha256, (uint8_t *)hash);
        ctxp = &ctx_sha256;
		goto back;
	} else {
		status = EFI_INVALID_PARAMETER;
		goto back;
	}

back:
	return EFI_EXIT(status);
}

/**
 * efi_hash_init() - initialize value of specific hash algorithm
 *
 * This function implement the HashInit() service of the EFI hash2 protocol.
 * See the UEFI spec for details.
 *
 * @this:			hash algorithm protocol instance
 * @hash_algorithm:			specific hash algorithm
 * Return:			status code
 */
static efi_status_t EFIAPI efi_hash_init(
			struct efi_hash2_protocol *this,
			efi_guid_t *hash_algorithm)
{
	efi_status_t status = EFI_SUCCESS;

	EFI_ENTRY("%p, %p", this, hash_algorithm);

	if (!this) {
		status = EFI_INVALID_PARAMETER;
		goto back;
	}

	efi_guid_hash_protocol = hash_algorithm;
	EFI_PRINT("HASH algorithm %pUl\n", efi_guid_hash_protocol);

	if (guidcmp(efi_guid_hash_protocol, &efi_guid_md5_protocol)) {
		status = EFI_UNSUPPORTED;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha1_protocol)) {
        sha1_starts((sha1_context *)ctxp);
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha224_protocol)) {
		status = EFI_UNSUPPORTED;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha256_protocol)) {
	    sha256_starts((sha256_context *)ctxp);
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha384_protocol)) {
	    sha384_starts((sha512_context *)ctxp);
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha512_protocol)) {
	    sha512_starts((sha512_context *)ctxp);
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha1_np_protocol) == 0) {
	    sha1_starts((sha1_context *)ctxp);
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha256_np_protocol) == 0) {
	    sha256_starts((sha256_context *)ctxp);
		goto back;
	} else {
		status = EFI_UNSUPPORTED;
		goto back;
	}

back:
	return EFI_EXIT(status);
}

/**
 * efi_hash_update() - update value of specific hash algorithm
 *
 * This function implement the HashUpdate() service of the EFI hash2 protocol.
 * See the UEFI spec for details.
 *
 * @this:			hash algorithm protocol instance
 * @message:		start of messaage
 * @message_size:	size of message
 * Return:			status code
 */
static efi_status_t EFIAPI efi_hash_update(
			struct efi_hash2_protocol *this,
			uint8_t *message,
			efi_uintn_t message_size)
{
	efi_status_t status = EFI_SUCCESS;

	EFI_ENTRY("%p, %p, %lx", this, message, message_size);

	if (!this || !message_size) {
		status = EFI_INVALID_PARAMETER;
		goto back;
	}

	EFI_PRINT("HASH algorithm %pUl\n", efi_guid_hash_protocol);

	if (guidcmp(efi_guid_hash_protocol, &efi_guid_md5_protocol)) {
		status = EFI_UNSUPPORTED;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha1_protocol)) {
        sha1_update((sha1_context *)ctxp, message, message_size);
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha224_protocol)) {
		status = EFI_UNSUPPORTED;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha256_protocol)) {
        sha256_update((sha256_context *)ctxp, message, message_size);
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha384_protocol)) {
        sha384_update((sha512_context *)ctxp, message, message_size);
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha512_protocol)) {
        sha512_update((sha512_context *)ctxp, message, message_size);
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha1_np_protocol) == 0) {
        sha1_update((sha1_context *)ctxp, message, message_size);
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha256_np_protocol) == 0) {
        sha256_update((sha256_context *)ctxp, message, message_size);
		goto back;
	} else {
		status = EFI_UNSUPPORTED;
		goto back;
	}

back:
	return EFI_EXIT(status);
}

/**
 * efi_hash_final() - get value of specific hash algorithm
 *hash_init_sha256
 *
 * @this:			hash algorithm protocol instance
 * @hash:			hash output
 * Return:			status code
 */
static efi_status_t EFIAPI efi_hash_final(
			struct efi_hash2_protocol *this,
			union efi_hash2_output *hash)
{
	efi_status_t status = EFI_SUCCESS;

	if (!this) {
		status = EFI_INVALID_PARAMETER;
		goto back;
	}

	EFI_ENTRY("%p, %p", this, hash);

	if (!this) {
		status = EFI_INVALID_PARAMETER;
		goto back;
	}

	EFI_PRINT("HASH algorithm %pUl\n", efi_guid_hash_protocol);

	if (guidcmp(efi_guid_hash_protocol, &efi_guid_md5_protocol)) {
		status = EFI_UNSUPPORTED;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha1_protocol)) {
        sha1_finish((sha1_context *)ctxp, (uint8_t *)hash);
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha224_protocol)) {
		status = EFI_UNSUPPORTED;
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha256_protocol)) {
        sha256_finish((sha256_context *)ctxp, (uint8_t *)hash);
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha384_protocol)) {
        sha384_finish((sha512_context *)ctxp, (uint8_t *)hash);
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha512_protocol)) {
        sha512_finish((sha512_context *)ctxp, (uint8_t *)hash);
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol, &efi_guid_sha1_np_protocol) == 0) {
        sha1_finish((sha1_context *)ctxp, (uint8_t *)hash);
		goto back;
	} else if (guidcmp(efi_guid_hash_protocol,
				&efi_guid_sha256_np_protocol) == 0) {
		sha256_finish((sha256_context *)ctxp, (uint8_t *)hash);
		goto back;
	} else {
		status = EFI_UNSUPPORTED;
		goto back;
	}

back:
	return EFI_EXIT(status);
}

static const struct efi_hash2_protocol efi_hash2_protocol = {
	.get_hash_size = efi_get_hash_size,
	.hash = efi_hash,
	.hash_init = efi_hash_init,
	.hash_update = efi_hash_update,
	.hash_final = efi_hash_final,
};

/**
 * efi_hash2_register() - register EFI_HASH2_PROTOCOL
 *
 * If a hash algolithm is available, the Hash Protocol is
 * registered.
 *
 * Return:	An error status is only returned if adding the protocol fails.
 */
efi_status_t efi_hash2_register(void)
{
	efi_status_t ret;

	ret = efi_add_protocol(efi_root, &efi_guid_hash2_protocol,
			       (void *)&efi_hash2_protocol);
	if (ret != EFI_SUCCESS)
		log_err("Cannot install EFI_HASH2_PROTOCOL\n");

	return ret;
}
