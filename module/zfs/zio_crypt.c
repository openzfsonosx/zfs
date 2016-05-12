/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2016, Datto, Inc. All rights reserved.
 */

#include <sys/zio_crypt.h>
#include <sys/dmu.h>
#include <sys/dnode.h>
#include <sys/fs/zfs.h>
#include <sys/zio.h>
#include <sys/zil.h>

/*
 * This file is responsible for handling all of the details of generating
 * encryption parameters and performing encryption.
 *
 * BLOCK ENCRYPTION PARAMETERS:
 * Encryption Algorithm (crypt):
 * The encryption algorithm and mode we are going to use. We currently support
 * AES-GCM and AES-CCM in 128, 192, and 256 bits. All encryption parameters are
 * stored in little endian format (regardless of the host machine's byteorder).
 *
 * Plaintext:
 * The unencrypted data that we want to encrypt
 *
 * Initialization Vector (IV):
 * An initialization vector for the encryption algorithms. This is
 * used to "tweak" the encryption algorithms so that equivalent blocks of
 * data are encrypted into different ciphertext outputs. Different modes
 * of encryption have different requirements for the IV. AES-GCM and AES-CCM
 * require that an IV is never reused with the same encryption key. This
 * value is stored unencrypted and must simply be provided to the decryption
 * function. We use a 96 bit IV (as recommended by NIST). For non-dedup blocks
 * we derive the IV randomly. The first 64 bits of the IV are stored in the
 * second word of DVA[2] and the remaining 32 bits are stored in the upper 32
 * bits of blk_fill. For most object types this is safe because we only encrypt
 * level 0 blocks which means that the fill count will be 1. For DMU_OT_DNODE
 * blocks the fill count is instead used to indicate the number of free dnodes
 * beneath the bp. In either case, this number should still be smaller than
 * UINT32_MAX so it is safe to store the IV in the top 32 bits of blk_fill,
 * while leaving the bottom 32 bits of the fill count for the dnode code.
 *
 * Master key:
 * This is the most important secret data of an encrypted dataset. It is used
 * along with the salt to generate that actual encryption keys via HKDF. We
 * do not use the master key to encrypt any data because there are theoretical
 * limits on how much data can actually be safely encrypted with any encryption
 * mode. The master key is stored encrypted on disk with the user's key. It's
 * length is determined by the encryption algorithm. For details on how this is
 * stored see the block comment in dsl_crypt.c
 *
 * Salt:
 * Used as an input to the HKDF function, along with the master key. We use a
 * 64 bit salt, stored unencrypted in the first word of DVA[2]. Any given salt
 * can be used for encrypting many blocks, so we cache the current salt and the
 * associated derived key in zio_crypt_t so we do not need to derive it again
 * needlessly.
 *
 * Encryption Key:
 * A secret binary key, generated from an HKDF function used to encrypt and
 * decrypt data.
 *
 * Message Authenication Code (MAC)
 * The MAC is an output of authenticated encryption modes suce ahes AES-GCM and
 * AES-CCM. It's purpose is to ensure that an attacker cannot modify encrypted
 * data on disk and return garbage to the application. Effectively, it is a
 * checksum that can not be reproduced by an attacker. We store the MAC in the
 * second 128 bits of blk_cksum, leaving the first 128 bits for a truncated
 * regular checksum of the ciphertext which can be used for scrubbing.
 *
 *
 * ZIL ENCRYPTION:
 * ZIL blocks have their bp written to disk ahead of the associated data, so we
 * cannot store encyrption paramaters there as we normally do. For these blocks
 * the MAC is stored in the zil_chain_t header (in zc_mac) in a previously
 * unused 8 bytes. The salt and IV are generated for the block on bp allocation.
 * Since ZIL blocks are rewritten many times as new log records are added it is
 * important that we do not reuse the IV with the same salt. To accomplish this
 * we add in zc_nused from the zil_chain_t which should be incremented on each
 * rewrite.
 *
 * CONSIDERATIONS FOR DEDUP:
 * In order for dedup to work, we need to ensure that the ciphertext checksum
 * and MAC are quivalent for equivalent plaintexts. This requires using the
 * same IV and encryption key for equivalent blocks of plaindata. Normally,
 * one should never reuse an IV with the same encryption key or else AES-GCM
 * and AES-CCM can both actually leak the plaintext of both blocks. In this
 * case, however, since we are using the same plaindata as well all that we end
 * up with is a duplicate of the original data we already had. As a result,
 * an attacker with read access to the raw disk will be able to tell which
 * blocks are the same but this information is already given away by dedup
 * anyway. In order to get the same IVs and encryption keys for equivalent
 * blocks of data we use a HMAC of the plaindata. We use an HMAC here so there
 * is never a reproducible checksum of the plaindata available to the attacker.
 * The HMAC key is kept alongside the master key, encrypted on disk. The first
 * 64 bits are used in place of the salt, and the next 96 bits replace the IV.
 *
 *
 * XXX: There is some code in this file that allows dnode blocks to be
 * encrypted. The dnodes themselves are left in the clear while bonus buffers
 * are encrypted. This code allows dnodes to be scrubbed, sent, etc. without the
 * keys being loaded. This feature isn't currently used because the dbuf and
 * ARC layers will need a good amount of work before they are able to handle
 * partially encrypted dnodes. Once this work is done the code can be re-enabled
 * by flagging the DMU_OT_DNODE object type as encrypted in the dmu_ot table. In
 * the meantime all bonus buffers are forced off to spill blocks using the
 * sa_force_spill flag, keeping the user data safe since spill block encryption
 * can be managed the same way that normal blocks are. Enabling dnode encryption
 * shouldn't require any on-disk format changes
 */

zio_crypt_info_t zio_crypt_table[ZIO_CRYPT_FUNCTIONS] = {
	{"",			ZC_TYPE_NONE,	0,	"inherit"},
	{"",			ZC_TYPE_NONE,	0,	"on"},
	{"",			ZC_TYPE_NONE,	0,	"off"},
	{SUN_CKM_AES_CCM,	ZC_TYPE_CCM,	16,	"aes-128-ccm"},
	{SUN_CKM_AES_CCM,	ZC_TYPE_CCM,	24,	"aes-192-ccm"},
	{SUN_CKM_AES_CCM,	ZC_TYPE_CCM,	32,	"aes-256-ccm"},
	{SUN_CKM_AES_GCM,	ZC_TYPE_GCM,	16,	"aes-128-gcm"},
	{SUN_CKM_AES_GCM,	ZC_TYPE_GCM,	24,	"aes-192-gcm"},
	{SUN_CKM_AES_GCM,	ZC_TYPE_GCM,	32,	"aes-256-gcm"}
};

static int
hkdf_sha256_extract(uint8_t *salt, uint_t salt_len, uint8_t *key_material,
    uint_t km_len, uint8_t *out_buf)
{
	int ret;
	crypto_mechanism_t mech;
	crypto_key_t key;
	crypto_data_t input_cd, output_cd;

	/* initialize sha 256 hmac mechanism */
	mech.cm_type = crypto_mech2id(SUN_CKM_SHA256_HMAC);
	mech.cm_param = NULL;
	mech.cm_param_len = 0;

	/* initialize the salt as a crypto key */
	key.ck_format = CRYPTO_KEY_RAW;
	key.ck_length = BYTES_TO_BITS(salt_len);
	key.ck_data = salt;

	/* initialize crypto data for the input and output data */
	input_cd.cd_format = CRYPTO_DATA_RAW;
	input_cd.cd_offset = 0;
	input_cd.cd_length = km_len;
	input_cd.cd_raw.iov_base = (char *)key_material;
	input_cd.cd_raw.iov_len = km_len;

	output_cd.cd_format = CRYPTO_DATA_RAW;
	output_cd.cd_offset = 0;
	output_cd.cd_length = SHA_256_DIGEST_LEN;
	output_cd.cd_raw.iov_base = (char *)out_buf;
	output_cd.cd_raw.iov_len = SHA_256_DIGEST_LEN;

	ret = crypto_mac(&mech, &input_cd, &key, NULL, &output_cd, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	return (0);

error:
	return (ret);
}

static int
hkdf_sha256_expand(uint8_t *extract_key, uint8_t *info, uint_t info_len,
    uint8_t *out_buf, uint_t out_len)
{
	int ret;
	crypto_mechanism_t mech;
	crypto_context_t ctx;
	crypto_key_t key;
	crypto_data_t T_cd, info_cd, c_cd;
	uint_t i, T_len = 0, pos = 0;
	uint_t c;
	uint_t N = (out_len + SHA_256_DIGEST_LEN) / SHA_256_DIGEST_LEN;
	uint8_t T[SHA_256_DIGEST_LEN];

	if (N > 255)
		return (SET_ERROR(EINVAL));

	/* initialize sha 256 hmac mechanism */
	mech.cm_type = crypto_mech2id(SUN_CKM_SHA256_HMAC);
	mech.cm_param = NULL;
	mech.cm_param_len = 0;

	/* initialize the salt as a crypto key */
	key.ck_format = CRYPTO_KEY_RAW;
	key.ck_length = BYTES_TO_BITS(SHA_256_DIGEST_LEN);
	key.ck_data = extract_key;

	/* initialize crypto data for the input and output data */
	T_cd.cd_format = CRYPTO_DATA_RAW;
	T_cd.cd_offset = 0;
	T_cd.cd_raw.iov_base = (char *)T;

	c_cd.cd_format = CRYPTO_DATA_RAW;
	c_cd.cd_offset = 0;
	c_cd.cd_length = 1;
	c_cd.cd_raw.iov_base = (char *)&c;
	c_cd.cd_raw.iov_len = 1;

	info_cd.cd_format = CRYPTO_DATA_RAW;
	info_cd.cd_offset = 0;
	info_cd.cd_length = info_len;
	info_cd.cd_raw.iov_base = (char *)info;
	info_cd.cd_raw.iov_len = info_len;

	for (i = 1; i <= N; i++) {
		c = i;

		T_cd.cd_length = T_len;
		T_cd.cd_raw.iov_len = T_len;

		ret = crypto_mac_init(&mech, &key, NULL, &ctx, NULL);
		if (ret != CRYPTO_SUCCESS) {
			ret = SET_ERROR(EIO);
			goto error;
		}

		ret = crypto_mac_update(ctx, &T_cd, NULL);
		if (ret != CRYPTO_SUCCESS) {
			ret = SET_ERROR(EIO);
			goto error;
		}

		ret = crypto_mac_update(ctx, &info_cd, NULL);
		if (ret != CRYPTO_SUCCESS) {
			ret = SET_ERROR(EIO);
			goto error;
		}

		ret = crypto_mac_update(ctx, &c_cd, NULL);
		if (ret != CRYPTO_SUCCESS) {
			ret = SET_ERROR(EIO);
			goto error;
		}

		T_len = SHA_256_DIGEST_LEN;
		T_cd.cd_length = T_len;
		T_cd.cd_raw.iov_len = T_len;

		ret = crypto_mac_final(ctx, &T_cd, NULL);
		if (ret != CRYPTO_SUCCESS) {
			ret = SET_ERROR(EIO);
			goto error;
		}

		bcopy(T, out_buf + pos,
		    (i != N) ? SHA_256_DIGEST_LEN : (out_len - pos));
		pos += SHA_256_DIGEST_LEN;
	}

	return (0);

error:
	return (ret);
}

/*
 * HKDF is designed to be a relatively fast function for deriving keys from a
 * master key + a salt. We use this function to generate new encryption keys
 * so as to avoid hitting the cryptographic limits of the underlying
 * encryption modes. Note that, for the sake of deriving encryption keys, the
 * info parameter is called the "salt" everywhere else in the code.
 */
static int
hkdf_sha256(uint8_t *key_material, uint_t km_len, uint8_t *salt,
    uint_t salt_len, uint8_t *info, uint_t info_len, uint8_t *output_key,
    uint_t out_len)
{
	int ret;
	uint8_t extract_key[SHA_256_DIGEST_LEN];

	ret = hkdf_sha256_extract(salt, salt_len, key_material, km_len,
	    extract_key);
	if (ret)
		goto error;

	ret = hkdf_sha256_expand(extract_key, info, info_len, output_key,
	    out_len);
	if (ret)
		goto error;

	return (0);

error:
	return (ret);
}

void
zio_crypt_key_destroy(zio_crypt_key_t *key)
{
	rw_destroy(&key->zk_salt_lock);

	/* free crypto templates */
	crypto_destroy_ctx_template(key->zk_current_tmpl);
	crypto_destroy_ctx_template(key->zk_hmac_tmpl);

	/* zero out sensitive data */
	bzero(key, sizeof (zio_crypt_key_t));
}

int
zio_crypt_key_init(uint64_t crypt, zio_crypt_key_t *key)
{
	int ret;
	crypto_mechanism_t mech;
	uint_t keydata_len;

	ASSERT(key != NULL);
	ASSERT3U(crypt, <, ZIO_CRYPT_FUNCTIONS);

	keydata_len = zio_crypt_table[crypt].ci_keylen;

	/* fill keydata buffers and salt with random data */
	ret = random_get_bytes(key->zk_master_keydata, keydata_len);
	if (ret)
		goto error;

	ret = random_get_bytes(key->zk_hmac_keydata, HMAC_SHA256_KEYLEN);
	if (ret)
		goto error;

	ret = random_get_bytes(key->zk_salt, DATA_SALT_LEN);
	if (ret)
		goto error;

	/* derive the current key from the master key */
	ret = hkdf_sha256(key->zk_master_keydata, keydata_len, NULL, 0,
	    key->zk_salt, DATA_SALT_LEN, key->zk_current_keydata, keydata_len);
	if (ret)
		goto error;

	/* initialize keys for the ICP */
	key->zk_current_key.ck_format = CRYPTO_KEY_RAW;
	key->zk_current_key.ck_data = key->zk_current_keydata;
	key->zk_current_key.ck_length = BYTES_TO_BITS(keydata_len);

	key->zk_hmac_key.ck_format = CRYPTO_KEY_RAW;
	key->zk_hmac_key.ck_data = &key->zk_hmac_key;
	key->zk_hmac_key.ck_length = BYTES_TO_BITS(HMAC_SHA256_KEYLEN);

	/*
	 * Initialize the crypto templates. It's ok if this fails because
	 * this is just an optimization.
	 */
	mech.cm_type = crypto_mech2id(zio_crypt_table[crypt].ci_mechname);
	ret = crypto_create_ctx_template(&mech, &key->zk_current_key,
	    &key->zk_current_tmpl, KM_SLEEP);
	if (ret != CRYPTO_SUCCESS)
		key->zk_current_tmpl = NULL;

	mech.cm_type = crypto_mech2id(SUN_CKM_SHA256_HMAC);
	ret = crypto_create_ctx_template(&mech, &key->zk_hmac_key,
	    &key->zk_hmac_tmpl, KM_SLEEP);
	if (ret != CRYPTO_SUCCESS)
		key->zk_hmac_tmpl = NULL;

	key->zk_crypt = crypt;
	key->zk_salt_count = 0;
	rw_init(&key->zk_salt_lock, NULL, RW_DEFAULT, NULL);

	return (0);

error:
	zio_crypt_key_destroy(key);
	return (ret);
}

static int
zio_crypt_key_change_salt(zio_crypt_key_t *key)
{
	int ret;
	uint8_t salt[DATA_SALT_LEN];
	crypto_mechanism_t mech;
	uint_t keydata_len = zio_crypt_table[key->zk_crypt].ci_keylen;

	/* generate a new salt */
	ret = random_get_bytes(salt, DATA_SALT_LEN);
	if (ret)
		goto error;

	rw_enter(&key->zk_salt_lock, RW_WRITER);

	/* derive the current key from the master key and the new salt */
	ret = hkdf_sha256(key->zk_master_keydata, keydata_len, NULL, 0,
	    salt, DATA_SALT_LEN, key->zk_current_keydata, keydata_len);
	if (ret)
		goto error_unlock;

	/* assign the salt and reset the usage count */
	bcopy(salt, key->zk_salt, DATA_SALT_LEN);
	key->zk_salt_count = 0;

	/* destroy the old context template and create the new one */
	crypto_destroy_ctx_template(key->zk_current_tmpl);
	ret = crypto_create_ctx_template(&mech, &key->zk_current_key,
	    &key->zk_current_tmpl, KM_SLEEP);
	if (ret != CRYPTO_SUCCESS)
		key->zk_current_tmpl = NULL;

	rw_exit(&key->zk_salt_lock);

	return (0);

error_unlock:
	rw_exit(&key->zk_salt_lock);
error:
	return (ret);
}

/* See comment above ZIO_CRYPT_MAX_SALT_USAGE definition for details */
int
zio_crypt_key_get_salt(zio_crypt_key_t *key, uint8_t *salt)
{
	int ret;
	boolean_t salt_change;

	rw_enter(&key->zk_salt_lock, RW_READER);

	bcopy(key->zk_salt, salt, DATA_SALT_LEN);
	salt_change = (atomic_inc_64_nv(&key->zk_salt_count) ==
	    ZIO_CRYPT_MAX_SALT_USAGE);

	rw_exit(&key->zk_salt_lock);

	if (salt_change) {
		ret = zio_crypt_key_change_salt(key);
		if (ret)
			goto error;
	}

	return (0);

error:
	return (ret);
}

/*
 * This function handles all encryption and decryption in zfs. When
 * encrypting it expects puio to reference the plaintext and cuio to
 * have enough space for the ciphertext + room for a MAC. On decrypting
 * it expects both puio and cuio to have enough room for a MAC, although
 * the plaintext uio can be dsicarded afterwards. datalen should be the
 * length of only the plaintext / ciphertext in either case.
 */
static int
zio_do_crypt_uio(boolean_t encrypt, uint64_t crypt, crypto_key_t *key,
    crypto_ctx_template_t tmpl, uint8_t *ivbuf, uint_t datalen,
    uio_t *puio, uio_t *cuio)
{
	int ret;
	crypto_data_t plaindata, cipherdata;
	CK_AES_CCM_PARAMS ccmp;
	CK_AES_GCM_PARAMS gcmp;
	crypto_mechanism_t mech;
	zio_crypt_info_t crypt_info;
	uint_t plain_full_len;
	uint64_t maclen;

	ASSERT3U(crypt, <, ZIO_CRYPT_FUNCTIONS);
	ASSERT3U(key->ck_format, ==, CRYPTO_KEY_RAW);

	/* lookup the encryption info */
	crypt_info = zio_crypt_table[crypt];

	/* the mac will always be the last iovec_t in the cipher uio */
	user_addr_t mac;
	uio_getiov(cuio, uio_iovcnt(cuio) - 1, &mac, &maclen);

	ASSERT(maclen <= DATA_MAC_LEN);

	/* setup encryption mechanism (same as crypt) */
	mech.cm_type = crypto_mech2id(crypt_info.ci_mechname);

	/* plain length will include the MAC if we are decrypting */
	if (encrypt) {
		plain_full_len = datalen;
	} else {
		plain_full_len = datalen + maclen;
	}

	/*
	 * setup encryption params (currently only AES CCM and AES GCM
	 * are supported)
	 */
	if (crypt_info.ci_crypt_type == ZC_TYPE_CCM) {
		ccmp.ulNonceSize = DATA_IV_LEN;
		ccmp.ulAuthDataSize = 0;
		ccmp.authData = NULL;
		ccmp.ulMACSize = maclen;
		ccmp.nonce = ivbuf;
		ccmp.ulDataSize = plain_full_len;

		mech.cm_param = (char *)(&ccmp);
		mech.cm_param_len = sizeof (CK_AES_CCM_PARAMS);
	} else {
		gcmp.ulIvLen = DATA_IV_LEN;
		gcmp.ulIvBits = BYTES_TO_BITS(DATA_IV_LEN);
		gcmp.ulAADLen = 0;
		gcmp.pAAD = NULL;
		gcmp.ulTagBits = BYTES_TO_BITS(maclen);
		gcmp.pIv = ivbuf;

		mech.cm_param = (char *)(&gcmp);
		mech.cm_param_len = sizeof (CK_AES_GCM_PARAMS);
	}

	/* populate the cipher and plain data structs. */
	plaindata.cd_format = CRYPTO_DATA_UIO;
	plaindata.cd_offset = 0;
	plaindata.cd_uio = puio;
	plaindata.cd_miscdata = NULL;
	plaindata.cd_length = plain_full_len;

	cipherdata.cd_format = CRYPTO_DATA_UIO;
	cipherdata.cd_offset = 0;
	cipherdata.cd_uio = cuio;
	cipherdata.cd_miscdata = NULL;
	cipherdata.cd_length = datalen + maclen;

	/* perform the actual encryption */
	if (encrypt) {
		ret = crypto_encrypt(&mech, &plaindata, key, tmpl, &cipherdata,
		    NULL);
	} else {
		ret = crypto_decrypt(&mech, &cipherdata, key, tmpl, &plaindata,
		    NULL);
	}

	if (ret != CRYPTO_SUCCESS) {
		panic("ZFS: crypto");
		ret = SET_ERROR(EIO);
		goto error;
	}

	return (0);

error:
	return (ret);
}

int
zio_crypt_key_wrap(crypto_key_t *cwkey, zio_crypt_key_t *key, uint8_t *iv,
    uint8_t *mac, uint8_t *keydata_out, uint8_t *hmac_keydata_out)
{
	int ret;
	uio_t *puio = NULL, *cuio = NULL;
	uint64_t crypt = key->zk_crypt;
	uint_t enc_len, keydata_len;

	ASSERT3U(crypt, <, ZIO_CRYPT_FUNCTIONS);
	ASSERT3U(cwkey->ck_format, ==, CRYPTO_KEY_RAW);

	keydata_len = zio_crypt_table[crypt].ci_keylen;

	/* generate iv for wrapping the master and hmac key */
	ret = random_get_pseudo_bytes(iv, WRAPPING_IV_LEN);
	if (ret)
		goto error;

	puio = uio_create(2, 0, UIO_SYSSPACE, UIO_READ);
	if (!puio) {
		ret = SET_ERROR(ENOMEM);
		goto error;
	}

	cuio = uio_create(3, 0, UIO_SYSSPACE, UIO_WRITE);
	if (!cuio) {
		ret = SET_ERROR(ENOMEM);
		goto error;
	}

	/* initialize uio_ts */
	VERIFY0(uio_addiov(puio, (user_addr_t)key->zk_master_keydata,
					   keydata_len));
	VERIFY0(uio_addiov(puio, (user_addr_t)key->zk_hmac_keydata,
					   HMAC_SHA256_KEYLEN));

	VERIFY0(uio_addiov(cuio, (user_addr_t)keydata_out, keydata_len));
	VERIFY0(uio_addiov(cuio, (user_addr_t)hmac_keydata_out,
					   HMAC_SHA256_KEYLEN));
	VERIFY0(uio_addiov(cuio, (user_addr_t)mac, WRAPPING_MAC_LEN));

	enc_len = zio_crypt_table[crypt].ci_keylen + HMAC_SHA256_KEYLEN;

	/* encrypt the keys and store the resulting ciphertext and mac */
	ret = zio_do_crypt_uio(B_TRUE, crypt, cwkey, NULL, iv, enc_len,
	    puio, cuio);
	if (ret)
		goto error;

	if (puio) uio_free(puio);
	if (cuio) uio_free(cuio);

	return (0);

error:
	if (puio) uio_free(puio);
	if (cuio) uio_free(cuio);

	return (ret);
}

int
zio_crypt_key_unwrap(crypto_key_t *cwkey, uint64_t crypt, uint8_t *keydata,
    uint8_t *hmac_keydata, uint8_t *iv, uint8_t *mac, zio_crypt_key_t *key)
{
	int ret;
	crypto_mechanism_t mech;
	uio_t *puio = NULL, *cuio = NULL;
	uint8_t outmac[WRAPPING_MAC_LEN];
	uint_t enc_len, keydata_len;

	ASSERT3U(crypt, <, ZIO_CRYPT_FUNCTIONS);
	ASSERT3U(cwkey->ck_format, ==, CRYPTO_KEY_RAW);

	keydata_len = zio_crypt_table[crypt].ci_keylen;

	puio = uio_create(3, 0, UIO_SYSSPACE, UIO_WRITE);
	if (!puio) {
		ret = SET_ERROR(ENOMEM);
		goto error;
	}

	cuio = uio_create(3, 0, UIO_SYSSPACE, UIO_READ);
	if (!cuio) {
		ret = SET_ERROR(ENOMEM);
		goto error;
	}

	/* initialize uio_ts */
	VERIFY0(uio_addiov(puio, (user_addr_t)key->zk_master_keydata,
					   keydata_len));
	VERIFY0(uio_addiov(puio, (user_addr_t)key->zk_hmac_keydata,
					   HMAC_SHA256_KEYLEN));
	VERIFY0(uio_addiov(puio, (user_addr_t)outmac,
					   WRAPPING_MAC_LEN));

	VERIFY0(uio_addiov(cuio, (user_addr_t)keydata, keydata_len));
	VERIFY0(uio_addiov(cuio, (user_addr_t)hmac_keydata,
					   HMAC_SHA256_KEYLEN));
	VERIFY0(uio_addiov(cuio, (user_addr_t)mac, WRAPPING_MAC_LEN));

	enc_len = keydata_len + HMAC_SHA256_KEYLEN;

	/* decrypt the keys and store the result in the output buffers */
	ret = zio_do_crypt_uio(B_FALSE, crypt, cwkey, NULL, iv, enc_len,
	    puio, cuio);
	if (ret)
		goto error;

	/* generate a fresh salt */
	ret = random_get_bytes(key->zk_salt, DATA_SALT_LEN);
	if (ret)
		goto error;

	/* derive the current key from the master key */
	ret = hkdf_sha256(key->zk_master_keydata, keydata_len, NULL, 0,
	    key->zk_salt, DATA_SALT_LEN, key->zk_current_keydata, keydata_len);
	if (ret)
		goto error;

	/* initialize keys for ICP */
	key->zk_current_key.ck_format = CRYPTO_KEY_RAW;
	key->zk_current_key.ck_data = key->zk_current_keydata;
	key->zk_current_key.ck_length = BYTES_TO_BITS(keydata_len);

	key->zk_hmac_key.ck_format = CRYPTO_KEY_RAW;
	key->zk_hmac_key.ck_data = key->zk_hmac_keydata;
	key->zk_hmac_key.ck_length = BYTES_TO_BITS(HMAC_SHA256_KEYLEN);

	/*
	 * Initialize the crypto templates. It's ok if this fails because
	 * this is just an optimization.
	 */
	mech.cm_type = crypto_mech2id(zio_crypt_table[crypt].ci_mechname);
	ret = crypto_create_ctx_template(&mech, &key->zk_current_key,
	    &key->zk_current_tmpl, KM_SLEEP);
	if (ret != CRYPTO_SUCCESS)
		key->zk_current_tmpl = NULL;

	mech.cm_type = crypto_mech2id(SUN_CKM_SHA256_HMAC);
	ret = crypto_create_ctx_template(&mech, &key->zk_hmac_key,
	    &key->zk_hmac_tmpl, KM_SLEEP);
	if (ret != CRYPTO_SUCCESS)
		key->zk_hmac_tmpl = NULL;

	key->zk_crypt = crypt;
	key->zk_salt_count = 0;
	rw_init(&key->zk_salt_lock, NULL, RW_DEFAULT, NULL);

	if (puio) uio_free(puio);
	if (cuio) uio_free(cuio);

	return (0);

error:
	if (puio) uio_free(puio);
	if (cuio) uio_free(cuio);
	zio_crypt_key_destroy(key);
	return (ret);
}

int
zio_crypt_generate_iv(uint8_t *ivbuf)
{
	int ret;

	/* randomly generate the IV */
	ret = random_get_pseudo_bytes(ivbuf, DATA_IV_LEN);
	if (ret)
		goto error;

	return (0);

error:
	bzero(ivbuf, DATA_IV_LEN);
	return (ret);
}

int
zio_crypt_generate_iv_salt_dedup(zio_crypt_key_t *key, uint8_t *data,
    uint_t datalen, uint8_t *ivbuf, uint8_t *salt)
{
	int ret;
	crypto_mechanism_t mech;
	crypto_data_t in_data, digest_data;
	uint8_t digestbuf[SHA_256_DIGEST_LEN];

	/* initialize sha256-hmac mechanism and crypto data */
	mech.cm_type = crypto_mech2id(SUN_CKM_SHA256_HMAC);
	mech.cm_param = NULL;
	mech.cm_param_len = 0;

	/* initialize the crypto data */
	in_data.cd_format = CRYPTO_DATA_RAW;
	in_data.cd_offset = 0;
	in_data.cd_length = datalen;
	in_data.cd_raw.iov_base = (char *)data;
	in_data.cd_raw.iov_len = datalen;

	digest_data.cd_format = CRYPTO_DATA_RAW;
	digest_data.cd_offset = 0;
	digest_data.cd_length = SHA_256_DIGEST_LEN;
	digest_data.cd_raw.iov_base = (char *)digestbuf;
	digest_data.cd_raw.iov_len = SHA_256_DIGEST_LEN;

	/* generate the hmac */
	ret = crypto_mac(&mech, &in_data, &key->zk_hmac_key, key->zk_hmac_tmpl,
	    &digest_data, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* truncate and copy the digest into the output buffer */
	bcopy(digestbuf, salt, DATA_SALT_LEN);
	bcopy(digestbuf + DATA_SALT_LEN, ivbuf, DATA_IV_LEN);

	return (0);

error:
	return (ret);
}

void
zio_crypt_encode_params_bp(blkptr_t *bp, uint8_t *salt, uint8_t *iv)
{
 	uint32_t *iv2 = (uint32_t *)(iv + sizeof (uint64_t));

 	ASSERT(BP_IS_ENCRYPTED(bp));
 	bp->blk_dva[2].dva_word[0] = LE_64(*((uint64_t *)salt));

 	bp->blk_dva[2].dva_word[1] = LE_64(*((uint64_t *)iv));
 	BP_SET_IV2(bp, LE_32(*iv2));
}

void
zio_crypt_decode_params_bp(const blkptr_t *bp, uint8_t *salt, uint8_t *iv)
{
 	uint32_t *iv2 = (uint32_t *)(iv + sizeof (uint64_t));

 	ASSERT(BP_IS_ENCRYPTED(bp));
 	*((uint64_t *)salt) = LE_64(bp->blk_dva[2].dva_word[0]);

 	*((uint64_t *)iv) = LE_64(bp->blk_dva[2].dva_word[1]);
 	*((uint32_t *)iv2) = LE_32((uint32_t)BP_GET_IV2(bp));
}

void
zio_crypt_encode_mac_bp(blkptr_t *bp, uint8_t *mac)
{
 	ASSERT(BP_IS_ENCRYPTED(bp));
 	bp->blk_cksum.zc_word[2] = LE_64(((uint64_t *)mac)[0]);
 	bp->blk_cksum.zc_word[3] = LE_64(((uint64_t *)mac)[1]);
}

void
zio_crypt_decode_mac_bp(const blkptr_t *bp, uint8_t *mac)
{
 	ASSERT(BP_IS_ENCRYPTED(bp));
 	((uint64_t *)mac)[0] = LE_64(bp->blk_cksum.zc_word[2]);
 	((uint64_t *)mac)[1] = LE_64(bp->blk_cksum.zc_word[3]);
}

static void zio_crypt_destroy_uio(uio_t *uio)
{
#ifdef _KERNEL
	if (uio) uio_free(uio);
#endif
}

/*
 * We do not check for the older zil chain because this feature was not
 * available before the newer zil chain was introduced. The goal here
 * is to encrypt everything except the blkptr_t of a lr_write_t and
 * the zil_chain_t header.
 */
static int
zio_crypt_init_uios_zil(boolean_t encrypt, uint8_t *plainbuf,
	uint8_t *cipherbuf, uint_t datalen, uio_t **puio, uio_t **cuio,
	uint_t *enc_len)
{
	int ret;
	uint_t nr_src, nr_dst, lr_len, crypt_len, nr_iovecs = 0, total_len = 0;
	uint8_t *src, *dst, *slrp, *dlrp, *end;
	zil_chain_t *zilc;
	lr_t *lr;
	uio_t *srcuio = NULL, *dstuio = NULL;

	/* if we are decrypting, the plainbuffer needs an extra iovec */
	if (encrypt) {
		src = plainbuf;
		dst = cipherbuf;
		nr_src = 0;
		nr_dst = 1;
	} else {
		src = cipherbuf;
		dst = plainbuf;
		nr_src = 1;
		nr_dst = 1;
	}

	/* find the start and end record of the log block */
	zilc = (zil_chain_t *) src;
	end = src + zilc->zc_nused;
	slrp = src + sizeof (zil_chain_t);

	/* calculate the number of encrypted iovecs we will need */
	for (; slrp < end; slrp += lr_len) {
		lr = (lr_t *) slrp;
		lr_len = lr->lrc_reclen;

		nr_iovecs++;
		if (lr->lrc_txtype == TX_WRITE &&
		    lr_len != sizeof (lr_write_t))
			nr_iovecs++;
	}

	if (nr_iovecs == 0) {
		*enc_len = 0;
		return (ZIO_NO_ENCRYPTION_NEEDED);
	}

	nr_src += nr_iovecs;
	nr_dst += nr_iovecs;


	/* allocate the uio to hold iovecs */
	srcuio = uio_create(nr_src, 0, UIO_SYSSPACE, UIO_READ);
	if (!srcuio) {
		ret = SET_ERROR(ENOMEM);
		goto error;
	}

	dstuio = uio_create(nr_dst, 0, UIO_SYSSPACE, UIO_WRITE);
	if (!dstuio) {
		ret = SET_ERROR(ENOMEM);
		goto error;
	}

	/* loop over records again, filling in iovecs */
	nr_iovecs = 0;
	slrp = src + sizeof (zil_chain_t);
	dlrp = dst + sizeof (zil_chain_t);

	for (; slrp < end; slrp += lr_len, dlrp += lr_len) {
		lr = (lr_t *) slrp;
		lr_len = lr->lrc_reclen;

		if (lr->lrc_txtype == TX_WRITE) {
			bcopy(slrp, dlrp, sizeof (lr_t));
			crypt_len = sizeof (lr_write_t) -
			    sizeof (lr_t) - sizeof (blkptr_t);

			VERIFY0(uio_addiov(srcuio, (user_addr_t)slrp + sizeof (lr_t),
							   crypt_len));
			VERIFY0(uio_addiov(dstuio, (user_addr_t)dlrp + sizeof (lr_t),
							   crypt_len));

			/* copy the bp now since it will not be encrypted */
			bcopy(slrp + sizeof (lr_write_t) - sizeof (blkptr_t),
			    dlrp + sizeof (lr_write_t) - sizeof (blkptr_t),
			    sizeof (blkptr_t));
			nr_iovecs++;
			total_len += crypt_len;

			if (lr_len != sizeof (lr_write_t)) {
				crypt_len = lr_len - sizeof (lr_write_t);

				VERIFY0(uio_addiov(srcuio,
								   (user_addr_t)slrp + sizeof (lr_write_t),
								   crypt_len));
				VERIFY0(uio_addiov(dstuio,
								   (user_addr_t)dlrp + sizeof (lr_write_t),
								   crypt_len));
				nr_iovecs++;
				total_len += crypt_len;
			}
		} else {
			bcopy(slrp, dlrp, sizeof (lr_t));
			crypt_len = lr_len - sizeof (lr_t);
			VERIFY0(uio_addiov(srcuio, (user_addr_t)slrp + sizeof (lr_t),
							   crypt_len));
			VERIFY0(uio_addiov(dstuio, (user_addr_t)dlrp + sizeof (lr_t),
							   crypt_len));
			nr_iovecs++;
			total_len += crypt_len;
		}
	}

	/* copy the plain zil header over */
	bcopy(src, dst, sizeof (zil_chain_t));

	*enc_len = total_len;

	if (encrypt) {
		*puio = srcuio;
		*cuio = dstuio;
	} else {
		*puio = dstuio;
		*cuio = srcuio;
	}

	return (0);

error:
	if (srcuio) uio_free(srcuio);
	if (dstuio) uio_free(dstuio);

	*enc_len = 0;

	return (ret);
}

static int
zio_crypt_init_uios_dnode(boolean_t encrypt, uint8_t *plainbuf,
    uint8_t *cipherbuf, uint_t datalen, uio_t **puio, uio_t **cuio,
    uint_t *enc_len)
{
	int ret;
	uint_t nr_src, nr_dst, crypt_len, total_len = 0, nr_iovecs = 0;
	uint_t i, max_dnp = datalen >> DNODE_SHIFT;
	uint8_t *src, *dst, *bonus, *bonus_end, *dn_end;
	dnode_phys_t *dnp, *sdnp, *ddnp;
	struct uio *src_uio = NULL, *dst_uio = NULL;

	if (encrypt) {
		src = plainbuf;
		dst = cipherbuf;
		nr_src = 0;
		nr_dst = 1;
	} else {
		src = cipherbuf;
		dst = plainbuf;
		nr_src = 1;
		nr_dst = 1;
	}

	sdnp = (dnode_phys_t *)src;
	ddnp = (dnode_phys_t *)dst;

	/* Until we get large-dnode support, we assume dn_extra_slots is 0 */
#define DN_SPILL_BLKPTR(dnp)    (blkptr_t *)((char *)(dnp) +			\
        ((/*(dnp)->dn_extra_slots*/ + 1) << DNODE_SHIFT) - (1 << SPA_BLKPTRSHIFT))

	for (i = 0; i < max_dnp; i += /*sdnp[i].dn_extra_slots*/ + 1) {
		if (sdnp[i].dn_type != DMU_OT_NONE &&
		    DMU_OT_IS_ENCRYPTED(sdnp[i].dn_bonustype) &&
		    sdnp[i].dn_bonuslen != 0) {
			nr_iovecs++;
		}
	}

	if (nr_iovecs == 0) {
		*enc_len = 0;
		return (ZIO_NO_ENCRYPTION_NEEDED);
	}

	nr_src += nr_iovecs;
	nr_dst += nr_iovecs;

	src_uio = uio_create(nr_src, 0, UIO_SYSSPACE, UIO_READ);
	if (!src_uio) {
		ret = SET_ERROR(ENOMEM);
		goto error;
	}
	dst_uio = uio_create(nr_dst, 0, UIO_SYSSPACE, UIO_WRITE);
	if (!src_uio) {
		ret = SET_ERROR(ENOMEM);
		goto error;
	}

	nr_iovecs = 0;

	for (i = 0; i < max_dnp; i += /*sdnp[i].dn_extra_slots*/ + 1) {
		dnp = &sdnp[i];
		dn_end = (uint8_t *)(dnp + (/*dnp->dn_extra_slots*/ + 1));
		if (dnp->dn_type != DMU_OT_NONE &&
		    DMU_OT_IS_ENCRYPTED(dnp->dn_bonustype) &&
		    dnp->dn_bonuslen != 0) {
			bonus = (uint8_t *)DN_BONUS(dnp);
			if (dnp->dn_flags & DNODE_FLAG_SPILL_BLKPTR) {
				bonus_end = (uint8_t *)DN_SPILL_BLKPTR(dnp);
			} else {
				bonus_end = (uint8_t *)dn_end;
			}
			crypt_len = bonus_end - bonus;

			bcopy(dnp, &ddnp[i], bonus - (uint8_t *)dnp);

			VERIFY0(uio_addiov(src_uio, (user_addr_t)bonus,
					crypt_len));
			VERIFY0(uio_addiov(dst_uio, (user_addr_t)DN_BONUS(&ddnp[i]),
					crypt_len));

			if (dnp->dn_flags & DNODE_FLAG_SPILL_BLKPTR)
				bcopy(bonus_end, DN_SPILL_BLKPTR(&ddnp[i]),
				    sizeof (blkptr_t));

			nr_iovecs++;
			total_len += crypt_len;
		} else {
			bcopy(dnp, &ddnp[i], dn_end - (uint8_t *)dnp);
		}
	}

	*enc_len = total_len;

	if (encrypt) {
		*puio = src_uio;
		*cuio = dst_uio;
	} else {
		*puio = dst_uio;
		*cuio = src_uio;
	}

	return (0);

error:
	zio_crypt_destroy_uio(src_uio);
	zio_crypt_destroy_uio(dst_uio);

	*enc_len = 0;
	return (ret);
}

static int
zio_crypt_init_uios_normal(boolean_t encrypt, uint8_t *plainbuf,
	uint8_t *cipherbuf, uint_t datalen, uio_t **puio, uio_t **cuio,
	uint_t *enc_len)
{
	int ret = 0;

	if (encrypt) {
		*puio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
		*cuio = uio_create(2, 0, UIO_SYSSPACE, UIO_WRITE);
	} else {
		*puio = uio_create(2, 0, UIO_SYSSPACE, UIO_WRITE);
		*cuio = uio_create(2, 0, UIO_SYSSPACE, UIO_READ);
	}
	if (!*puio || !*cuio) {
		ret = SET_ERROR(ENOMEM);
		goto out;
	}

	VERIFY0(uio_addiov(*puio, (user_addr_t)plainbuf, datalen));
	VERIFY0(uio_addiov(*cuio, (user_addr_t)cipherbuf, datalen));

	*enc_len = datalen;

	return (0);

  out:
	zio_crypt_destroy_uio(*puio);
	zio_crypt_destroy_uio(*cuio);

	return ret;
}


static int
zio_crypt_init_uios(boolean_t encrypt, dmu_object_type_t ot, uint8_t *plainbuf,
	uint8_t *cipherbuf, uint_t datalen, uint8_t *mac, uint8_t *out_mac,
	uio_t **puio, uio_t **cuio, uint_t *enc_len)
{
	int ret;
	uint_t maclen;

	ASSERT(DMU_OT_IS_ENCRYPTED(ot));

	/* route to handler */
	switch (ot) {
	case DMU_OT_INTENT_LOG:
		ret = zio_crypt_init_uios_zil(encrypt, plainbuf, cipherbuf,
		    datalen, puio, cuio, enc_len);
		maclen = ZIL_MAC_LEN;
		break;
	case DMU_OT_DNODE:
		ret = zio_crypt_init_uios_dnode(encrypt, plainbuf, cipherbuf,
		    datalen, puio, cuio, enc_len);
		maclen = DATA_MAC_LEN;
		break;
	default:
		ret = zio_crypt_init_uios_normal(encrypt, plainbuf, cipherbuf,
		    datalen, puio, cuio, enc_len);
		maclen = DATA_MAC_LEN;
		break;
	}

	/* return the error or ZIO_NO_ENCRYPTION_NEEDED to the caller */
	if (ret)
		goto error;

	/* populate the uios */
#ifdef __APPLE__
	VERIFY0(uio_addiov(*cuio, (user_addr_t)mac, maclen));

	if (!encrypt) {
		VERIFY0(uio_addiov(*puio, (user_addr_t)out_mac, maclen));
	}

#else // !APPLE

	puio->uio_segflg = UIO_SYSSPACE;
	cuio->uio_segflg = UIO_SYSSPACE;

	mac_iov = ((iovec_t *)&cuio->uio_iov[cuio->uio_iovcnt - 1]);
	mac_iov->iov_base = mac;
	mac_iov->iov_len = maclen;

	if (!encrypt) {
		mac_out_iov = ((iovec_t *)&puio->uio_iov[puio->uio_iovcnt - 1]);
		mac_out_iov->iov_base = out_mac;
		mac_out_iov->iov_len = maclen;
	}
#endif // !APPLE

	return (0);

error:
	return (ret);
}

int
zio_do_crypt_data(boolean_t encrypt, zio_crypt_key_t *key, uint8_t *salt,
    dmu_object_type_t ot, uint8_t *iv, uint8_t *mac, uint_t datalen,
    uint8_t *plainbuf, uint8_t *cipherbuf)
{
	int ret;
	boolean_t locked = B_FALSE;
	uint64_t crypt = key->zk_crypt;
	uint_t enc_len, keydata_len = zio_crypt_table[crypt].ci_keylen;
	/* We have to delay the allocation call uio_create() until we know
	 * how many iovecs we want (as max).
	 */
	uio_t *puio = NULL, *cuio = NULL;
	uint8_t out_mac[DATA_MAC_LEN];
	uint8_t enc_keydata[MAX_MASTER_KEY_LEN];
	crypto_key_t tmp_ckey, *ckey = NULL;
	crypto_ctx_template_t tmpl;

	/* create uios for encryption */
	ret = zio_crypt_init_uios(encrypt, ot, plainbuf, cipherbuf, datalen,
		mac, out_mac, &puio, &cuio, &enc_len);

 	/* return the error or ZIO_NO_ENCRYPTION_NEEDED to the caller */
 	if (ret)
  		return (ret);

	/*
	 * If the needed key is the current one, just use it. Otherwise we
	 * need to generate a temporary one from the given salt + master key.
	 * If we are encrypting, we must return a copy of the current salt
	 * so that it can be stored in the blkptr_t.
	 */
	rw_enter(&key->zk_salt_lock, RW_READER);
	locked = B_TRUE;

	if (bcmp(salt, key->zk_salt, DATA_SALT_LEN) == 0) {
		ckey = &key->zk_current_key;
		tmpl = key->zk_current_tmpl;
	} else {
		rw_exit(&key->zk_salt_lock);
		locked = B_FALSE;

		ret = hkdf_sha256(key->zk_master_keydata, keydata_len, NULL, 0,
		    salt, DATA_SALT_LEN, enc_keydata, keydata_len);
		if (ret)
			goto error;

		tmp_ckey.ck_format = CRYPTO_KEY_RAW;
		tmp_ckey.ck_data = enc_keydata;
		tmp_ckey.ck_length = BYTES_TO_BITS(keydata_len);

		ckey = &tmp_ckey;
		tmpl = NULL;
	}

	/* perform the encryption / decryption */
	ret = zio_do_crypt_uio(encrypt, key->zk_crypt, ckey, tmpl, iv, enc_len,
	    puio, cuio);

	if (ret)
		goto error;

	if (locked) {
		rw_exit(&key->zk_salt_lock);
		locked = B_FALSE;
	}

	if (ckey == &tmp_ckey)
		bzero(enc_keydata, keydata_len);
	zio_crypt_destroy_uio(puio);
	zio_crypt_destroy_uio(cuio);

	return (0);

error:
	if (locked)
		rw_exit(&key->zk_salt_lock);
	if (ckey == &tmp_ckey)
		bzero(enc_keydata, keydata_len);

	zio_crypt_destroy_uio(puio);
	zio_crypt_destroy_uio(cuio);

	return (ret);
}
