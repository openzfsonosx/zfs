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

zio_crypt_info_t zio_crypt_table[ZIO_CRYPT_FUNCTIONS] = {
	{"",			ZC_TYPE_NONE,	0,  "inherit"},
	{SUN_CKM_AES_CCM,	ZC_TYPE_CCM,	32, "on"},
	{"",			ZC_TYPE_NONE,	0,  "off"},
	{SUN_CKM_AES_CCM,	ZC_TYPE_CCM,	16, "aes-128-ccm"},
	{SUN_CKM_AES_CCM,	ZC_TYPE_CCM,	24, "aes-192-ccm"},
	{SUN_CKM_AES_CCM,	ZC_TYPE_CCM,	32, "aes-256-ccm"},
	{SUN_CKM_AES_GCM,	ZC_TYPE_GCM,	16, "aes-128-gcm"},
	{SUN_CKM_AES_GCM,	ZC_TYPE_GCM,	24, "aes-192-gcm"},
	{SUN_CKM_AES_GCM,	ZC_TYPE_GCM,	32, "aes-256-gcm"}
};

void
l2arc_crypt_key_destroy(l2arc_crypt_key_t *key)
{
	if (key->l2ck_ctx_tmpl)
		crypto_destroy_ctx_template(key->l2ck_ctx_tmpl);
	if (key->l2ck_key.ck_data) {
		bzero(key->l2ck_key.ck_data,
		    BITS_TO_BYTES(key->l2ck_key.ck_length));
		kmem_free(key->l2ck_key.ck_data,
		    BITS_TO_BYTES(key->l2ck_key.ck_length));
	}
}

int
l2arc_crypt_key_init(l2arc_crypt_key_t *key)
{
	int ret;
	crypto_mechanism_t mech;
	uint64_t keydata_len, crypt = L2ARC_DEFAULT_CRYPT;

	key->l2ck_crypt = crypt;

	/* get the key length from the crypt table */
	keydata_len = zio_crypt_table[crypt].ci_keylen;

	/* allocate the key data's new buffer */
	key->l2ck_key.ck_data = kmem_alloc(keydata_len, KM_SLEEP);
	if (!key->l2ck_key.ck_data) {
		ret = ENOMEM;
		goto error;
	}

	/* set values for the key */
	key->l2ck_key.ck_format = CRYPTO_KEY_RAW;
	key->l2ck_key.ck_length = BYTES_TO_BITS(keydata_len);

	/*
	 * create the data. We can use pseudo random bytes here
	 * because this key will not persist through reboots
	 */
	ret = random_get_pseudo_bytes(key->l2ck_key.ck_data, keydata_len);
	if (ret)
		goto error;

	/* create the key's context template */
	mech.cm_type = crypto_mech2id(zio_crypt_table[crypt].ci_mechname);
	ret = crypto_create_ctx_template(&mech, &key->l2ck_key,
	    &key->l2ck_ctx_tmpl, KM_SLEEP);
	if (ret != CRYPTO_SUCCESS)
		key->l2ck_ctx_tmpl = NULL;

	return (0);

error:
	if (key->l2ck_key.ck_data)
		kmem_free(key->l2ck_key.ck_data, keydata_len);

	return (ret);
}

void
zio_crypt_key_destroy(zio_crypt_key_t *key)
{
	if (key->zk_ctx_tmpl)
		crypto_destroy_ctx_template(key->zk_ctx_tmpl);
	if (key->zk_ctx_tmpl)
		crypto_destroy_ctx_template(key->zk_dd_ctx_tmpl);
	if (key->zk_key.ck_data) {
		bzero(key->zk_key.ck_data,
			BITS_TO_BYTES(key->zk_key.ck_length));
		kmem_free(key->zk_key.ck_data,
			BITS_TO_BYTES(key->zk_key.ck_length));
	}
	if (key->zk_dd_key.ck_data) {
		bzero(key->zk_dd_key.ck_data,
			BITS_TO_BYTES(key->zk_dd_key.ck_length));
		kmem_free(key->zk_dd_key.ck_data,
			BITS_TO_BYTES(key->zk_dd_key.ck_length));
	}
}

int
zio_crypt_key_init(uint64_t crypt, uint8_t *keydata, uint8_t *dd_keydata,
    zio_crypt_key_t *key)
{
	int ret;
	crypto_mechanism_t mech;
	uint64_t keydata_len;

	ASSERT(crypt < ZIO_CRYPT_FUNCTIONS);

	key->zk_crypt = crypt;

	/* get the key length from the crypt table */
	keydata_len = zio_crypt_table[crypt].ci_keylen;

	/* allocate the key data's new buffer */
	key->zk_key.ck_data = kmem_alloc(keydata_len, KM_SLEEP);
	if (!key->zk_key.ck_data) {
		ret = ENOMEM;
		goto error;
	}

	/* allocate the dedup key data's new buffer */
	key->zk_dd_key.ck_data = kmem_alloc(HMAC_SHA256_KEYLEN, KM_SLEEP);
	if (!key->zk_dd_key.ck_data) {
		ret = ENOMEM;
		goto error;
	}

	/* set values for the key */
	key->zk_key.ck_format = CRYPTO_KEY_RAW;
	key->zk_key.ck_length = BYTES_TO_BITS(keydata_len);

	/* copy the data */
	bcopy(keydata, key->zk_key.ck_data, keydata_len);

	/* create the key's context template */
	mech.cm_type = crypto_mech2id(zio_crypt_table[crypt].ci_mechname);
	ret = crypto_create_ctx_template(&mech, &key->zk_key,
	    &key->zk_ctx_tmpl, KM_SLEEP);
	if (ret != CRYPTO_SUCCESS)
		key->zk_ctx_tmpl = NULL;

	/* set values for the dedup key */
	key->zk_dd_key.ck_format = CRYPTO_KEY_RAW;
	key->zk_dd_key.ck_length = BYTES_TO_BITS(HMAC_SHA256_KEYLEN);

	/* copy the data */
	bcopy(dd_keydata, key->zk_dd_key.ck_data, HMAC_SHA256_KEYLEN);

	/* create the dedup key's context template */
	mech.cm_type = crypto_mech2id(SUN_CKM_SHA256_HMAC);
	ret = crypto_create_ctx_template(&mech, &key->zk_dd_key,
	    &key->zk_dd_ctx_tmpl, KM_SLEEP);
	if (ret != CRYPTO_SUCCESS)
		key->zk_dd_ctx_tmpl = NULL;

	return (0);

error:
	if (key->zk_key.ck_data)
		kmem_free(key->zk_key.ck_data, keydata_len);
	if (key->zk_dd_key.ck_data)
		kmem_free(key->zk_dd_key.ck_data, keydata_len);

	return (ret);
}

static int
zio_do_crypt_raw(boolean_t encrypt, uint64_t crypt, crypto_key_t *key,
	crypto_ctx_template_t tmpl, uint8_t *ivbuf, uint8_t *plainbuf,
	uint8_t *cipherbuf, uint_t datalen)
{
	int ret;
	crypto_data_t plaindata, cipherdata;
	CK_AES_CCM_PARAMS ccmp;
	CK_AES_GCM_PARAMS gcmp;
	crypto_mechanism_t mech;
	zio_crypt_info_t crypt_info;
	uint_t plain_full_len;

	ASSERT(crypt < ZIO_CRYPT_FUNCTIONS);
	ASSERT(key->ck_format == CRYPTO_KEY_RAW);

	/* lookup the encryption info */
	crypt_info = zio_crypt_table[crypt];

	/* setup encryption mechanism (same as crypt) */
	mech.cm_type = crypto_mech2id(crypt_info.ci_mechname);

	/* plain length will include the MAC if we are decrypting */
	if (encrypt)
		plain_full_len = datalen;
	else
		plain_full_len = datalen + WRAPPING_MAC_LEN;

	/*
	 * setup encryption params (currently only AES
	 * CCM and AES GCM are supported)
	 */
	if (crypt_info.ci_crypt_type == ZC_TYPE_CCM) {
		ccmp.ulNonceSize = WRAPPING_IV_LEN;
		ccmp.ulAuthDataSize = 0;
		ccmp.authData = NULL;
		ccmp.ulMACSize = WRAPPING_MAC_LEN;
		ccmp.nonce = ivbuf;
		ccmp.ulDataSize = plain_full_len;

		mech.cm_param = (char *)(&ccmp);
		mech.cm_param_len = sizeof (CK_AES_CCM_PARAMS);
	} else {
		gcmp.ulIvLen = WRAPPING_IV_LEN;
		gcmp.ulIvBits = BYTES_TO_BITS(WRAPPING_IV_LEN);
		gcmp.ulAADLen = 0;
		gcmp.pAAD = NULL;
		gcmp.ulTagBits = BYTES_TO_BITS(WRAPPING_MAC_LEN);
		gcmp.pIv = ivbuf;

		mech.cm_param = (char *)(&gcmp);
		mech.cm_param_len = sizeof (CK_AES_GCM_PARAMS);
	}

	/* setup plaindata struct with buffer from plainbuf */
	plaindata.cd_format = CRYPTO_DATA_RAW;
	plaindata.cd_offset = 0;
	plaindata.cd_length = plain_full_len;
	plaindata.cd_miscdata = NULL;
	plaindata.cd_raw.iov_base = (char *)plainbuf;
	plaindata.cd_raw.iov_len = plain_full_len;

	/* setup cipherdata to be filled */
	cipherdata.cd_format = CRYPTO_DATA_RAW;
	cipherdata.cd_offset = 0;
	cipherdata.cd_length = datalen + WRAPPING_MAC_LEN;
	cipherdata.cd_miscdata = NULL;
	cipherdata.cd_raw.iov_base = (char *)cipherbuf;
	cipherdata.cd_raw.iov_len = datalen + WRAPPING_MAC_LEN;

	/* perform the actual encryption */
	if (encrypt) {
		ret = crypto_encrypt(&mech, &plaindata, key, tmpl, &cipherdata,
			NULL);
	} else {
		ret = crypto_decrypt(&mech, &cipherdata, key, tmpl, &plaindata,
			NULL);
	}

	if (ret != CRYPTO_SUCCESS) {
		ret = EIO;
		goto error;
	}

	return (0);

error:
	return (ret);
}
#define	zio_encrypt_raw(crypt, key, tmpl, iv, pd, cd, datalen) \
	zio_do_crypt_raw(B_TRUE, crypt, key, tmpl, iv, pd, cd, datalen)
#define	zio_decrypt_raw(crypt, key, tmpl, iv, pd, cd, datalen) \
	zio_do_crypt_raw(B_FALSE, crypt, key, tmpl, iv, pd, cd, datalen)

int
zio_crypt_key_wrap(crypto_key_t *cwkey, uint64_t crypt, uint8_t *keydata,
    uint8_t *dd_keydata, dsl_crypto_key_phys_t *dckp)
{
	int ret;

	ASSERT(crypt < ZIO_CRYPT_FUNCTIONS);
	ASSERT(cwkey->ck_format == CRYPTO_KEY_RAW);

	bzero(dckp, sizeof (dsl_crypto_key_phys_t));

	/* set the crypt */
	dckp->dk_crypt_alg = (uint8_t)crypt;

	/* generate ivs */
	ret = random_get_pseudo_bytes(dckp->dk_iv, WRAPPING_IV_LEN);
	if (ret)
		goto error;

	ret = random_get_pseudo_bytes(dckp->dk_dd_iv, WRAPPING_IV_LEN);
	if (ret)
		goto error;

	/* encrypt the keys and store the results in the dckp */
	ret = zio_encrypt_raw(crypt, cwkey, NULL, dckp->dk_iv,
	    keydata, dckp->dk_keybuf, zio_crypt_table[crypt].ci_keylen);
	if (ret)
		goto error;

	ret = zio_encrypt_raw(crypt, cwkey, NULL, dckp->dk_dd_iv,
	    dd_keydata, dckp->dk_dd_keybuf, HMAC_SHA256_KEYLEN);
	if (ret)
		goto error;

	return (0);

error:
	return (ret);
}

int
zio_crypt_key_unwrap(crypto_key_t *cwkey, dsl_crypto_key_phys_t *dckp,
	uint8_t *keydata, uint8_t *dd_keydata)
{
	int ret;
	uint64_t crypt = dckp->dk_crypt_alg;

	ASSERT(dckp->dk_crypt_alg < ZIO_CRYPT_FUNCTIONS);
	ASSERT(cwkey->ck_format == CRYPTO_KEY_RAW);

	/* decrypt the keys and store the result in the output buffers */
	ret = zio_decrypt_raw(crypt, cwkey, NULL,
	    dckp->dk_iv, keydata, dckp->dk_keybuf,
	    zio_crypt_table[dckp->dk_crypt_alg].ci_keylen);
	if (ret)
		goto error;

	ret = zio_decrypt_raw(crypt, cwkey, NULL,
	    dckp->dk_dd_iv, dd_keydata, dckp->dk_dd_keybuf, HMAC_SHA256_KEYLEN);
	if (ret)
		goto error;

	return (0);
error:
	return (ret);
}

int
zio_crypt_generate_iv(zbookmark_phys_t *bookmark, uint64_t txgid,
	uint_t ivlen, uint8_t *ivbuf)
{
	int ret;
	crypto_mechanism_t mech;
	crypto_context_t ctx;
	crypto_data_t in_data, digest_data;
	uint8_t digestbuf[SHA_256_DIGEST_LEN];

	/* initialize sha 256 mechanism and crypto data */
	mech.cm_type = crypto_mech2id(SUN_CKM_SHA256);
	mech.cm_param = NULL;
	mech.cm_param_len = 0;

	in_data.cd_format = CRYPTO_DATA_RAW;
	in_data.cd_offset = 0;

	digest_data.cd_format = CRYPTO_DATA_RAW;
	digest_data.cd_offset = 0;
	digest_data.cd_length = SHA_256_DIGEST_LEN;
	digest_data.cd_raw.iov_base = (char *)digestbuf;
	digest_data.cd_raw.iov_len = SHA_256_DIGEST_LEN;

	/* initialize the context */
	ret = crypto_digest_init(&mech, &ctx, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* add in the bookmark */
	in_data.cd_length = sizeof (zbookmark_phys_t);
	in_data.cd_raw.iov_base = (char *)bookmark;
	in_data.cd_raw.iov_len = sizeof (zbookmark_phys_t);

	ret = crypto_digest_update(ctx, &in_data, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* add in the txgid */
	in_data.cd_length = sizeof (uint64_t);
	in_data.cd_raw.iov_base = (char *)&txgid;
	in_data.cd_raw.iov_len = sizeof (uint64_t);

	ret = crypto_digest_update(ctx, &in_data, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* finish the hash */
	ret = crypto_digest_final(ctx, &digest_data, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* truncate and copy the digest into the output buffer */
	bcopy(digestbuf, ivbuf, ivlen);

	return (0);

error:
	return (ret);
}

int
zio_crypt_generate_iv_dd(zio_crypt_key_t *key, uint8_t *plainbuf,
    uint_t datalen, uint_t ivlen, uint8_t *ivbuf)
{
	int ret;
	crypto_mechanism_t mech;
	crypto_data_t pb_data, digest_data;
	uint8_t digestbuf[SHA_256_DIGEST_LEN];

	/* initialize sha 256 hmac mechanism */
	mech.cm_type = crypto_mech2id(SUN_CKM_SHA256_HMAC);
	mech.cm_param = NULL;
	mech.cm_param_len = 0;

	/* initialize crypto data for the plain buffer */
	pb_data.cd_format = CRYPTO_DATA_RAW;
	pb_data.cd_offset = 0;
	pb_data.cd_length = datalen;
	pb_data.cd_raw.iov_base = (char *)plainbuf;
	pb_data.cd_raw.iov_len = datalen;

	/* initialize crypto data for the output digest */
	digest_data.cd_format = CRYPTO_DATA_RAW;
	digest_data.cd_offset = 0;
	digest_data.cd_length = SHA_256_DIGEST_LEN;
	digest_data.cd_raw.iov_base = (char *)digestbuf;
	digest_data.cd_raw.iov_len = SHA_256_DIGEST_LEN;

	/* generate the digest */
	ret = crypto_mac(&mech, &pb_data, &key->zk_dd_key, key->zk_dd_ctx_tmpl,
	    &digest_data, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* truncate and copy the digest into the output buffer */
	bcopy(digestbuf, ivbuf, ivlen);

	return (0);

error:
	return (ret);
}

int
zio_crypt_generate_iv_l2arc(uint64_t spa, dva_t *dva, uint64_t birth,
    uint64_t daddr, uint8_t *ivbuf)
{
	int ret;
	crypto_mechanism_t mech;
	crypto_context_t ctx;
	crypto_data_t in_data, digest_data;
	uint8_t digestbuf[SHA_256_DIGEST_LEN];

	/* initialize sha 256 mechanism and crypto data */
	mech.cm_type = crypto_mech2id(SUN_CKM_SHA256);
	mech.cm_param = NULL;
	mech.cm_param_len = 0;

	in_data.cd_format = CRYPTO_DATA_RAW;
	in_data.cd_offset = 0;

	digest_data.cd_format = CRYPTO_DATA_RAW;
	digest_data.cd_offset = 0;
	digest_data.cd_length = SHA_256_DIGEST_LEN;
	digest_data.cd_raw.iov_base = (char *)digestbuf;
	digest_data.cd_raw.iov_len = SHA_256_DIGEST_LEN;

	/* initialize the context */
	ret = crypto_digest_init(&mech, &ctx, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* add in the spa */
	in_data.cd_length = sizeof (uint64_t);
	in_data.cd_raw.iov_base = (char *)&spa;
	in_data.cd_raw.iov_len = sizeof (uint64_t);

	ret = crypto_digest_update(ctx, &in_data, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* add in the dva */
	in_data.cd_length = sizeof (dva_t);
	in_data.cd_raw.iov_base = (char *)dva;
	in_data.cd_raw.iov_len = sizeof (dva_t);

	ret = crypto_digest_update(ctx, &in_data, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* add in the birth */
	in_data.cd_length = sizeof (uint64_t);
	in_data.cd_raw.iov_base = (char *)&birth;
	in_data.cd_raw.iov_len = sizeof (uint64_t);

	ret = crypto_digest_update(ctx, &in_data, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* add in the daddr */
	in_data.cd_length = sizeof (uint64_t);
	in_data.cd_raw.iov_base = (char *)&daddr;
	in_data.cd_raw.iov_len = sizeof (uint64_t);

	ret = crypto_digest_update(ctx, &in_data, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* finish the hash */
	ret = crypto_digest_final(ctx, &digest_data, NULL);
	if (ret != CRYPTO_SUCCESS) {
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* truncate and copy the digest into the output buffer */
	bcopy(digestbuf, ivbuf, L2ARC_IV_LEN);

	return (0);

error:
	return (ret);
}

int
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
	user_size_t maclen = 0;

	ASSERT(crypt < ZIO_CRYPT_FUNCTIONS);
	ASSERT(key->ck_format == CRYPTO_KEY_RAW);

	/* lookup the encryption info */
	crypt_info = zio_crypt_table[crypt];

	/* the mac will always be the last iovec_t in the cipher uio */
#ifdef __APPLE__
	uio_getiov(cuio, uio_iovcnt(cuio) - 1, NULL, &maclen);
#else
	maclen = cuio->uio_iov[cuio->uio_iovcnt - 1].iov_len;
#endif
	ASSERT(maclen <= MAX_DATA_MAC_LEN);

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
		ccmp.ulNonceSize = MAX_DATA_IV_LEN;
		ccmp.ulAuthDataSize = 0;
		ccmp.authData = NULL;
		ccmp.ulMACSize = maclen;
		ccmp.nonce = ivbuf;
		ccmp.ulDataSize = plain_full_len;

		mech.cm_param = (char *)(&ccmp);
		mech.cm_param_len = sizeof (CK_AES_CCM_PARAMS);
	} else {
		gcmp.ulIvLen = MAX_DATA_IV_LEN;
		gcmp.ulIvBits = BYTES_TO_BITS(MAX_DATA_IV_LEN);
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
		ret = SET_ERROR(EIO);
		goto error;
	}

	return (0);

error:
	return (ret);
}

static void zio_crypt_destroy_uio(uio_t *uio)
{
#ifdef __APPLE__
#ifdef _KERNEL
	if (uio) uio_free(uio);
#endif
#else
	if (uio->uio_iov)
		kmem_free(uio->uio_iov, uio->uio_iovcnt * sizeof (iovec_t));
#endif
}



#ifdef __APPLE__

/*
 * We do not check for older zil chain because this feature was not
 * available before the newer zil chain was introduced. The goal here
 * is to encrypt everything except the blkptr_t of a lr_write_t and
 * the zil_chain_t header
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
zio_crypt_init_uios_normal(boolean_t encrypt, uint8_t *plainbuf,
	uint8_t *cipherbuf, uint_t datalen, uio_t **puio, uio_t **cuio,
	uint_t *enc_len)
{
	int error = 0;

	if (encrypt) {
		*puio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
		*cuio = uio_create(2, 0, UIO_SYSSPACE, UIO_WRITE);
	} else {
		*puio = uio_create(2, 0, UIO_SYSSPACE, UIO_WRITE);
		*cuio = uio_create(2, 0, UIO_SYSSPACE, UIO_READ);
	}
	if (!*puio || !*cuio) {
		error = SET_ERROR(ENOMEM);
		goto out;
	}

	uio_addiov(*puio, (user_addr_t)plainbuf, datalen);
	uio_addiov(*cuio, (user_addr_t)cipherbuf, datalen);

	*enc_len = datalen;

	return (0);

  out:
	zio_crypt_destroy_uio(*puio);
	zio_crypt_destroy_uio(*cuio);
	return error;
}


#else // !__APPLE__

/*
 * We do not check for older zil chain because this feature was not
 * available before the newer zil chain was introduced. The goal here
 * is to encrypt everything except the blkptr_t of a lr_write_t and
 * the zil_chain_t header
 */
static int
zio_crypt_init_uios_zil(boolean_t encrypt, uint8_t *plainbuf,
	uint8_t *cipherbuf, uint_t datalen, uio_t *puio, uio_t *cuio,
	uint_t *enc_len)
{
	int ret;
	uint_t nr_src, nr_dst, lr_len, crypt_len, nr_iovecs = 0, total_len = 0;
	iovec_t *src_iovecs = NULL, *dst_iovecs = NULL;
	uint8_t *src, *dst, *slrp, *dlrp, *end;
	zil_chain_t *zilc;
	lr_t *lr;

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
		puio->uio_iov = NULL;
		puio->uio_iovcnt = 0;
		cuio->uio_iov = NULL;
		cuio->uio_iovcnt = 0;
		return (ZIO_NO_ENCRYPTION_NEEDED);
	}

	nr_src += nr_iovecs;
	nr_dst += nr_iovecs;

	/* allocate the iovec arrays */
	src_iovecs = kmem_alloc(nr_src * sizeof (iovec_t), KM_SLEEP);
	if (!src_iovecs) {
		ret = SET_ERROR(ENOMEM);
		goto error;
	}

	dst_iovecs = kmem_alloc(nr_dst * sizeof (iovec_t), KM_SLEEP);
	if (!dst_iovecs) {
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

			src_iovecs[nr_iovecs].iov_base = slrp + sizeof (lr_t);
			src_iovecs[nr_iovecs].iov_len = crypt_len;
			dst_iovecs[nr_iovecs].iov_base = dlrp + sizeof (lr_t);
			dst_iovecs[nr_iovecs].iov_len = crypt_len;

			/* copy the bp now since it will not be encrypted */
			bcopy(slrp + sizeof (lr_write_t) - sizeof (blkptr_t),
			    dlrp + sizeof (lr_write_t) - sizeof (blkptr_t),
			    sizeof (blkptr_t));
			nr_iovecs++;
			total_len += crypt_len;

			if (lr_len != sizeof (lr_write_t)) {
				crypt_len = lr_len - sizeof (lr_write_t);
				src_iovecs[nr_iovecs].iov_base =
				    slrp + sizeof (lr_write_t);
				src_iovecs[nr_iovecs].iov_len = crypt_len;
				dst_iovecs[nr_iovecs].iov_base =
				    dlrp + sizeof (lr_write_t);
				dst_iovecs[nr_iovecs].iov_len = crypt_len;
				nr_iovecs++;
				total_len += crypt_len;
			}
		} else {
			bcopy(slrp, dlrp, sizeof (lr_t));
			crypt_len = lr_len - sizeof (lr_t);
			src_iovecs[nr_iovecs].iov_base = slrp + sizeof (lr_t);
			src_iovecs[nr_iovecs].iov_len = crypt_len;
			dst_iovecs[nr_iovecs].iov_base = dlrp + sizeof (lr_t);
			dst_iovecs[nr_iovecs].iov_len = crypt_len;
			nr_iovecs++;
			total_len += crypt_len;
		}
	}

	/* copy the plain zil header over */
	bcopy(src, dst, sizeof (zil_chain_t));

	*enc_len = total_len;

	if (encrypt) {
		puio->uio_iov = src_iovecs;
		puio->uio_iovcnt = nr_src;
		cuio->uio_iov = dst_iovecs;
		cuio->uio_iovcnt = nr_dst;
	} else {
		puio->uio_iov = dst_iovecs;
		puio->uio_iovcnt = nr_dst;
		cuio->uio_iov = src_iovecs;
		cuio->uio_iovcnt = nr_src;
	}

	return (0);

error:
	if (src_iovecs)
		kmem_free(src_iovecs, nr_src * sizeof (iovec_t));
	if (dst_iovecs)
		kmem_free(dst_iovecs, nr_dst * sizeof (iovec_t));

	*enc_len = 0;
	puio->uio_iov = NULL;
	puio->uio_iovcnt = 0;
	cuio->uio_iov = NULL;
	cuio->uio_iovcnt = 0;
	return (ret);
}

static int
zio_crypt_init_uios_normal(boolean_t encrypt, uint8_t *plainbuf,
	uint8_t *cipherbuf, uint_t datalen, uio_t *puio, uio_t *cuio,
	uint_t *enc_len)
{
	int ret;
	uint_t nr_plain, nr_cipher;
	iovec_t *plain_iovecs = NULL, *cipher_iovecs = NULL;

	/* allocate the iovecs for the plain and cipher data */
	if (encrypt) {
		nr_plain = 1;
		plain_iovecs = kmem_alloc(nr_plain * sizeof (iovec_t),
			KM_SLEEP);
		if (!plain_iovecs) {
			ret = SET_ERROR(ENOMEM);
			goto error;
		}

		nr_cipher = 2;
		cipher_iovecs = kmem_alloc(nr_cipher * sizeof (iovec_t),
			KM_SLEEP);
		if (!cipher_iovecs) {
			ret = SET_ERROR(ENOMEM);
			goto error;
		}
	} else {
		nr_plain = 2;
		plain_iovecs = kmem_alloc(nr_plain * sizeof (iovec_t),
			KM_SLEEP);
		if (!plain_iovecs) {
			ret = SET_ERROR(ENOMEM);
			goto error;
		}

		nr_cipher = 2;
		cipher_iovecs = kmem_alloc(nr_cipher * sizeof (iovec_t),
			KM_SLEEP);
		if (!cipher_iovecs) {
			ret = SET_ERROR(ENOMEM);
			goto error;
		}
	}

	plain_iovecs[0].iov_base = plainbuf;
	plain_iovecs[0].iov_len = datalen;
	cipher_iovecs[0].iov_base = cipherbuf;
	cipher_iovecs[0].iov_len = datalen;

	*enc_len = datalen;
	puio->uio_iov = plain_iovecs;
	puio->uio_iovcnt = nr_plain;
	cuio->uio_iov = cipher_iovecs;
	cuio->uio_iovcnt = nr_cipher;

	return (0);

error:
	if (plain_iovecs)
		kmem_free(plain_iovecs, nr_plain * sizeof (iovec_t));
	if (cipher_iovecs)
		kmem_free(cipher_iovecs, nr_cipher * sizeof (iovec_t));

	*enc_len = 0;
	puio->uio_iov = NULL;
	puio->uio_iovcnt = 0;
	cuio->uio_iov = NULL;
	cuio->uio_iovcnt = 0;
	return (ret);
}

#endif // !__APPLE__



static int
zio_crypt_init_uios(boolean_t encrypt, dmu_object_type_t ot, uint8_t *plainbuf,
	uint8_t *cipherbuf, uint_t datalen, uint8_t *mac, uint8_t *out_mac,
	uio_t **puio, uio_t **cuio, uint_t *enc_len)
{
	int ret;
	uint_t maclen;

	ASSERT(DMU_OT_IS_ENCRYPTED(ot));

	/* route to handler */
	if (ot == DMU_OT_INTENT_LOG) {
		ret = zio_crypt_init_uios_zil(encrypt, plainbuf, cipherbuf,
			datalen, puio, cuio, enc_len);
		maclen = ZIL_MAC_LEN;
	} else {
		ret = zio_crypt_init_uios_normal(encrypt, plainbuf, cipherbuf,
			datalen, puio, cuio, enc_len);
		maclen = MAX_DATA_MAC_LEN;
	}

	if (ret == ZIO_NO_ENCRYPTION_NEEDED) {
		bzero(mac, maclen);
		return (ret);
	} else if (ret) {
		goto error;
	}

	/* populate the uios */
#ifdef __APPLE__
	uio_addiov(*cuio, (user_addr_t)mac, maclen);

	if (!encrypt) {
		uio_addiov(*puio, (user_addr_t)out_mac, maclen);
	}

#else // !APPLE

#ifdef _KERNEL
	puio->uio_segflg = UIO_SYSSPACE;
	cuio->uio_segflg = UIO_SYSSPACE;
#else
	puio->uio_segflg = UIO_USERSPACE;
	cuio->uio_segflg = UIO_USERSPACE;
#endif

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
zio_do_crypt_data(boolean_t encrypt, zio_crypt_key_t *key,
    dmu_object_type_t ot, uint8_t *iv, uint8_t *mac, uint_t datalen,
    uint8_t *plainbuf, uint8_t *cipherbuf)
{
	int ret;
	uint_t enc_len;
#ifdef __APPLE__
	/* We have to delay the allocaiton call uio_create() until we know
	 * how many iovecs we want (as max).
	 */
	uio_t *puio = NULL, *cuio = NULL;
#else
	uio_t puio, cuio;
#endif
	uint8_t out_mac[MAX_DATA_MAC_LEN];

#ifdef LINUX
	bzero(&puio, sizeof (uio_t));
	bzero(&cuio, sizeof (uio_t));
#endif

	/* create uios for encryption */
	ret = zio_crypt_init_uios(encrypt, ot, plainbuf, cipherbuf, datalen,
		mac, out_mac, &puio, &cuio, &enc_len);

	/* if no encryption is required, just copy the plain data */
	if (ret == ZIO_NO_ENCRYPTION_NEEDED) {
		if (encrypt) {
			bcopy(plainbuf, cipherbuf, datalen);
		} else {
			bcopy(cipherbuf, plainbuf, datalen);
		}
		return (0);
	} else if (ret) {
		return (ret);
	}

	/* perform the encryption */
	ret = zio_do_crypt_uio(encrypt, key->zk_crypt, &key->zk_key,
		key->zk_ctx_tmpl, iv, enc_len, puio, cuio);
	if (ret)
		goto error;

	zio_crypt_destroy_uio(puio);
	zio_crypt_destroy_uio(cuio);

	return (0);

error:
	zio_crypt_destroy_uio(puio);
	zio_crypt_destroy_uio(cuio);

	return (ret);
}
