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
#include <sys/fs/zfs.h>
#include <sys/zio.h>

#define	SHA_256_DIGEST_LEN 32

void
print_iovec(const iovec_t *iov)
{
#if defined(_KERNEL) && defined(ENCRYPT_DEBUG)
	int i;
	uint8_t *buf = ((uint8_t *)iov->iov_base);
	uint8_t c;

	printk(KERN_DEBUG "\t\tiov_base = %p, iov_len = %lu\n",
		iov->iov_base, (unsigned long)iov->iov_len);

	for (i = 0; i < 32 && i < iov->iov_len; i++) {
		if ((buf[i] >= 'a' && buf[i] <= 'z') ||
			(buf[i] >= 'A' && buf[i] <= 'Z') ||
			(buf[i] >= '0' && buf[i] <= '9'))
			c = buf[i];
		else
			c = '.';

		printk(KERN_DEBUG "\t\t\t%d:\t%02x\t%c\n", i, buf[i], c);
	}

#endif
}

void
print_crypto_data(char *name, crypto_data_t *cd)
{
#if defined(_KERNEL) && defined(ENCRYPT_DEBUG)
	int i;

	printk(KERN_DEBUG "PRINT CRYPTO_DATA: %s\n", name);

	switch (cd->cd_format) {
	case CRYPTO_DATA_RAW:
		printk(KERN_DEBUG "\tRAW CD\n");
		print_iovec(&cd->cd_raw);

		break;
	case CRYPTO_DATA_UIO:
		printk(KERN_DEBUG "\tUIO CD (%u iovecs)\n",
			(unsigned)cd->cd_uio->uio_iovcnt);

		for (i = 0; i < cd->cd_uio->uio_iovcnt; i++) {
			print_iovec(&cd->cd_uio->uio_iov[i]);
		}

		break;
	default:
		printk(KERN_DEBUG "\tUNRECOGNIZED CD\n");
		break;
	}

	printk("\n");
#endif
}

void
zio_crypt_key_destroy(zio_crypt_key_t *key)
{
	if (key->zk_ctx_tmpl)
		crypto_destroy_ctx_template(key->zk_ctx_tmpl);
	if (key->zk_key.ck_data) {
		bzero(key->zk_key.ck_data,
			BITS_TO_BYTES(key->zk_key.ck_length));
		kmem_free(key->zk_key.ck_data,
			BITS_TO_BYTES(key->zk_key.ck_length));
	}
}

int
zio_crypt_key_init(uint64_t crypt, uint8_t *keydata, zio_crypt_key_t *key)
{
	int ret;
	crypto_mechanism_t mech;
	uint64_t keydata_len;

	ASSERT(crypt < ZIO_CRYPT_FUNCTIONS);

	/* get the key length from the crypt table */
	keydata_len = zio_crypt_table[crypt].ci_keylen;

	/* allocate the key data's new buffer */
	key->zk_key.ck_data = kmem_alloc(keydata_len, KM_SLEEP);
	if (!key->zk_key.ck_data) {
		ret = ENOMEM;
		goto error;
	}

	/* set values for the key */
	key->zk_crypt = crypt;
	key->zk_key.ck_format = CRYPTO_KEY_RAW;
	key->zk_key.ck_length = BYTES_TO_BITS(keydata_len);

	/* copy the data */
	bcopy(keydata, key->zk_key.ck_data, keydata_len);

	/* create the key's context template */
	mech.cm_type = crypto_mech2id(zio_crypt_table[crypt].ci_mechname);
	ret = crypto_create_ctx_template(&mech, &key->zk_key, &key->zk_ctx_tmpl,
		KM_SLEEP);
	if (ret != CRYPTO_SUCCESS) {
		LOG_DEBUG("Failed to create context, consider CCM encryption");
		key->zk_ctx_tmpl = NULL;
	}

	return (0);

error:
	LOG_ERROR(ret, "");
	if (key->zk_key.ck_data)
		kmem_free(key->zk_key.ck_data, keydata_len);

	return (ret);
}

static int
zio_do_crypt_raw(boolean_t encrypt, uint64_t crypt, crypto_key_t *key,
	crypto_ctx_template_t tmpl, uint8_t *ivbuf,	uint8_t *plainbuf,
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
	if (encrypt)
		ret = crypto_encrypt(&mech, &plaindata, key, tmpl, &cipherdata,
			NULL);
	else
		ret = crypto_decrypt(&mech, &cipherdata, key, tmpl, &plaindata,
			NULL);

	print_crypto_data("plaindata", &plaindata);
	print_crypto_data("cipherdata", &cipherdata);

	if (ret != CRYPTO_SUCCESS) {
		LOG_ERROR(ret, "");
		ret = EIO;
		goto error;
	}

	return (0);

error:
	LOG_ERROR(ret, "");
	return (ret);
}
#define	zio_encrypt_raw(crypt, key, tmpl, iv, pd, cd, datalen) \
	zio_do_crypt_raw(B_TRUE, crypt, key, tmpl, iv, pd, cd, datalen)
#define	zio_decrypt_raw(crypt, key, tmpl, iv, pd, cd, datalen) \
	zio_do_crypt_raw(B_FALSE, crypt, key, tmpl, iv, pd, cd, datalen)

int
zio_crypt_key_wrap(crypto_key_t *cwkey, uint64_t crypt,
	uint8_t *keydata, dsl_crypto_key_phys_t *dckp)
{
	int ret;

	ASSERT(crypt < ZIO_CRYPT_FUNCTIONS);
	ASSERT(cwkey->ck_format == CRYPTO_KEY_RAW);

	/* copy the crypt and iv into the dsl_crypto_key_phys_t */
	dckp->dk_crypt_alg = crypt;
	bzero(dckp->dk_padding, sizeof (dckp->dk_padding));
	bzero(dckp->dk_keybuf, sizeof (dckp->dk_keybuf));

	/* generate an iv */
	ret = random_get_bytes(dckp->dk_iv, WRAPPING_IV_LEN);
	if (ret)
		goto error;

	/* encrypt the key and store the result in dckp->keybuf */
	ret = zio_encrypt_raw(crypt, cwkey, NULL, dckp->dk_iv,
		keydata, dckp->dk_keybuf, zio_crypt_table[crypt].ci_keylen);
	if (ret)
		goto error;

	return (0);
error:
	LOG_ERROR(ret, "");
	return (ret);
}

int
zio_crypt_key_unwrap(crypto_key_t *cwkey, dsl_crypto_key_phys_t *dckp,
	uint8_t *keydata)
{
	int ret;

	ASSERT(dckp->dk_crypt_alg < ZIO_CRYPT_FUNCTIONS);
	ASSERT(cwkey->ck_format == CRYPTO_KEY_RAW);

	/* encrypt the key and store the result in dckp->keybuf */
	ret = zio_decrypt_raw(dckp->dk_crypt_alg, cwkey, NULL,
		dckp->dk_iv, keydata, dckp->dk_keybuf,
		zio_crypt_table[dckp->dk_crypt_alg].ci_keylen);
	if (ret)
		goto error;

	return (0);
error:
	LOG_ERROR(ret, "");
	return (ret);
}

int
zio_crypt_generate_iv(zbookmark_phys_t *bookmark, uint64_t txgid,
	uint_t ivlen, uint8_t *ivbuf)
{
	int ret;
	crypto_mechanism_t mech;
	crypto_context_t ctx;
	crypto_data_t bm_data, txg_data, digest_data;
	uint8_t digestbuf[SHA_256_DIGEST_LEN];

	/* initialize sha 256 mechanism */
	mech.cm_type = crypto_mech2id(SUN_CKM_SHA256);
	mech.cm_param = NULL;
	mech.cm_param_len = 0;

	/* initialize crypto data for the bookmark */
	bm_data.cd_format = CRYPTO_DATA_RAW;
	bm_data.cd_offset = 0;
	bm_data.cd_length = sizeof (zbookmark_phys_t);
	bm_data.cd_raw.iov_base = (char *)bookmark;
	bm_data.cd_raw.iov_len = sizeof (zbookmark_phys_t);

	/* initialize crypto data for the txgid */
	txg_data.cd_format = CRYPTO_DATA_RAW;
	txg_data.cd_offset = 0;
	txg_data.cd_length = sizeof (uint64_t);
	txg_data.cd_raw.iov_base = (char *)&txgid;
	txg_data.cd_raw.iov_len = sizeof (uint64_t);

	/* initialize crypto data for the output digest */
	digest_data.cd_format = CRYPTO_DATA_RAW;
	digest_data.cd_offset = 0;
	digest_data.cd_length = SHA_256_DIGEST_LEN;
	digest_data.cd_raw.iov_base = (char *)digestbuf;
	digest_data.cd_raw.iov_len = SHA_256_DIGEST_LEN;

	/* perform the sha256 digest */
	ret = crypto_digest_init(&mech, &ctx, NULL);
	if (ret != CRYPTO_SUCCESS) {
		LOG_ERROR(ret, "crypto_digest_init() failed");
		ret = SET_ERROR(EIO);
		goto error;
	}

	ret = crypto_digest_update(ctx, &bm_data, NULL);
	if (ret != CRYPTO_SUCCESS) {
		LOG_ERROR(ret, "crypto_digest_update() failed for bookmark");
		ret = SET_ERROR(EIO);
		goto error;
	}

	ret = crypto_digest_update(ctx, &txg_data, NULL);
	if (ret != CRYPTO_SUCCESS) {
		LOG_ERROR(ret, "crypto_digest_update() failed for txgid");
		ret = SET_ERROR(EIO);
		goto error;
	}

	ret = crypto_digest_final(ctx, &digest_data, NULL);
	if (ret != CRYPTO_SUCCESS) {
		LOG_ERROR(ret, "crypto_digest_update() failed for txgid");
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* truncate and copy the digest into the output buffer */
	bcopy(digestbuf, ivbuf, ivlen);

	return (0);

error:
	LOG_ERROR(ret, "");
	return (ret);
}

int
zio_crypt_generate_iv_dd(uint8_t *plainbuf, uint_t datalen, uint_t ivlen,
	uint8_t *ivbuf)
{
	int ret;
	crypto_mechanism_t mech;
	crypto_data_t pb_data, digest_data;
	uint8_t digestbuf[SHA_256_DIGEST_LEN];

	/* initialize sha 256 mechanism */
	mech.cm_type = crypto_mech2id(SUN_CKM_SHA256);
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
	digest_data.cd_raw.iov_base = (char *)ivbuf;
	digest_data.cd_raw.iov_len = SHA_256_DIGEST_LEN;

	/* generate the digest */
	ret = crypto_digest(&mech, &pb_data, &digest_data, NULL);
	if (ret != CRYPTO_SUCCESS) {
		LOG_ERROR(ret, "crypto_digest() failed");
		ret = SET_ERROR(EIO);
		goto error;
	}

	/* truncate and copy the digest into the output buffer */
	bcopy(digestbuf, ivbuf, ivlen);

	return (0);

error:
	LOG_ERROR(ret, "");
	return (ret);
}

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
	uint_t plain_full_len, ivlen, maclen;

	ASSERT(crypt < ZIO_CRYPT_FUNCTIONS);
	ASSERT(key->ck_format == CRYPTO_KEY_RAW);

	/* lookup the encryption info */
	crypt_info = zio_crypt_table[crypt];
	ivlen = crypt_info.ci_ivlen;
	maclen = crypt_info.ci_maclen;

	ASSERT(ivlen <= MAX_DATA_IV_LEN);
	ASSERT(maclen <= MAX_DATA_MAC_LEN);

	/* setup encryption mechanism (same as crypt) */
	mech.cm_type = crypto_mech2id(crypt_info.ci_mechname);

	/* plain length will include the MAC if we are decrypting */
	if (encrypt)
		plain_full_len = datalen;
	else
		plain_full_len = datalen + maclen;

	/*
	 * setup encryption params (currently only AES
	 * CCM and AES GCM are supported)
	 */
	if (crypt_info.ci_crypt_type == ZC_TYPE_CCM) {
		ccmp.ulNonceSize = ivlen;
		ccmp.ulAuthDataSize = 0;
		ccmp.authData = NULL;
		ccmp.ulMACSize = maclen;
		ccmp.nonce = ivbuf;
		ccmp.ulDataSize = plain_full_len;

		mech.cm_param = (char *)(&ccmp);
		mech.cm_param_len = sizeof (CK_AES_CCM_PARAMS);
	} else {
		gcmp.ulIvLen = ivlen;
		gcmp.ulIvBits = BYTES_TO_BITS(ivlen);
		gcmp.ulAADLen = 0;
		gcmp.pAAD = NULL;
		gcmp.ulTagBits = BYTES_TO_BITS(maclen);
		gcmp.pIv = ivbuf;

		mech.cm_param = (char *)(&gcmp);
		mech.cm_param_len = sizeof (CK_AES_GCM_PARAMS);
	}

	/* populate the cipher and plain data structs */
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
	if (encrypt)
		ret = crypto_encrypt(&mech, &plaindata, key, tmpl, &cipherdata,
			NULL);
	else
		ret = crypto_decrypt(&mech, &cipherdata, key, tmpl, &plaindata,
			NULL);

	print_crypto_data("plaindata", &plaindata);
	print_crypto_data("cipherdata", &cipherdata);

	if (ret != CRYPTO_SUCCESS) {
		LOG_ERROR(ret, "");
		ret = EIO;
		goto error;
	}

	return (0);

error:
	LOG_ERROR(ret, "");
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
static int
zio_crypt_init_uios(boolean_t encrypt, dmu_object_type_t ot, uint8_t *plainbuf,
	uint8_t *cipherbuf, uint_t datalen, uint8_t *mac, uint8_t *out_mac,
	uio_t **puio, uio_t **cuio)
{
	int ret = ENOTSUP;
	uint_t nr_iovecs, nr_plain, nr_cipher;
	int spacetype;

#ifdef _KERNEL
	/* other encrypted objects will be added later */
	ASSERT(ot == DMU_OT_PLAIN_FILE_CONTENTS);

/* allocate the iovecs for the plain and cipher data */
	nr_iovecs = 1;

	if (encrypt) {
		nr_plain = nr_iovecs;

		*puio = uio_create(nr_plain, 0,
						  spacetype,
						  UIO_READ);
		if (!*puio) {
			ret = SET_ERROR(ENOMEM);
			goto error;
		}

		nr_cipher = nr_iovecs + 1;

		*cuio = uio_create(nr_cipher, 0,
						  spacetype,
						  UIO_WRITE);

		if (!*cuio) {
			ret = SET_ERROR(ENOMEM);
			goto error;
		}


		uio_addiov(*puio, (user_addr_t)plainbuf, datalen);

		uio_addiov(*cuio, (user_addr_t)cipherbuf, datalen);
		uio_addiov(*cuio, (user_addr_t)mac, MAX_DATA_MAC_LEN);

	} else {

		nr_plain = nr_iovecs + 1;

		*puio = uio_create(nr_plain, 0,
						  spacetype,
						  UIO_READ);
		if (!*puio) {
			ret = SET_ERROR(ENOMEM);
			goto error;
		}

		nr_cipher = nr_iovecs + 1;
		*cuio = uio_create(nr_cipher, 0,
						  spacetype,
						  UIO_WRITE);

		if (!*cuio) {
			ret = SET_ERROR(ENOMEM);
			goto error;
		}


		uio_addiov(*puio, (user_addr_t)plainbuf, datalen);

		uio_addiov(*cuio, (user_addr_t)cipherbuf, datalen);

		uio_addiov(*puio, (user_addr_t)out_mac, MAX_DATA_MAC_LEN);
		uio_addiov(*cuio, (user_addr_t)mac, MAX_DATA_MAC_LEN);

	}

	return (0);

error:
	LOG_ERROR(ret, "");
#endif // KERNEL

	return (ret);
}

#else // !APPLE

static int
zio_crypt_init_uios(boolean_t encrypt, dmu_object_type_t ot, uint8_t *plainbuf,
	uint8_t *cipherbuf, uint_t datalen, uint8_t *mac, uint8_t *out_mac,
	uio_t *puio, uio_t *cuio)
{
	int ret;
	uint_t nr_iovecs, nr_plain, nr_cipher;
	iovec_t *plain_iovecs = NULL, *cipher_iovecs = NULL, *mac_iov = NULL;

	/* other encrypted objects will be added later */
	ASSERT(ot == DMU_OT_PLAIN_FILE_CONTENTS);

	/* allocate the iovecs for the plain and cipher data */
	nr_iovecs = 1;

	if (encrypt) {
		nr_plain = nr_iovecs;

		plain_iovecs = kmem_alloc(nr_plain * sizeof (iovec_t),
			KM_SLEEP);
		if (!plain_iovecs) {
			ret = SET_ERROR(ENOMEM);
			goto error;
		}

		nr_cipher = nr_iovecs + 1;
		cipher_iovecs = kmem_alloc(nr_cipher * sizeof (iovec_t),
			KM_SLEEP);
		if (!cipher_iovecs) {
			ret = SET_ERROR(ENOMEM);
			goto error;
		}

		cipher_iovecs[nr_iovecs].iov_base = mac;
		cipher_iovecs[nr_iovecs].iov_len = MAX_DATA_MAC_LEN;

	} else {
		nr_plain = nr_iovecs + 1;
		plain_iovecs = kmem_alloc(nr_plain * sizeof (iovec_t),
			KM_SLEEP);
		if (!plain_iovecs) {
			ret = SET_ERROR(ENOMEM);
			goto error;
		}

		nr_cipher = nr_iovecs + 1;
		cipher_iovecs = kmem_alloc(nr_cipher * sizeof (iovec_t),
			KM_SLEEP);
		if (!cipher_iovecs) {
			ret = SET_ERROR(ENOMEM);
			goto error;
		}
		mac_iov = &plain_iovecs[nr_iovecs];

		plain_iovecs[nr_iovecs].iov_base = out_mac;
		plain_iovecs[nr_iovecs].iov_len = MAX_DATA_MAC_LEN;
		cipher_iovecs[nr_iovecs].iov_base = mac;
		cipher_iovecs[nr_iovecs].iov_len = MAX_DATA_MAC_LEN;
	}

	plain_iovecs[0].iov_base = plainbuf;
	plain_iovecs[0].iov_len = datalen;
	cipher_iovecs[0].iov_base = cipherbuf;
	cipher_iovecs[0].iov_len = datalen;

	/* populate the uios */
#ifdef _KERNEL
	puio->uio_segflg = UIO_SYSSPACE;
	cuio->uio_segflg = UIO_SYSSPACE;
#else
	puio->uio_segflg = UIO_USERSPACE;
	cuio->uio_segflg = UIO_USERSPACE;
#endif

	puio->uio_iov = plain_iovecs;
	puio->uio_iovcnt = nr_plain;
	cuio->uio_iov = cipher_iovecs;
	cuio->uio_iovcnt = nr_cipher;

	return (0);

error:
	LOG_ERROR(ret, "");
	if (plain_iovecs)
		kmem_free(plain_iovecs, nr_iovecs * sizeof (iovec_t));
	if (cipher_iovecs)
		kmem_free(cipher_iovecs, nr_iovecs * sizeof (iovec_t));

	return (ret);
}
#endif // __APPLE__

#ifdef __APPLE__
int
zio_do_crypt_data(boolean_t encrypt, zio_crypt_key_t *key,
	dmu_object_type_t ot, uint8_t *iv, uint8_t *mac, uint_t datalen,
	uint8_t *plainbuf, uint8_t *cipherbuf)
{
	int ret;
	uio_t *puio = NULL, *cuio = NULL;
	uint8_t out_mac[MAX_DATA_MAC_LEN];

	/* create uios for encryption */
	ret = zio_crypt_init_uios(encrypt, ot, plainbuf, cipherbuf, datalen,
		mac, out_mac, &puio, &cuio);
	if (ret)
		goto error;

	/* perform the encryption */
	zio_do_crypt_uio(encrypt, key->zk_crypt, &key->zk_key,
		key->zk_ctx_tmpl, iv, datalen, puio, cuio);

	zio_crypt_destroy_uio(puio);
	zio_crypt_destroy_uio(cuio);

	return (0);

error:
	LOG_ERROR(ret, "");
	zio_crypt_destroy_uio(puio);
	zio_crypt_destroy_uio(cuio);

	return (ret);
}

#else // !APPLE

int
zio_do_crypt_data(boolean_t encrypt, zio_crypt_key_t *key,
	dmu_object_type_t ot, uint8_t *iv, uint8_t *mac, uint_t datalen,
	uint8_t *plainbuf, uint8_t *cipherbuf)
{
	int ret;
	uio_t puio, cuio;
	uint8_t out_mac[MAX_DATA_MAC_LEN];

	bzero(&puio, sizeof (uio_t));
	bzero(&cuio, sizeof (uio_t));

	/* create uios for encryption */
	ret = zio_crypt_init_uios(encrypt, ot, plainbuf, cipherbuf, datalen,
		mac, out_mac, &puio, &cuio);
	if (ret)
		goto error;

	/* perform the encryption */
	zio_do_crypt_uio(encrypt, key->zk_crypt, &key->zk_key,
		key->zk_ctx_tmpl, iv, datalen, &puio, &cuio);

	zio_crypt_destroy_uio(&puio);
	zio_crypt_destroy_uio(&cuio);

	return (0);

error:
	LOG_ERROR(ret, "");
	zio_crypt_destroy_uio(&puio);
	zio_crypt_destroy_uio(&cuio);

	return (ret);
}
#endif // !APPLE
