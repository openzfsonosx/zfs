/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
#include <sys/fs/zfs.h>

void
zio_crypt_key_destroy(zio_crypt_key_t *key)
{
	if (key->zk_ctx_tmpl) crypto_destroy_ctx_template(key->zk_ctx_tmpl);
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
		ret = EIO;
		key->zk_ctx_tmpl = NULL;
		goto error;
	}

	return (0);

error:
	LOG_ERROR(ret, "");
	if (key->zk_key.ck_data)
		kmem_free(key->zk_key.ck_data, keydata_len);

	return (ret);
}

void
dsl_wrapping_key_hold(dsl_wrapping_key_t *wkey, void *tag)
{
	(void) refcount_add(&wkey->wk_refcnt, tag);
	LOG_DEBUG("wkey hold 0x%p: refcount = %d", wkey,
		(int)refcount_count(&wkey->wk_refcnt));
}

void
dsl_wrapping_key_rele(dsl_wrapping_key_t *wkey, void *tag)
{
	(void) refcount_remove(&wkey->wk_refcnt, tag);
	LOG_DEBUG("wkey rele 0x%p: refcount = %d", wkey,
		(int)refcount_count(&wkey->wk_refcnt));
}

void
dsl_wrapping_key_free(dsl_wrapping_key_t *wkey) {
	VERIFY0(refcount_count(&wkey->wk_refcnt));

	if (wkey->wk_key.ck_data) {
		bzero(wkey->wk_key.ck_data,
			BITS_TO_BYTES(wkey->wk_key.ck_length));
		kmem_free(wkey->wk_key.ck_data,
			BITS_TO_BYTES(wkey->wk_key.ck_length));
	}

	refcount_destroy(&wkey->wk_refcnt);
	kmem_free(wkey, sizeof (dsl_wrapping_key_t));
}

int
dsl_wrapping_key_create(uint8_t *wkeydata, dsl_wrapping_key_t **wkey_out)
{
	int ret;
	dsl_wrapping_key_t *wkey;

	/* allocate the wrapping key */
	wkey = kmem_alloc(sizeof (dsl_wrapping_key_t), KM_SLEEP);
	if (!wkey)
		return (SET_ERROR(ENOMEM));

	/* allocate and initialize the underlying crypto key */
	wkey->wk_key.ck_data = kmem_alloc(WRAPPING_KEY_LEN, KM_SLEEP);
	if (!wkey->wk_key.ck_data) {
		ret = ENOMEM;
		goto error;
	}

	wkey->wk_key.ck_format = CRYPTO_KEY_RAW;
	wkey->wk_key.ck_length = BYTES_TO_BITS(WRAPPING_KEY_LEN);

	/* copy the data */
	bcopy(wkeydata, wkey->wk_key.ck_data, WRAPPING_KEY_LEN);

	/* initialize the refcount */
	refcount_create(&wkey->wk_refcnt);

	*wkey_out = wkey;
	return (0);

error:
	dsl_wrapping_key_free(wkey);

	*wkey_out = NULL;
	return (ret);
}

int
dsl_crypto_params_init_nvlist(nvlist_t *props, dsl_crypto_params_t *dcp)
{
	int ret;
	dsl_wrapping_key_t *wkey = NULL;
	boolean_t crypt_exists = B_TRUE, wkeydata_exists = B_TRUE;
	boolean_t keysource_exists = B_TRUE, salt_exists = B_TRUE;
	boolean_t cmd_exists = B_TRUE;
	char *keysource = NULL;
	uint64_t salt = 0, crypt = 0, cmd = ZFS_IOC_CRYPTO_CMD_NONE;
	uint8_t *wkeydata;
	uint_t wkeydata_len;

	/* get relevent properties from the nvlist */
	ret = nvlist_lookup_uint64(props,
		zfs_prop_to_name(ZFS_PROP_ENCRYPTION), &crypt);
	if (ret)
		crypt_exists = B_FALSE;

	ret = nvlist_lookup_string(props,
		zfs_prop_to_name(ZFS_PROP_KEYSOURCE), &keysource);
	if (ret)
		keysource_exists = B_FALSE;

	ret = nvlist_lookup_uint8_array(props, "wkeydata", &wkeydata,
		&wkeydata_len);
	if (ret)
		wkeydata_exists = B_FALSE;

	ret = nvlist_lookup_uint64(props,
		zfs_prop_to_name(ZFS_PROP_SALT), &salt);
	if (ret)
		salt_exists = B_FALSE;

	ret = nvlist_lookup_uint64(props, "crypto_cmd", &cmd);
	if (ret)
		cmd_exists = B_FALSE;

	LOG_DEBUG("%d %d %d %d %d", (int)crypt_exists, (int)keysource_exists,
		(int)wkeydata_exists, (int)salt_exists, (int)cmd_exists);

	/* no parameters are valid; results in inherited crypto settings */
	if ((!crypt_exists || crypt == ZIO_CRYPT_OFF) && !keysource_exists &&
		!wkeydata_exists & !salt_exists) {
		ret = 0;
		goto out;
	}

	/* check wrapping key length */
	if (wkeydata_len != WRAPPING_KEY_LEN) {
		ret = SET_ERROR(EINVAL);
		goto error;
	}

	/* specifying a keysource requires keydata */
	if (keysource_exists && !wkeydata_exists) {
		ret = SET_ERROR(EINVAL);
		goto error;
	}

	/* remove crypto_cmd from props since it should not be used again */
	if (cmd_exists) {
		ret = nvlist_remove_all(props, "crypto_cmd");
		if (ret) {
			ret = SET_ERROR(EIO);
			goto error;
		}
	}

	/* create the wrapping key from the raw data */
	if (wkeydata_exists) {
		/* create the wrapping key with the verified parameters */
		ret = dsl_wrapping_key_create(wkeydata, &wkey);
		if (ret) goto error;

		/* remove wkeydata from props since it should not be logged */
		bzero(wkeydata, wkeydata_len);
		ret = nvlist_remove_all(props, "wkeydata");
		if (ret) {
			ret = SET_ERROR(EIO);
			goto error;
		}
	}

	dcp->cp_cmd = cmd;
	dcp->cp_crypt = crypt;
	dcp->cp_salt = salt;
	dcp->cp_keysource = keysource;
	dcp->cp_wkey = wkey;
	return (0);

error:
	LOG_ERROR(ret, "");
	if (wkey) dsl_wrapping_key_free(wkey);

out:
	dcp->cp_cmd = ZFS_IOC_CRYPTO_CMD_NONE;
	dcp->cp_crypt = ZIO_CRYPT_INHERIT;
	dcp->cp_salt = 0;
	dcp->cp_keysource = NULL;
	dcp->cp_wkey = NULL;
	return (ret);
}

void
dsl_crypto_params_destroy(dsl_crypto_params_t *dcp)
{
	dsl_wrapping_key_free(dcp->cp_wkey);
}

int
zio_do_crypt(boolean_t encrypt, uint64_t crypt, crypto_key_t *key,
	crypto_ctx_template_t tmpl, uint8_t *ivbuf, uint_t ivlen, uint_t maclen,
	uint8_t *plainbuf, uint8_t *cipherbuf, uint_t datalen)
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
	if (encrypt) plain_full_len = datalen;
	else plain_full_len = datalen + maclen;

	/*
	 * setup encryption params (currently only AES
	 * CCM and AES GCM are supported)
	 */
	if (crypt_info.ci_crypt_type == ZIO_CRYPT_TYPE_CCM) {
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

	/* setup plaindata struct with buffer from keydata */
	plaindata.cd_format = CRYPTO_DATA_RAW;
	plaindata.cd_offset = 0;
	plaindata.cd_length = plain_full_len;
	plaindata.cd_miscdata = NULL;
	plaindata.cd_raw.iov_base = (char *)plainbuf;
	plaindata.cd_raw.iov_len = plain_full_len;

	/* setup cipherdata to be filled */
	cipherdata.cd_format = CRYPTO_DATA_RAW;
	cipherdata.cd_offset = 0;
	cipherdata.cd_length = datalen + maclen;
	cipherdata.cd_miscdata = NULL;
	cipherdata.cd_raw.iov_base = (char *)cipherbuf;
	cipherdata.cd_raw.iov_len = datalen + maclen;

	/* perform the actual encryption */
	if (encrypt)
		ret = crypto_encrypt(&mech, &plaindata, key, tmpl, &cipherdata,
			NULL);
	else
		ret = crypto_decrypt(&mech, &cipherdata, key, tmpl, &plaindata,
			NULL);

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
