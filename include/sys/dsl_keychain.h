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

#ifndef	_SYS_DSL_KEYCHAIN_H
#define	_SYS_DSL_KEYCHAIN_H

#include <sys/dmu_tx.h>
#include <sys/dmu.h>
#include <sys/zio_crypt.h>
#include <sys/spa.h>
#include <sys/dsl_dataset.h>

typedef enum zfs_keystatus {
	ZFS_KEYSTATUS_NONE = 0,
	ZFS_KEYSTATUS_UNAVAILABLE,
	ZFS_KEYSTATUS_AVAILABLE,
} zfs_keystatus_t;

/* in memory representation of a wrapping key */
typedef struct dsl_wrapping_key
{
	/* link into the keystore's tree of wrapping keys */
	avl_node_t wk_avl_link;

	/* actual wrapping key */
	crypto_key_t wk_key;

	/* refcount of number of keychains holding this struct */
	refcount_t wk_refcnt;

	/* dsl directory object that owns this wrapping key */
	uint64_t wk_ddobj;
} dsl_wrapping_key_t;

/* structure for passing around encryption params from userspace */
typedef struct dsl_crypto_params
{
	/* command to be executed */
	zfs_ioc_crypto_cmd_t cp_cmd;

	/* the encryption algorithm */
	uint64_t cp_crypt;

	/* the salt, if the keysource is of type passphrase */
	uint64_t cp_salt;

	/* keysource property string */
	const char *cp_keysource;

	/* the wrapping key */
	dsl_wrapping_key_t *cp_wkey;
} dsl_crypto_params_t;

/* in memory representation of an entry in the DSL Keychain */
typedef struct dsl_keychain_entry
{
	/* link into the keychain */
	list_node_t ke_link;

	/* first txg id that this key should be applied to */
	uint64_t ke_txgid;

	/* the actual key that this entry represents */
	zio_crypt_key_t ke_key;
} dsl_keychain_entry_t;

/* in memory representation of a DSL keychain */
typedef struct dsl_keychain
{
	/* avl node for linking into the keystore */
	avl_node_t kc_avl_link;

	/* refcount of dsl_keychain_record_t's holding this keychain */
	refcount_t kc_refcnt;

	/* lock for protecting the wrapping key and entries list */
	krwlock_t kc_lock;

	/* list of keychain entries */
	list_t kc_entries;

	/* wrapping key for all entries */
	dsl_wrapping_key_t *kc_wkey;

	/* keychain object id */
	uint64_t kc_obj;

	/* crypt used for this keychain */
	uint64_t kc_crypt;
} dsl_keychain_t;

/* in memory mapping of a dataset to a DSL keychain */
typedef struct dsl_keychain_record
{
	/* avl node for linking into the keystore dataset index */
	avl_node_t kr_avl_link;

	/* dataset this keychain belongs to (index) */
	uint64_t kr_dsobj;

	/* keychain value of this record */
	dsl_keychain_t *kr_keychain;
} dsl_keychain_record_t;

/* in memory structure for holding all keychains loaded into memory */
typedef struct spa_keystore
{
	/* lock for protecting structure of sk_keychains */
	krwlock_t sk_kc_lock;

	/* tree of all dsl_keychain_t's */
	avl_tree_t sk_keychains;

	/* lock for protecting sk_keychain_recs */
	krwlock_t sk_kr_lock;

	/* tree of all dsl_keychain_record_t's, indexed by dsobj */
	avl_tree_t sk_keychain_recs;

	/* lock for protecting the wrapping keys tree */
	krwlock_t sk_wkeys_lock;

	/* tree of all wrapping keys, indexed by ddobj */
	avl_tree_t sk_wkeys;
} spa_keystore_t;

typedef struct dsl_dataset dsl_dataset_t;

void dsl_wrapping_key_hold(dsl_wrapping_key_t *wkey, void *tag);
void dsl_wrapping_key_rele(dsl_wrapping_key_t *wkey, void *tag);
void dsl_wrapping_key_free(dsl_wrapping_key_t *wkey);
int dsl_wrapping_key_create(uint8_t *wkeydata, dsl_wrapping_key_t **wkey_out);
int dsl_crypto_params_init_nvlist(nvlist_t *props, dsl_crypto_params_t *dcp);
void dsl_crypto_params_destroy(dsl_crypto_params_t *dcp);

void spa_keystore_init(spa_keystore_t *sk);
void spa_keystore_fini(spa_keystore_t *sk);
int spa_keystore_wkey_hold_ddobj(spa_t *spa, uint64_t ddobj, void *tag,
	dsl_wrapping_key_t **wkey_out);
int spa_keystore_keychain_hold_dd(spa_t *spa, dsl_dir_t *dd, void *tag,
	dsl_keychain_t **kc_out);
void spa_keystore_keychain_rele(spa_t *spa, dsl_keychain_t *kc, void *tag);
int spa_keystore_load_wkey_impl(spa_t *spa, dsl_wrapping_key_t *wkey);
int spa_keystore_load_wkey(const char *dsname, dsl_crypto_params_t *dcp);
int spa_keystore_unload_wkey_impl(spa_t *spa, uint64_t ddobj);
int spa_keystore_unload_wkey(const char *dsname);
int spa_keystore_keychain_add_key(const char *dsname);
int spa_keystore_rewrap(const char *dsname, dsl_crypto_params_t *dcp);
int spa_keystore_create_keychain_record(spa_t *spa, dsl_dataset_t *ds);
int spa_keystore_remove_keychain_record(spa_t *spa, dsl_dataset_t *ds);
zfs_keystatus_t dsl_dataset_keystore_keystatus(dsl_dataset_t *ds);

int spa_encrypt_data(spa_t *spa, zbookmark_phys_t *bookmark, uint64_t txgid,
	dmu_object_type_t ot, blkptr_t *bp, uint_t datalen, boolean_t dedup,
	uint8_t *iv, uint8_t *mac, uint8_t *plainbuf, uint8_t *cipherbuf);
int spa_decrypt_data(spa_t *spa, zbookmark_phys_t *bookmark, uint64_t txgid,
	dmu_object_type_t ot, blkptr_t *bp, uint_t datalen, uint8_t *plainbuf,
	uint8_t *cipherbuf);

int dmu_objset_create_encryption_check(dsl_dir_t *pdd,
	dsl_crypto_params_t *dcp);
int dmu_objset_clone_encryption_check(dsl_dir_t *pdd, dsl_dir_t *odd,
	dsl_crypto_params_t *dcp);
uint64_t dsl_keychain_create_sync(uint64_t crypt, dsl_wrapping_key_t *wkey,
	dmu_tx_t *tx);
uint64_t dsl_keychain_clone_sync(dsl_dir_t *orig_dd, dsl_wrapping_key_t *wkey,
	boolean_t add_key, dmu_tx_t *tx);
void dsl_keychain_destroy_sync(uint64_t kcobj, dmu_tx_t *tx);

#endif
