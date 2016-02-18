#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/sched_impl.h>
#include <sys/modhash_impl.h>
#include <sys/crypto/algs.h>

#define	WRAPPING_IV_LEN 13
#define	WRAPPING_MAC_LEN 16
#define	CTBUF_LEN(len) ((len) + WRAPPING_IV_LEN + WRAPPING_MAC_LEN)

#define	SET_CRYPTO_DATA(cd, buf, len)	\
	(cd).cd_format = CRYPTO_DATA_RAW;\
	(cd).cd_offset = 0;\
	(cd).cd_length = (len);\
	(cd).cd_miscdata = NULL;\
	(cd).cd_raw.iov_base = (buf);\
	(cd).cd_raw.iov_len = (len);

#define	SHA_CKSUM_SIZE 32

static void __exit
illumos_crypto_exit(void)
{
	sha2_mod_fini();
	aes_mod_fini();
	kcf_sched_destroy();
	kcf_prov_tab_destroy();
	kcf_destroy_mech_tabs();
	mod_hash_fini();
}
module_exit(illumos_crypto_exit);

/* roughly equivalent to kcf.c: _init() */
static int __init
illumos_crypto_init(void)
{
	/* initialize the mod hash module */
	mod_hash_init();

	/* initialize the mechanisms tables supported out-of-the-box */
	kcf_init_mech_tabs();

	/* initialize the providers tables */
	kcf_prov_tab_init();

	/*
	 * Initialize scheduling structures. Note that this does NOT
	 * start any threads since it might not be safe to do so.
	 */
	kcf_sched_init();

	/* initialize algorithms */
	aes_mod_init();
	sha2_mod_init();

	return (0);
}
module_init(illumos_crypto_init);

MODULE_LICENSE("CDDL");
