#include <sys/crypto/api.h>
#include <sys/crypto/common.h>

/* Placeholders so that libzpool will build */

crypto_mech_type_t
crypto_mech2id(crypto_mech_name_t name)
{
	return (EOPNOTSUPP);
}

int
crypto_create_ctx_template(crypto_mechanism_t *mech, crypto_key_t *key,
	crypto_ctx_template_t *tmpl, int kmflag)
{
	return (EOPNOTSUPP);
}

void
crypto_destroy_ctx_template(crypto_ctx_template_t tmpl)
{
}

int
crypto_encrypt(crypto_mechanism_t *mech, crypto_data_t *plaintext,
	crypto_key_t *key, crypto_ctx_template_t tmpl,
	crypto_data_t *ciphertext, crypto_call_req_t *cr)
{
	return (EOPNOTSUPP);
}

int
crypto_decrypt(crypto_mechanism_t *mech, crypto_data_t *ciphertext,
	crypto_key_t *key, crypto_ctx_template_t tmpl, crypto_data_t *plaintext,
	crypto_call_req_t *cr)
{
	return (EOPNOTSUPP);
}

int
crypto_digest(crypto_mechanism_t *mech, crypto_data_t *data,
    crypto_data_t *digest, crypto_call_req_t *cr)
{
	return (EOPNOTSUPP);
}

int
crypto_digest_init(crypto_mechanism_t *mech, crypto_context_t *ctxp,
    crypto_call_req_t *cr)
{
	return (EOPNOTSUPP);
}

int crypto_digest_update(crypto_context_t ctx, crypto_data_t *data,
    crypto_call_req_t *cr)
{
	return (EOPNOTSUPP);
}

int crypto_digest_final(crypto_context_t ctx, crypto_data_t *digest,
    crypto_call_req_t *cr)
{
	return (EOPNOTSUPP);
}