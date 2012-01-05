/*
 * Copyright 2011-2012 Mo McRoberts.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "p_keytool.h"

static kt_match_string matchers[] =
{
	{ "-----BEGIN CERTIFICATE-----", 0, 0 },
	{ NULL, 0, 0 }
};

int
x509_detect(kt_key *k, BIO *bin, kt_args *args)
{
	int r;

	r = kt_detect_match_bio(bin, matchers, k, args);
	if(r < 0)
	{
		return -1;
	}
	return (r ? 0 : 1);
}

/* Write an X.509 subjectKeyIdentifier according to method (1) of
 * section 4.2.1.2 of RFC5280.
 */

int
x509_fingerprint(kt_key *k, BIO *bout, kt_args *args)
{
	BIO *tmp, *mdbio;
	EVP_MD *digest;
	unsigned char buf[EVP_MAX_MD_SIZE];
	size_t mdlen, c;
	unsigned char *bp;

	/* Create a sink BIO for writing the digest material to */
	tmp = BIO_new(BIO_s_null());
	/* Create a digest filter BIO */
	mdbio = BIO_new(BIO_f_md());
	BIO_set_md(mdbio, EVP_sha1());
	/* Attach the filter to the sink */
	tmp = BIO_push(mdbio, tmp);
	switch(k->type)
	{
	case KT_RSA:
		i2d_RSAPublicKey_bio(tmp, k->k.rsa);
		break;
	case KT_DSA:
		bp = NULL;
		k->k.dsa->write_params = 0;
		c = i2d_DSAPublicKey(k->k.dsa, &bp);
		BIO_write(tmp, bp, (int) c);
		OPENSSL_free(bp);
		break;
	default:
		BIO_printf(args->berr, "%s: X.509: Cannot generate a fingerprint for a %s key\n", progname, kt_type_printname(k->type));
		BIO_free_all(tmp);
		return -1;
	}
	BIO_get_md(mdbio, &digest);
	mdlen = BIO_gets(mdbio, (char *) buf, EVP_MAX_MD_SIZE);
	BIO_free_all(tmp);
	for(c = 0; c < mdlen; c++)
	{
		if(c)
		{
			BIO_write(bout, ":", 1);
		}
		BIO_printf(bout, "%02x", buf[c] & 0xff);
	}
	BIO_write(bout, "\n", 1);
	return 0;
}

/* Read an X.509 certificate in PEM format and extract its public key */
int
x509_input(kt_key *key, BIO *bin, kt_args *args)
{
	X509 *x509;
	EVP_PKEY *pkey;

	(void) args;

	if(!(x509 = PEM_read_bio_X509(bin, NULL, NULL, NULL)))
	{
		return -1;
	}
	if(!(pkey = X509_get_pubkey(x509)))
	{
		X509_free(x509);
		return -1;
	}
	if(kt_key_from_evp(pkey, key))
	{
		X509_free(x509);
		return -1;
	}
	EVP_PKEY_assign(pkey, EVP_PKEY_NONE, NULL);
	X509_free(x509);
	return 0;
}

