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

/* Do not insert new entries into this array -- add them immediately above
 * the NULL entry. The index into this array as passed to pem_input().
 */
static kt_match_string matchers[] =
{
	{ "-----BEGIN PUBLIC KEY-----", 0, 0 },

	{ "-----BEGIN RSA PRIVATE KEY-----", 0, 1 },
	{ "-----BEGIN DSA PRIVATE KEY-----", 0, 1 },

	{ "-----BEGIN DSA PARAMETERS-----", 0, 0 },
	{ "-----BEGIN DH PARAMETERS-----", 0, 0 },

	{ "-----BEGIN RSA PUBLIC KEY-----", 0, 0 },
	{ "-----BEGIN DSA PUBLIC KEY-----", 0, 0 },

	{ NULL, 0, 0 }
};

int
pem_detect(kt_key *k, BIO *bin, kt_args *args)
{
	int r;

	r = kt_detect_match_bio(bin, matchers, k, args);
	if(r < 0)
	{
		return -1;
	}
	return (r ? 0 : 1);
}

int
pem_input(kt_key *k, BIO *bin, kt_args *args)
{
	EVP_PKEY *pkey = NULL;
	pem_password_cb *callback = NULL;
	void *cbdata = NULL;
	kt_keytype ktype;

	if(args->detect_match_entry == -1)
	{
		/* No detection pass has been run, try one now */
		pem_detect(k, bin, args);
		(void) BIO_seek(bin, 0);
	}
	ktype = k->type;
	if(args->readpriv)
	{
		pkey = PEM_read_bio_PrivateKey(bin, NULL, callback, cbdata);
		if(pkey == NULL)
		{
			BIO_printf(args->berr, "PEM: unable to load key from %s\n", args->infile);
			ERR_print_errors(args->berr);
			return 1;
		}
		k->privkey = 1;
	}
	else if(args->detect_match_entry == 3)
	{
		/* BEGIN DSA PARAMETERS */
		k->type = KT_DSAPARAM;
		if(!(k->k.dsa = PEM_read_bio_DSAparams(bin, NULL, callback, cbdata)))
		{
			BIO_printf(args->berr, "%s: PEM: unable to load DSA parameters from %s\n", progname, args->infile);
			ERR_print_errors(args->berr);
			return 1;
		}				

	}
	else if(args->detect_match_entry == 4)
	{
		/* BEGIN DH PARAMETERS */
		k->type = KT_DHPARAM;
		if(!(k->k.dh = PEM_read_bio_DHparams(bin, NULL, callback, cbdata)))
		{
			BIO_printf(args->berr, "%s: PEM: unable to load Diffie-Hellman parameters from %s\n", progname, args->infile);
			ERR_print_errors(args->berr);
			return 1;
		}				
	}
	else if(args->detect_match_entry == 5)
	{
		/* BEGIN RSA PUBLIC KEY */
		k->type = KT_RSA;
		if(!(k->k.rsa = PEM_read_bio_RSAPublicKey(bin, NULL, callback, cbdata)))
		{
			/* Try reading it as a SubjectPublicKeyInfo instead */
			BIO_reset(bin);
			pkey = PEM_ASN1_read_bio(d2i_PUBKEY, PEM_STRING_RSA_PUBLIC, bin, NULL, callback, cbdata);
			if(!pkey)
			{
				BIO_printf(args->berr, "%s: PEM: unable to load RSA public key from %s\n", progname, args->infile);
				ERR_print_errors(args->berr);
				return 1;
			}
		}
	}
	else if(args->detect_match_entry == 6)
	{
		/* BEGIN DSA PUBLIC KEY */
		pkey = PEM_ASN1_read_bio(d2i_PUBKEY, PEM_STRING_DSA_PUBLIC, bin, NULL, callback, cbdata);
		if(!pkey)
		{
			BIO_printf(args->berr, "%s: PEM: unable to load DSA public key from %s\n", progname, args->infile);
			ERR_print_errors(args->berr);
			return 1;
		}
	}
	else
	{
		pkey = PEM_read_bio_PUBKEY(bin, NULL, callback, cbdata);
		if(pkey == NULL)
		{
			BIO_printf(args->berr, "%s: PEM: unable to load key from %s\n", progname, args->infile);
			ERR_print_errors(args->berr);
			return 1;
		}
	}
	if(pkey)
	{
		if(kt_key_from_evp(pkey, k))
		{
			BIO_printf(args->berr, "%s: PEM: unable to handle a %s key\n", progname, kt_evptype_printname(pkey));
			EVP_PKEY_free(pkey);
			return 1;
		}
		EVP_PKEY_assign(pkey, EVP_PKEY_NONE, NULL);
		EVP_PKEY_free(pkey);
	}
	/* If an explicit type was requested, it's an error if the key read from
	 * the PEM file is a different type.
	 */
	if(ktype != KT_UNKNOWN && k->type != ktype)
	{
		BIO_printf(args->berr, "%s: PEM: expected a %s key, but read a %s key\n", progname, kt_type_printname(ktype), kt_type_printname(k->type));
		return 1;
	}
	return 0;
}

int
pem_output(kt_key *k, BIO *bout, kt_args *args)
{
	EVP_PKEY *pkey;
	EVP_CIPHER *cipher = NULL;
	unsigned char *kstr = NULL;
	int klen = 0;
	pem_password_cb *callback = NULL;
	void *cbdata = NULL;

	pkey = NULL;
	switch(k->type)
	{
	case KT_RSA:
	case KT_DSA:
		pkey = kt_key_to_evp(k);
		break;
	case KT_DSAPARAM:
		PEM_write_bio_DSAparams(bout, k->k.dsa);
		return 0;
	case KT_DHPARAM:
		PEM_write_bio_DHparams(bout, k->k.dh);
		return 0;
	default:
		break;
	}
	if(!pkey)
	{
		BIO_printf(args->berr, "%s: PEM: unable to write a %s key in PEM format\n", progname, kt_type_printname(k->type));
		return 1;
	}
	if(k->privkey && args->writepriv)
	{
		switch(k->type)
		{
		case KT_RSA:
			PEM_write_bio_RSAPrivateKey(bout, k->k.rsa, cipher, kstr, klen, callback, cbdata);
			break;
		case KT_DSA:
			PEM_write_bio_DSAPrivateKey(bout, k->k.dsa, cipher, kstr, klen, callback, cbdata);
			break;
		default:
			break;
		}
	}
	else
	{
		PEM_write_bio_PUBKEY(bout, pkey);
	}
	EVP_PKEY_assign(pkey, EVP_PKEY_NONE, NULL);
	EVP_PKEY_free(pkey);
	return 0;
}

