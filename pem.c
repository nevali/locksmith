/*
 * Copyright 2011 Mo McRoberts.
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

int
pem_input(kt_key *k, BIO *bin, kt_args *args)
{
	EVP_PKEY *pkey = NULL;
	pem_password_cb *callback = NULL;
	void *cbdata = NULL;
	unsigned long e;
	int t;
	kt_keytype ktype;

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
	else
	{
		pkey = PEM_read_bio_PUBKEY(bin, NULL, callback, cbdata);
		if(pkey == NULL)
		{
			e = ERR_peek_error();
			/* It may be that we couldn't load the key because it's a private
			 * key -- try that instead.
			 */
			if(ERR_GET_LIB(e) == ERR_LIB_PEM)
			{
				if(ERR_GET_REASON(e) == PEM_R_NO_START_LINE)
				{
					(void) BIO_reset(bin);
					pkey = PEM_read_bio_PrivateKey(bin, NULL, callback, cbdata);
					if(pkey != NULL)
					{
						ERR_clear_error();
						k->privkey = 1;
					}
				}
			}
			if(pkey == NULL)
			{
				BIO_printf(args->berr, "PEM: unable to load key from %s\n", args->infile);
				ERR_print_errors(args->berr);
				return 1;
			}
		}
	}
	t = EVP_PKEY_type(pkey->type);
	switch(t)
	{
	case EVP_PKEY_RSA:
		ktype = KT_RSA;
		k->k.rsa = EVP_PKEY_get1_RSA(pkey);
		break;
	case EVP_PKEY_DSA:
		ktype = KT_DSA;
		k->k.dsa = EVP_PKEY_get1_DSA(pkey);
		break;
	default:
		BIO_printf(args->berr, "PEM: unable to handle a %d key\n", t);
		return 1;
	}
	EVP_PKEY_assign(pkey, EVP_PKEY_NONE, NULL);
	EVP_PKEY_free(pkey);
	/* If an explicit type was requested, it's an error if the key read from
	 * the PEM file is a different type.
	 */
	if(k->type != KT_UNKNOWN && k->type != ktype)
	{
		BIO_printf(args->berr, "expected a key of type %d but read a key of type %d\n", k->type, ktype);
		return 1;
	}
	k->type = ktype;
	return 0;
}

int
pem_output(kt_key *k, BIO *bout, kt_args *args)
{
	EVP_PKEY *pkey;
	EVP_CIPHER *cipher = NULL;
	char *kstr = NULL;
	int klen = 0;
	pem_password_cb *callback = NULL;
	void *cbdata = NULL;

	pkey = EVP_PKEY_new();
	switch(k->type)
	{
	case KT_RSA:
		EVP_PKEY_assign(pkey, EVP_PKEY_RSA, (char *) (k->k.rsa));
		break;
	case KT_DSA:
		EVP_PKEY_assign(pkey, EVP_PKEY_DSA, (char *) (k->k.dsa));
		break;
	default:
		BIO_printf(args->berr, "PEM: unable to write a %s key in PEM format\n", kt_type_printname(k->type));
		return 1;
	}
	if(k->privkey && args->writepriv)
	{
		PEM_write_bio_PKCS8PrivateKey(bout, pkey, cipher, kstr, klen, callback, cbdata);		
	}
	else
	{
		PEM_write_bio_PUBKEY(bout, pkey);
	}
	EVP_PKEY_assign(pkey, EVP_PKEY_NONE, NULL);
	EVP_PKEY_free(pkey);
	return 0;
}

