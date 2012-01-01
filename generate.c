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

/* Generate a new key of type key->type using args */
int
kt_generate(kt_key *key, kt_args *args)
{
	RSA *rsa;
	DSA *dsa;
	BIGNUM *exponent;
	BN_GENCB *gencb = NULL;

	/* If we're generating a new pair, we must have the private key */
	key->privkey = 1;
	switch(key->type)
	{
	case KT_RSA:
		if(args->bits <= 0)
		{
			args->bits = 2048;
		}
		if(!args->exponent)
		{
			args->exponent = RSA_F4;
		}
		rsa = RSA_new();
		exponent = BN_new();
		BIO_printf(args->berr, "%s: Generating a new RSA private key with a %d-bit modulus\n", progname, args->bits);
		if(!BN_set_word(exponent, args->exponent))
		{
			ERR_print_errors(args->berr);
			return 1;
		}
		if(!RSA_generate_key_ex(rsa, args->bits, exponent, gencb))
		{
			ERR_print_errors(args->berr);
			return 1;
		}
		key->k.rsa = rsa;
		break;
	case KT_DSAPARAM:
		if(args->bits <= 0)
		{
			args->bits = 2048;
		}
		dsa = DSA_new();
		BIO_printf(args->berr, "%s: Generating new %d-bit DSA key parameters\n", progname, args->bits);
		if(!DSA_generate_parameters_ex(dsa, args->bits, NULL, 0, NULL, NULL, gencb))
		{
			ERR_print_errors(args->berr);
			return 1;
		}
		key->k.dsa = dsa;
		break;
	default:
		BIO_printf(args->berr, "%s: Unable to generate a new %s key\n", progname, kt_type_printname(key->type));
		return 1;
	}
	return 0;
}

/* If key contains a private key, convert it to a public key */
int
kt_get_public(kt_key *key)
{
	RSA *rsa;
	DSA *dsa;

	if(!key->privkey)
	{
		return 0;
	}
	switch(key->type)
	{
	case KT_RSA:
		rsa = RSA_new();
		rsa->n = key->k.rsa->n;
		rsa->e = key->k.rsa->e;
		key->k.rsa->n = NULL;
		key->k.rsa->e = NULL;
		RSA_free(key->k.rsa);
		key->k.rsa = rsa;
		break;
	case KT_DSA:
		dsa = DSA_new();
		dsa->p = key->k.dsa->p;
		dsa->q = key->k.dsa->q;
		dsa->g = key->k.dsa->g;
		dsa->pub_key = key->k.dsa->pub_key;
		key->k.dsa->p = NULL;
		key->k.dsa->q = NULL;
		key->k.dsa->g = NULL;
		key->k.dsa->pub_key = NULL;
		DSA_free(key->k.dsa);
		key->k.dsa = dsa;
		break;
	default:
		fprintf(stderr, "public: Unable to retrieve public key from a %s private key.\n", kt_type_printname(key->type));
		return 1;
	}
	key->privkey = 0;
	return 0;
}

int
kt_get_size(kt_key *key)
{
	switch(key->type)
	{
	case KT_RSA:
		return BN_num_bytes(key->k.rsa->n) * 8;
	case KT_DSA:
		return BN_num_bytes(key->k.dsa->pub_key) * 8;
	default:
		return 0;
	}
}

EVP_PKEY *
kt_key_to_evp(kt_key *k)
{
	EVP_PKEY *pkey;

	switch(k->type)
	{
	case KT_RSA:
		if((pkey = EVP_PKEY_new()))
		{
			EVP_PKEY_assign(pkey, EVP_PKEY_RSA, (char *) (k->k.rsa));
		}
		break;
	case KT_DSA:
		if((pkey = EVP_PKEY_new()))
		{
			EVP_PKEY_assign(pkey, EVP_PKEY_DSA, (char *) (k->k.dsa));
		}
		break;
	default:
		return NULL;
	}
	return pkey;
}

int
kt_key_from_evp(EVP_PKEY *pkey, kt_key *k)
{
	int t;

	t = EVP_PKEY_type(pkey->type);
	switch(t)
	{
	case EVP_PKEY_RSA:
		k->type = KT_RSA;
		k->k.rsa = EVP_PKEY_get1_RSA(pkey);
		break;
	case EVP_PKEY_DSA:
		k->type = KT_DSA;
		k->k.dsa = EVP_PKEY_get1_DSA(pkey);
		break;
	default:
		return -1;
	}
	return 0;
}

kt_keytype
kt_type_from_evptype(int t)
{
	switch(t)
	{
	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA2:
		return KT_RSA;
	case EVP_PKEY_DSA:
	case EVP_PKEY_DSA1:
	case EVP_PKEY_DSA2:
	case EVP_PKEY_DSA3:
	case EVP_PKEY_DSA4:
		return KT_DSA;
	case EVP_PKEY_EC:
		return KT_ECC;
	case EVP_PKEY_DH:		
		return KT_DH;
	}
	return KT_UNKNOWN;
}

kt_keytype
kt_type_from_evp(EVP_PKEY *pkey)
{
	return kt_type_from_evptype(EVP_PKEY_type(pkey->type));
}

const char *
kt_evptype_printname(EVP_PKEY *pkey)
{
	return kt_type_printname(kt_type_from_evp(pkey));
}

const char *
kt_hash_printname(int nid)
{
	static char sbuf[64];
	
	switch(nid)
	{
	case NID_md5:
		return "MD5";
	case NID_sha1:
		return "SHA1";
	case NID_sha224:
		return "SHA-224";
	case NID_sha256:
		return "SHA-256";
	case NID_sha384:
		return "SHA-384";
	case NID_sha512:
		return "SHA-512";
	}
	sprintf(sbuf, "Unknown hash algorithm %d", nid);
	return sbuf;
}
