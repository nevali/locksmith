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

/* Generate a new key of type key->type using args */
int
kt_generate(kt_key *key, kt_args *args)
{
	RSA *rsa;
	BIGNUM *exponent;
	BN_GENCB *gencb = NULL;

	/* If we're generating a new pair, we must have the private key */
	key->privkey = 1;
	switch(key->type)
	{
	case KT_RSA:
		if(!args->bits)
		{
			args->bits = 2048;
		}
		if(!args->exponent)
		{
			args->exponent = RSA_F4;
		}
		rsa = RSA_new();
		exponent = BN_new();
		BIO_printf(args->berr, "generate: Generating a new RSA private key with a %d-bit modulus\n", args->bits);
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
	default:
		BIO_printf(args->berr, "generate: Unable to generate a new %s key\n", kt_type_printname(key->type));
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
