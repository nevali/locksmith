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

int
der_input(kt_key *k, BIO *bin, kt_args *args)
{
	int r;
	EVP_PKEY *pkey;
	kt_keytype ktype;

	r = -1;
	if(args->readpriv)
	{
		/* For private keys, we must know the kind of key being read */
		ktype = k->type;
		switch(k->type)
		{
		case KT_RSA:
			if((k->k.rsa = d2i_RSAPrivateKey_bio(bin, NULL)))
			{
				k->privkey = 1;
				r = 0;
			}
			break;
		case KT_DSA:
			if((k->k.dsa = d2i_DSAPrivateKey_bio(bin, NULL)))
			{
				k->privkey = 1;
				r = 0;
			}
			break;
		case KT_UNKNOWN:
			BIO_printf(args->berr, "%s: DER: You must specify a key type (using -t) to read in DER format\n", progname);
			return -1;
		default:
			BIO_printf(args->berr, "%s: DER: Unable to read a %s key in DER format\n", progname, kt_type_printname(k->type));
			return -1;
		}
		if(r)
		{		
			ERR_print_errors(args->berr);
			return r;
		}
	}
	else
	{
		/* For public keys, reading DER is very similar to reading PEM */
		if(!(pkey = d2i_PUBKEY_bio(bin, NULL)))
		{		
			ERR_print_errors(args->berr);
			return -1;
		}
		ktype = k->type;
		if(kt_key_from_evp(pkey, k))
		{
			BIO_printf(args->berr, "%s: DER: unable to handle a %s key\n", progname, kt_evptype_printname(pkey));
			EVP_PKEY_free(pkey);
			return 1;
		}
		EVP_PKEY_assign(pkey, EVP_PKEY_NONE, NULL);
		EVP_PKEY_free(pkey);
		if(ktype != KT_UNKNOWN && k->type != ktype)
		{
			BIO_printf(args->berr, "%s: DER: expected a %s key, but read a %s key\n", progname, kt_type_printname(k->type), kt_type_printname(ktype));
			return -1;
		}
	}
	return 0;
}

int
der_output(kt_key *k, BIO *bout, kt_args *args)
{
	switch(k->type)
	{
	case KT_RSA:
		if(k->privkey && args->writepriv)
		{
			i2d_RSAPrivateKey_bio(bout, k->k.rsa);
		}
		else
		{
			i2d_RSA_PUBKEY_bio(bout, k->k.rsa);
		}
		break;
	case KT_DSA:
		if(k->privkey && args->writepriv)
		{
			i2d_DSAPrivateKey_bio(bout, k->k.dsa);
		}
		else
		{
			i2d_DSA_PUBKEY_bio(bout, k->k.dsa);
		}
		break;
	case KT_DSAPARAM:
		i2d_DSAparams_bio(bout, k->k.dsa);
		break;
	case KT_DHPARAM:
		i2d_DHparams_bio(bout, k->k.dh);
		break;
	default:
		BIO_printf(args->berr, "%s: DER: unable to write a %s key in DER format\n", progname, kt_type_printname(k->type));
		return 1;
	}
	return 0;
}

