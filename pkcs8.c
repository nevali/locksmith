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

/* Read keypairs in PKCS#8 [RFC5208] format */

int
pkcs8_input(kt_key *k, BIO *bin, kt_args *args)
{
	EVP_PKEY *pkey;
	PKCS8_PRIV_KEY_INFO *p8inf;
	int ktype;

	if(!(p8inf = PEM_read_bio_PKCS8_PRIV_KEY_INFO(bin, NULL, NULL, NULL)))
	{
		ERR_print_errors(args->berr);
		return 1;
	}	
	if(!(pkey = EVP_PKCS82PKEY(p8inf)))
	{
		ERR_print_errors(args->berr);
		return 1;
	}
	ktype = k->type;
	if(kt_key_from_evp(pkey, k))
	{
		BIO_printf(args->berr, "%s: PKCS#8: unable to handle a %s key\n", progname, kt_evptype_printname(pkey));
		EVP_PKEY_free(pkey);
		return 1;
	}
	EVP_PKEY_assign(pkey, EVP_PKEY_NONE, NULL);
	EVP_PKEY_free(pkey);
	/* If an explicit type was requested, it's an error if the key read from
	 * the PEM file is a different type.
	 */
	if(ktype != KT_UNKNOWN && k->type != ktype)
	{
		BIO_printf(args->berr, "%s: PKCS#8: expected a %s key, but read a %s key\n", progname, kt_type_printname(ktype), kt_type_printname(k->type));
		return 1;
	}	
	return 0;
}


int
pkcs8_output(kt_key *k, BIO *bout, kt_args *args)
{
	EVP_PKEY *pkey;
	PKCS8_PRIV_KEY_INFO *p8inf;

	if(!k->privkey)
	{
		BIO_printf(args->berr, "%s: PKCS#8: A private key is required to output PKCS#8\n", progname);
		return -1;
	}
	if(!args->writepriv)
	{
		BIO_printf(args->berr, "%s: PKCS#8: Warning: 'Write the private key' (-P) was not specified, but PKCS#8 output requested - writing anyway.\n", progname);
	}
	if(!(pkey = kt_key_to_evp(k)))
	{
		BIO_printf(args->berr, "%s: PKCS#8: unable to write a %s key in PKCS#8 format\n", progname, kt_type_printname(k->type));
		return -1;		
	}
	if(!(p8inf = EVP_PKEY2PKCS8(pkey)))
	{
		ERR_print_errors(args->berr);
		EVP_PKEY_free(pkey);
		return -1;
	}
	PEM_write_bio_PKCS8_PRIV_KEY_INFO(bout, p8inf);
	PKCS8_PRIV_KEY_INFO_free(p8inf);
	EVP_PKEY_free(pkey);
	return 0;
}
