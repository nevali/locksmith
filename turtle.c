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

static int bn_print(BIO *bout, const char *predicate, BIGNUM *num, const char *terminator);

int
turtle_output(kt_key *key, BIO *bout, kt_args *args)
{
	char namebuf[64], timebuf[32];
	int r;
	BIO *nbio;
	struct tm *tm;

	(void) args;

	switch(key->type)
	{
	case KT_RSA:
		break;
	default:
		BIO_printf(args->berr, "%s: Turtle: Unable to express a %s key as RDF\n", progname, kt_type_printname(key->type));
		return -1;
	}
	nbio = BIO_new(BIO_s_null());
	r = pgp_write_pubkey_packet(nbio, key);
	BIO_free(nbio);	
	
	if(key->keyid && !r)
	{
		sprintf(namebuf, "%08qx", (unsigned long long) key->keyid->id);
	}
	else
	{
		strcpy(namebuf, "key");
	}
	BIO_printf(bout,
			   "@prefix cert: <http://www.w3.org/ns/auth/cert#> .\n"
			   "@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n"
			   "@prefix dct: <http://purl.org/dc/terms/> .\n"
			   "\n");
	tm = gmtime(&key->timestamp);
	strftime(timebuf, sizeof(timebuf) - 1, "%Y-%m-%dT%H:%M:%SZ", tm);
	switch(key->type)
	{
	case KT_RSA:
		BIO_printf(bout, "_:%s a cert:RSAPublicKey ;\n", namebuf);
		BIO_printf(bout, "\tdct:created \"%s\"^^xsd:dateTime ;\n", timebuf);
		bn_print(bout, "cert:modulus", key->k.rsa->n, ";");
		bn_print(bout, "cert:exponent", key->k.rsa->e, ".");
		break;
	default:
		break;
	}
	return 0;
}

static int
bn_print(BIO *bout, const char *predicate, BIGNUM *num, const char *terminator)
{
	const char *neg;
	unsigned char *buf;
	int n, i;

	BIO_printf(bout, "\t%s ", predicate);
	if(BN_is_negative(num))
	{
		neg = "-";
	}
	else
	{
		neg = "";
	}
	if(BN_num_bytes(num) <= BN_BYTES)
	{
		BIO_printf(bout, "%s%lu ", neg, (unsigned long) num->d[0]);
	}
	else
	{
		BIO_write(bout, "\"", 1);
		buf = (unsigned char *) malloc(BN_num_bytes(num));
		n = BN_bn2bin(num, buf);
		for(i = 0; i < n; i++)
		{
			BIO_printf(bout, "%02x", buf[i]);
		}
		free(buf);
		BIO_printf(bout, "\"^^xsd:hexBinary ");
	}
	BIO_printf(bout, "%s\n", terminator);
	return 0;
}

