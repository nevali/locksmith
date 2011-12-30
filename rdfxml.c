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

static int bn_print(BIO *bout, const char *predicate, BIGNUM *num);

int
rdfxml_output(kt_key *key, BIO *bout, kt_args *args)
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
		BIO_printf(args->berr, "%s: RDF/XML: Unable to express a %s key as RDF\n", progname, kt_type_printname(key->type));
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
	tm = gmtime(&key->timestamp);
	strftime(timebuf, sizeof(timebuf) - 1, "%Y-%m-%dT%H:%M:%SZ", tm);
	BIO_printf(bout, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	BIO_printf(bout, 
			   "<rdf:RDF "
			   "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\""
			   "xmlns:cert=\"http://www.w3.org/ns/auth/cert#\""
			   "xmlns:dct=\"http://purl.org/dc/terms/\">\n\n");
	switch(key->type)
	{
	case KT_RSA:
		BIO_printf(bout, "<cert:RSAPublicKey rdf:about=\"#%s\">\n", namebuf);
		BIO_printf(bout, "\t<dct:created rdf:datatype=\"http://www.w3.org/2001/XMLSchema#dateTime\">%s</dct:created>\n", timebuf);
		bn_print(bout, "cert:modulus", key->k.rsa->n);
		bn_print(bout, "cert:exponent", key->k.rsa->e);
		BIO_printf(bout, "</cert:RSAPublicKey>\n");
		break;
	default:
		break;
	}
	BIO_printf(bout, "\n</rdf:RDF>\n");
	return 0;
}

static int
bn_print(BIO *bout, const char *predicate, BIGNUM *num)
{
	const char *neg;
	unsigned char *buf;
	int n, i;

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
		BIO_printf(bout, "\t<%s rdf:datatype=\"http://www.w3.org/2001/XMLSchema#integer\">%s%lu</%s>\n", predicate, neg, (unsigned long) num->d[0], predicate);
		return 0;
	}
	BIO_printf(bout, "\t<%s rdf:datatype=\"http://www.w3.org/2001/XMLSchema#hexBinary\">", predicate);
	buf = (unsigned char *) malloc(BN_num_bytes(num));
	n = BN_bn2bin(num, buf);
	for(i = 0; i < n; i++)
	{
		BIO_printf(bout, "%02x", buf[i]);
	}
	free(buf);
	BIO_printf(bout, "</%s>\n", predicate);
	return 0;
}

