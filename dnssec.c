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
dnssec_output(kt_key *key, BIO *bout, kt_args *args)
{
	BIO *mbio, *b64;
	BUF_MEM *ptr;
	const char *domain = "example.com.";
	const char *t;
	int version = 3;
	int flags = 256;
	int hash = NID_sha1;
	int alg;
	size_t l;
	unsigned char buf[4];
	unsigned char *bp;

	if(args->domain && args->domain[0])
	{
		domain = args->domain;
	}
	t = strchr(domain, 0);
	t--;
	if(*t != '.')
	{
		BIO_printf(args->berr, "%s: DNSSEC: Domain name '%s' does not include a terminating period, which is probably not what you want\n", progname, domain);
	}
	switch(key->type)
	{
	case KT_RSA:
		switch(hash)
		{
		case NID_md5:
			alg = 1;
			break;
		case NID_sha1:
			alg = 5;
			break;
		default:
			BIO_printf(args->berr, "%s: DNSSEC: Algorithm %d is not supported with RSA keys for DNSSEC output\n", progname, hash);
			return -1;
		}
		break;
	default:
		BIO_printf(args->berr, "%s: DNSSEC Unable to write a %s key\n", progname, kt_type_printname(key->type));
		return -1;
	}
	if(key->privkey && args->writepriv)
	{
		return dnssec_write_private(bout, key, alg);
	}
	BIO_printf(bout, ";; %d-bit %s zone key for %s\n", key->size, kt_type_printname(key->type), domain);
	BIO_printf(bout, ";; K%s+%03d+%05d\n", domain, alg, 0);
	mbio = BIO_new(BIO_s_mem());
	b64 = BIO_new(BIO_f_base64());
	mbio = BIO_push(b64, mbio);
	BIO_set_flags(mbio, BIO_FLAGS_BASE64_NO_NL);
	bp = NULL;
	switch(key->type)
	{
	case KT_RSA:
		/* Write the exponent length */
		l = BN_num_bytes(key->k.rsa->e);
		if(l < 255)
		{
			buf[0] = l;
			BIO_write(mbio, buf, 1);
		}
		else
		{
			buf[0] = 0;
			buf[1] = (l >> 8) & 0xff;
			buf[2] = l & 0xff;
			BIO_write(mbio, buf, 3);
		}
		/* Write the exponent */
		bp = (unsigned char *) malloc((BN_num_bytes(key->k.rsa->n)));
		BN_bn2bin(key->k.rsa->e, bp);
		BIO_write(mbio, bp, l);
		/* Write the modulus */
		l = BN_bn2bin(key->k.rsa->n, bp);
		BIO_write(mbio, bp, l);
		break;
	default:
		break;
	}
	if(bp)
	{
		free(bp);
	}
	mbio = BIO_pop(mbio);
	BIO_free(b64);
	BIO_get_mem_ptr(mbio, &ptr);
	BIO_printf(bout, "%s IN DNSKEY %d %d %d ( ", domain, flags, version, alg);
	BIO_write(bout, ptr->data, ptr->length);
	BIO_write(bout, " )\n", 3);
	BIO_free(mbio);
	return 0;
}

const char *
dnssec_alg_printname(int alg)
{
	switch(alg)
	{
	case 1:
		return "RSAMD5";
	case 5:
		return "RSASHA1";
	}
	return "Unknown";
}

int
dnssec_write_private(BIO *bout, kt_key *key, int alg)
{
	BIO_printf(bout, "Private-key-format: v1.2\n");
	BIO_printf(bout, "Algorithm: %d (%s)\n", alg, dnssec_alg_printname(alg));
	switch(key->type)
	{
	case KT_RSA:
		dnssec_write_bn_base64(bout, "Modulus: ", key->k.rsa->n, "\n");
		dnssec_write_bn_base64(bout, "PublicExponent: ", key->k.rsa->e, "\n");
		dnssec_write_bn_base64(bout, "PrivateExponent: ", key->k.rsa->d, "\n");
		dnssec_write_bn_base64(bout, "Prime1: ", key->k.rsa->p, "\n");
		dnssec_write_bn_base64(bout, "Prime2: ", key->k.rsa->q, "\n");
		dnssec_write_bn_base64(bout, "Exponent1: ", key->k.rsa->dmp1, "\n");
		dnssec_write_bn_base64(bout, "Exponent2: ", key->k.rsa->dmq1, "\n");
		dnssec_write_bn_base64(bout, "Coefficient: ", key->k.rsa->iqmp, "\n");
		break;
	default:
		break;
	}
	return 0;
}

int
dnssec_write_bn_base64(BIO *bout, const char *prefix, BIGNUM *num, const char *suffix)
{
	static unsigned char *buf = NULL;
	static size_t bufsize = 0;
	BIO *mbio, *b64;
	BUF_MEM *ptr;
	size_t l;
	unsigned char *p;

	l = BN_num_bytes(num);
	if(l > bufsize)
	{
		p = (unsigned char *) realloc(buf, l);
		if(!p)
		{
			return -1;
		}
		buf = p;
	}
	mbio = BIO_new(BIO_s_mem());
	b64 = BIO_new(BIO_f_base64());
	mbio = BIO_push(b64, mbio);
	BIO_set_flags(mbio, BIO_FLAGS_BASE64_NO_NL);
	BN_bn2bin(num, buf);
	BIO_write(mbio, buf, l);
	mbio = BIO_pop(mbio);
	BIO_free(b64);
	if(prefix)
	{
		BIO_write(bout, prefix, strlen(prefix));
	}
	BIO_get_mem_ptr(mbio, &ptr);
	BIO_write(bout, ptr->data, ptr->length);
	if(suffix)
	{
		BIO_write(bout, suffix, strlen(suffix));
	}
	return 0;
}
