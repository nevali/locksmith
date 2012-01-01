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

/* http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xml */
#define DNSSEC_ALG_RESERVED             0
#define DNSSEC_ALG_RSAMD5               1
#define DNSSEC_ALG_DH                   2
#define DNSSEC_ALG_DSA                  3
#define DNSSEC_ALG_ECC                  4
#define DNSSEC_ALG_RSASHA1              5
#define DNSSEC_ALG_DSA_NSEC3_SHA1       6
#define DNSSEC_ALG_RSASHA1_NSEC3_SHA1   7
#define DNSSEC_ALG_RSASHA256            8
#define DNSSEC_ALG_RSASHA512            10
#define DNSSEC_ALG_ECC_GOST             12
#define DNSSEC_ALG_INDIRECT             252
#define DNSSEC_ALG_PRIVATEDNS           253
#define DNSSEC_ALG_PRIVATEOID           254

static int get_args(kt_key *key, kt_args *args, const char **domain, int *version, int *flags, int *alg);

int
dnssec_output(kt_key *key, BIO *bout, kt_args *args)
{
	const char *domain = "example.com.";
	int version = 3;
	int flags = 256;
	int alg;

	if(get_args(key, args, &domain, &version, &flags, &alg))
	{
		return -1;
	}
	if(key->privkey && args->writepriv)
	{
		return dnssec_write_private(bout, key, alg);
	}
	return dnssec_write_public(bout, key, alg, domain, flags, version);
}

int
dnssec_keyid(kt_key *key, BIO *bout, kt_args *args)
{
	const char *domain = "example.com.";
	int version = 3;
	int flags = 256;
	int alg;
	int r;
	BIO *mem;
	BUF_MEM *ptr;
	unsigned int tag;

	if(get_args(key, args, &domain, &version, &flags, &alg))
	{
		return -1;
	}
	mem = BIO_new(BIO_s_mem());
	r = dnssec_write_public_rdata(mem, key, alg, domain, flags, version);
	if(r)
	{
		BIO_free(mem);
		return r;
	}
	BIO_get_mem_ptr(mem, &ptr);	
	tag = dnssec_keytag(ptr->data, ptr->length, alg);
	BIO_free(mem);
	BIO_printf(bout, "K%s+%03d+%05u\n", domain, alg, tag);	
	return 0;
}

static int
get_args(kt_key *key, kt_args *args, const char **domain, int *version, int *flags, int *alg)
{
	int hash = NID_undef;
	const char *t;

	if(args->domain && args->domain[0])
	{
		*domain = args->domain;
	}
	t = strchr(*domain, 0);
	t--;
	if(*t != '.')
	{
		BIO_printf(args->berr, "%s: DNSSEC: Domain name '%s' does not include a terminating period, which is probably not what you want\n", progname, *domain);
	}
	switch(key->type)
	{
	case KT_RSA:
		switch(hash)
		{
		case NID_md5:
			*alg = DNSSEC_ALG_RSAMD5;
			break;
		case NID_sha1:
			*alg = DNSSEC_ALG_RSASHA1;
			break;
		case NID_sha256:
			*alg = DNSSEC_ALG_RSASHA256;
			break;
		case NID_sha512:
			*alg = DNSSEC_ALG_RSASHA512;
			break;
		case NID_undef:
			/* Default to RSA/SHA-1 */
			*alg = DNSSEC_ALG_RSASHA1;
			break;
		default:
			BIO_printf(args->berr, "%s: DNSSEC: Algorithm %d is not supported with RSA keys for DNSSEC output\n", progname, hash);
			return -1;
		}
		break;
	case KT_DSA:
		switch(hash)
		{
		case NID_sha1:
			*alg = DNSSEC_ALG_DSA;
			break;
		case NID_undef:
			/* Default to DSA/SHA1 */
			*alg = DNSSEC_ALG_DSA;
			break;
		default:
			BIO_printf(args->berr, "%s: DNSSEC: Algorithm %d is not supported with DSA keys for DNSSEC output\n", progname, hash);
			return -1;
		}
		break;
	default:
		BIO_printf(args->berr, "%s: DNSSEC Unable to write a %s key\n", progname, kt_type_printname(key->type));
		return -1;
	}
	return 0;
}

const char *
dnssec_alg_printname(int alg)
{
	switch(alg)
	{
	case DNSSEC_ALG_RSAMD5:
		return "RSAMD5";
	case DNSSEC_ALG_DH:
		return "DH";
	case DNSSEC_ALG_DSA:
		return "DSA";
	case DNSSEC_ALG_ECC:
		return "ECC";
	case DNSSEC_ALG_RSASHA1:
		return "RSASHA1";
	case DNSSEC_ALG_DSA_NSEC3_SHA1:
		return "DSA-NSEC3-SHA1";
	case DNSSEC_ALG_RSASHA1_NSEC3_SHA1:
		return "RSASHA1-NSEC3-SHA1";
	case DNSSEC_ALG_RSASHA256:
		return "RSASHA256";
	case DNSSEC_ALG_RSASHA512:
		return "RSASHA512";
	case DNSSEC_ALG_ECC_GOST:
		return "ECC-GOST";
	case DNSSEC_ALG_INDIRECT:
		return "INDIRECT";
	case DNSSEC_ALG_PRIVATEDNS:
		return "PRIVATEDNS";
	case DNSSEC_ALG_PRIVATEOID:
		return "PRIVATEOID";
	}
	return "Unknown";
}
	
int
dnssec_write_public(BIO *bout, kt_key *key, int alg, const char *domain, int flags, int version)
{
	BIO *mem, *mbio, *b64;
	BUF_MEM *ptr;
	int r;
	unsigned int tag;

	mem = BIO_new(BIO_s_mem());
	r = dnssec_write_public_rdata(mem, key, alg, domain, flags, version);
	if(r)
	{
		BIO_free(mem);
		return r;
	}
	BIO_get_mem_ptr(mem, &ptr);	
	tag = dnssec_keytag(ptr->data, ptr->length, alg);

	BIO_printf(bout, ";; %d-bit %s zone key for %s\n", key->size, dnssec_alg_printname(alg), domain);
	BIO_printf(bout, ";; K%s+%03d+%05u\n", domain, alg, tag);

	mbio = BIO_new(BIO_s_mem());
	b64 = BIO_new(BIO_f_base64());
	mbio = BIO_push(b64, mbio);
	BIO_set_flags(mbio, BIO_FLAGS_BASE64_NO_NL);
	/* The first four bytes are flags, version, alg (which we already have) */
	BIO_write(mbio, ptr->data + 4, ptr->length - 4);
	BIO_free(mem);
	(void) BIO_flush(mbio);
	mbio = BIO_pop(mbio);
	BIO_free(b64);

	BIO_get_mem_ptr(mbio, &ptr);
	BIO_printf(bout, "%s IN DNSKEY %d %d %d ( ", domain, flags, version, alg);
	BIO_write(bout, ptr->data, ptr->length);
	BIO_write(bout, " )\n", 3);
	BIO_free(mbio);
	return r;
}

unsigned int
dnssec_keytag(unsigned char *key, size_t keysize, int alg)
{
	unsigned long ac;
	size_t i;

	if(alg == DNSSEC_ALG_RSAMD5)
	{
		/* RFC4043 Appendix B.1 */
		return 0;
	}
	for(ac = 0, i = 0; i < keysize; i++)
	{
		ac += (i & 1) ? key[i] : key[i] << 8;
	}
	ac += (ac >> 16) & 0xFFFF;
	return ac & 0xFFFF;
}

int
dnssec_write_public_rdata(BIO *bout, kt_key *key, int alg, const char *domain, int flags, int version)
{
	int r;
	size_t l, t;
	unsigned char buf[4];
	unsigned char *bp;

	buf[0] = (flags >> 8) & 0xff;
	buf[1] = flags & 0xff;
	buf[2] = version;
	buf[3] = alg;
	BIO_write(bout, buf, 4);
	bp = NULL;
	r = 0;
	switch(key->type)
	{
	case KT_RSA:
		/* Write the exponent length */
		l = BN_num_bytes(key->k.rsa->e);
		if(l < 255)
		{
			buf[0] = l;
			BIO_write(bout, buf, 1);
		}
		else
		{
			buf[0] = 0;
			buf[1] = (l >> 8) & 0xff;
			buf[2] = l & 0xff;
			BIO_write(bout, buf, 3);
		}
		/* Write the exponent */
		bp = (unsigned char *) malloc((BN_num_bytes(key->k.rsa->n)));
		BN_bn2bin(key->k.rsa->e, bp);
		BIO_write(bout, bp, l);
		/* Write the modulus */
		l = BN_bn2bin(key->k.rsa->n, bp);
		BIO_write(bout, bp, l);
		break;
	case KT_DSA:
		/* Calculate the T value, where 0 <= T <= 8
		 * The size of G is is T * 8 + 64, so we can find the size of
		 * G, subtract 64 and divide by 8 to obtain T.
		 */
		t = (BN_num_bytes(key->k.dsa->g) - 64) / 8;
		if(t > 8)
		{
			BIO_printf(bio_err, "%s: DNSSEC: This DSA key is too large to be written as a DNSKEY record (t = %d)\n", progname, (int) t);
			r = -1;
		}
		else
		{
			bp = (unsigned char *) malloc(t * 8 + 64);
			/* Write T */
			buf[0] = t;
			BIO_write(bout, buf, 1);
			r |= dnssec_write_bn_fixed(bout, key->k.dsa->q, bp, 20);
			r |= dnssec_write_bn_fixed(bout, key->k.dsa->p, bp, t * 8 + 64);
			r |= dnssec_write_bn_fixed(bout, key->k.dsa->g, bp, t * 8 + 64);
			r |= dnssec_write_bn_fixed(bout, key->k.dsa->pub_key, bp, t * 8 + 64);
		}
		break;
	default:
		break;
	}
	if(bp)
	{
		free(bp);
	}
	return r;
}

int
dnssec_write_bn_fixed(BIO *bout, BIGNUM *bn, unsigned char *buf, size_t nbytes)
{
	size_t l;
	unsigned char *bp;

	l = BN_num_bytes(bn);
	if(l > nbytes)
	{
		BIO_printf(bio_err, "%s: DNSSEC: Unable to fit key component in %d octets (%d octets required)\n", progname, (int) nbytes, (int) l);
		return -1;
	}
	memset(buf, 0, nbytes);
	bp = buf;
	if(l < nbytes)
	{
		bp += nbytes - l;
	}
	BN_bn2bin(bn, bp);
	BIO_write(bout, buf, nbytes);
	return 0;
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
	case KT_DSA:
		dnssec_write_bn_base64(bout, "Prime(p): ", key->k.dsa->p, "\n");
		dnssec_write_bn_base64(bout, "Subprime(q): ", key->k.dsa->q, "\n");
		dnssec_write_bn_base64(bout, "Base(g): ", key->k.dsa->g, "\n");
		dnssec_write_bn_base64(bout, "Private_value(x): ", key->k.dsa->priv_key, "\n");
		dnssec_write_bn_base64(bout, "Public_value(y): ", key->k.dsa->pub_key, "\n");
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
	(void) BIO_flush(mbio);
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
