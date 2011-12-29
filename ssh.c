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

/* Write an MD5 fingerprint to bout, equivalent to 'ssh-keygen -l -f infile'
 *
 * The format is:
 * <keysize> <00>:<01>:<02>... <filename> (<type>)
 *
 * e.g.:
 * 2048 66:f6:4b:2a:c8:4f:3b:22:13:36:f4:c0:93:e7:74:3d id_dsa.pub (RSA)
 *
 */
int
ssh_fingerprint(kt_key *k, BIO *bout, kt_args *args)
{
	BIO *tmp, *md;
	EVP_MD *digest;
	unsigned char mdbuf[EVP_MAX_MD_SIZE];
	size_t mdlen, i;

	(void) bout;

	switch(k->type)
	{
	case KT_RSA:
	case KT_DSA:
		break;
	default:
		BIO_printf(args->berr, "ssh: unable to generate an SSH fingerprint for a %s key\n", kt_type_printname(k->type));
		return 1;
	}
	/* Create a sink BIO for writing the digest material to */
	tmp = BIO_new(BIO_s_null());
	/* Create an MD5 filter BIO */
	md = BIO_new(BIO_f_md());
	BIO_set_md(md, EVP_md5());
	/* Attach the filter to the sink */
	tmp = BIO_push(md, tmp);
	ssh_write_pubkey_bio(k, tmp);
	BIO_get_md(md, &digest);
	mdlen = BIO_gets(md, (char *) mdbuf, EVP_MAX_MD_SIZE);
	BIO_printf(args->berr, "%d", k->size);
	for(i = 0; i < mdlen; i++)
	{
		BIO_printf(args->berr, "%c%02x", (i ? ':' : ' '), mdbuf[i]);
	}
	BIO_printf(args->berr, " %s (%s)\n", (args->comment ? args->comment : args->infile), kt_type_printname(k->type));
	BIO_free_all(tmp);
	return 0;
}

int
ssh_output(kt_key *k, BIO *bout, kt_args *args)
{
	BIO *b64;
	const char *p;

	if(k->privkey && args->writepriv)
	{
		return pem_output(k, bout, args);
	}	
	switch(k->type)
	{
	case KT_RSA:
	case KT_DSA:
		break;
	default:
		BIO_printf(args->berr, "ssh: unable to write a %s key in SSH-2 format\n", kt_type_printname(k->type));
		return 1;
	}
	b64 = BIO_new(BIO_f_base64());
	BIO_printf(bout, "---- BEGIN SSH2 PUBLIC KEY ----\n");
	if(args->comment)
	{
		BIO_printf(bout, "Comment: ");
		for(p = args->comment; *p; p++)
		{
			if(*p == '\\' || *p == '"' || *p == '\n')
			{
				BIO_write(bout, "\\", 1);
			}
			BIO_write(bout, p, 1);
		}
		BIO_write(bout, "\n", 1);
	}
	else
	{
		BIO_printf(bout, "Comment: %d-bit %s public key\n", k->size, kt_type_printname(k->type));
	}
	bout = BIO_push(b64, bout);
	ssh_write_pubkey_bio(k, bout);
	(void) BIO_flush(bout);
	bout = BIO_pop(bout);
	BIO_printf(bout, "---- END SSH2 PUBLIC KEY ----\n");
	BIO_free(b64);
	return 0;
}

/* Write the contents of a public key to a BIO */
int
ssh_write_pubkey_bio(kt_key *pubkey, BIO *bout)
{
	unsigned char *buf;
	size_t bufsize;
	
	buf = NULL;
	bufsize = 0;
	switch(pubkey->type)
	{
	case KT_RSA:
		ssh_write_str(bout, "ssh-rsa");
		buf = ssh_write_bn(bout, pubkey->k.rsa->e, buf, &bufsize);
		buf = ssh_write_bn(bout, pubkey->k.rsa->n, buf, &bufsize);
		break;
	case KT_DSA:
		ssh_write_str(bout, "ssh-dss");
		buf = ssh_write_bn(bout, pubkey->k.dsa->p, buf, &bufsize);
		buf = ssh_write_bn(bout, pubkey->k.dsa->q, buf, &bufsize);
		buf = ssh_write_bn(bout, pubkey->k.dsa->g, buf, &bufsize);
		buf = ssh_write_bn(bout, pubkey->k.dsa->pub_key, buf, &bufsize);
		break;
	default:
		return -1;
	}
	free(buf);
	return 0;
}

/* Write a null-terminated string to a BIO, in <length[uint32]><value>
 * format.
 */
int
ssh_write_str(BIO *bout, const char *str)
{
	size_t length;
	unsigned char lbytes[4];

	length = strlen(str);
	lbytes[0] = (length >> 24) & 0xFF;
	lbytes[1] = (length >> 16) & 0xFF;
	lbytes[2] = (length >> 8) & 0xFF;
	lbytes[3] = length & 0xFF;
	BIO_write(bout, lbytes, 4);
	BIO_write(bout, str, length);
	return 0;
}

/* Write an MPI to a BIO, in <length[uint32]><value> format
 *
 * Note that this function will allocate (or realloc) a buffer if buf
 * is NULL or buflen is smaller than the required size. The allocated
 * buffer will be returned, and will need to be freed by the caller.
 * (This pattern allows a buffer to be passed between repeated invocations
 * of ssh_write_bn(), with it growing to the largest size required
 * before finally being freed by the caller).
 */
unsigned char *
ssh_write_bn(BIO *bout, BIGNUM *num, unsigned char *buf, size_t *buflen)
{
	size_t l;

	l = BN_num_bytes(num) + 8;
	if(!buf || *buflen < l)
	{
		buf = realloc(buf, l);
		*buflen = l;
	}
	l = BN_bn2mpi(num, buf);
	BIO_write(bout, buf, l);
	return buf;
}
