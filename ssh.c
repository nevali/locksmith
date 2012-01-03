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

#define SSH_MAGIC                       0x3f6ff9eb

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
	unsigned char mdbuf[EVP_MAX_MD_SIZE];
	ssize_t mdlen, i;

	mdlen = ssh_calc_fp(k, EVP_md5(), mdbuf);
	if(mdlen < 0)
	{
		BIO_printf(args->berr, "%s: SSH: unable to generate an SSH fingerprint for a %s key\n", progname, kt_type_printname(k->type));
		return (int) mdlen;
	}
	BIO_printf(bout, "%d", k->size);
	for(i = 0; i < mdlen; i++)
	{
		BIO_printf(bout, "%c%02x", (i ? ':' : ' '), mdbuf[i]);
	}
	BIO_printf(bout, " %s (%s)\n", (args->comment ? args->comment : args->infile), kt_type_printname(k->type));
	return 0;
}

/* Calculate an SSH key fingerprint using the algorithm specified by md
 * buf must be able to hold EVP_MAX_MD_SIZE bytes. The return value is
 * the number of bytes in the digest if positive, or an error code if
 * negative.
 */
ssize_t
ssh_calc_fp(kt_key *key, const EVP_MD *md, unsigned char *buf)
{
	BIO *tmp, *mdbio;
	EVP_MD *digest;
	size_t mdlen;
	int r;

	/* Create a sink BIO for writing the digest material to */
	tmp = BIO_new(BIO_s_null());
	/* Create a digest filter BIO */
	mdbio = BIO_new(BIO_f_md());
	BIO_set_md(mdbio, md);
	/* Attach the filter to the sink */
	tmp = BIO_push(mdbio, tmp);
	r = ssh_write_pubkey(tmp, key);
	BIO_get_md(mdbio, &digest);
	mdlen = BIO_gets(mdbio, (char *) buf, EVP_MAX_MD_SIZE);
	BIO_free_all(tmp);
	if(r)
	{
		return r > 0 ? -1 : r;
	}
	return mdlen;
}

/* Write an SSH2 public or private key */
int
ssh_output(kt_key *k, BIO *bout, kt_args *args)
{
	BIO *b64, *bmem;
	BUF_MEM *ptr;
	const char *p;
	int r, priv;
	unsigned char buf[128];
	size_t l;
	const char *privtype, *ciphername;

	bmem = BIO_new(BIO_s_mem());
	if(k->privkey && args->writepriv)
	{
		r = ssh_write_privkey(bmem, k);
		priv = 1;
	}	
	else
	{
		r = ssh_write_pubkey(bmem, k);
		priv = 0;
	}
	if(r)
	{
		BIO_free(bmem);
		return r;
	}
	BIO_get_mem_ptr(bmem, &ptr);
	b64 = BIO_new(BIO_f_base64());
	if(priv)
	{
		BIO_printf(bout, "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\n");
	}
	else
	{
		BIO_printf(bout, "---- BEGIN SSH2 PUBLIC KEY ----\n");
	}
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
		BIO_printf(bout, "Comment: %d-bit %s %s key\n", k->size, kt_type_printname(k->type), (priv ? "private" : "public"));
	}
	bout = BIO_push(b64, bout);
	if(priv)
	{
		buf[0] = (SSH_MAGIC >> 24) & 0xff;
		buf[1] = (SSH_MAGIC >> 16) & 0xff;
		buf[2] = (SSH_MAGIC >> 8) & 0xff;
		buf[3] = SSH_MAGIC & 0xff;
		BIO_write(bout, buf, 4);

		switch(k->type)
		{
		case KT_RSA:
		    privtype = "if-modn{sign{rsa-pkcs1-sha1},encrypt{rsa-pkcs1v2-oaep}}";
			break;
		case KT_DSA:
			privtype = "dl-modp{sign{dsa-nist-sha1},dh{plain}}";
			break;
		default:
			privtype = "error";
			break;
		}
		ciphername = "none";		
		l = ptr->length + strlen(privtype) + 4 + strlen(ciphername) + 4 + 16;
		buf[0] = (l >> 24) & 0xff;
		buf[1] = (l >> 16) & 0xff;
		buf[2] = (l >> 8) & 0xff;
		buf[3] = l & 0xff;
		BIO_write(bout, buf, 4);
		ssh_write_str(bout, privtype);
		ssh_write_str(bout, ciphername);
		l = ptr->length + 4; /* + length of cipher parameters */
		buf[0] = (l >> 24) & 0xff;
		buf[1] = (l >> 16) & 0xff;
		buf[2] = (l >> 8) & 0xff;
		buf[3] = l & 0xff;
		/* Cipher parameters appear here if encrypted */
		BIO_write(bout, buf, 4);
		l = ptr->length;
		buf[0] = (l >> 24) & 0xff;
		buf[1] = (l >> 16) & 0xff;
		buf[2] = (l >> 8) & 0xff;
		buf[3] = l & 0xff;
		BIO_write(bout, buf, 4);
	}
	
	BIO_write(bout, ptr->data, ptr->length);

	(void) BIO_flush(bout);
	bout = BIO_pop(bout);
	BIO_free(b64);
	if(priv)
	{
		BIO_printf(bout, "---- END SSH2 ENCRYPTED PRIVATE KEY ----\n");
	}
	else
	{
		BIO_printf(bout, "---- END SSH2 PUBLIC KEY ----\n");
	}
	return 0;
}

/* Write the inner content of a private key to a BIO */
int
ssh_write_privkey(BIO *bout, kt_key *key)
{
	unsigned char *buf;
	unsigned char zbuf[4];
	size_t bufsize;

	buf = NULL;
	bufsize = 0;
	switch(key->type)
	{
	case KT_RSA:
		buf = ssh_write_bn_bits(bout, key->k.rsa->e, buf, &bufsize);
		buf = ssh_write_bn_bits(bout, key->k.rsa->d, buf, &bufsize);
		buf = ssh_write_bn_bits(bout, key->k.rsa->n, buf, &bufsize);
		buf = ssh_write_bn_bits(bout, key->k.rsa->iqmp, buf, &bufsize);
		buf = ssh_write_bn_bits(bout, key->k.rsa->q, buf, &bufsize);
		buf = ssh_write_bn_bits(bout, key->k.rsa->p, buf, &bufsize);
		break;
	case KT_DSA:
		zbuf[0] = 0;
		zbuf[1] = 0;
		zbuf[2] = 0;
		zbuf[3] = 0;
		BIO_write(bout, zbuf, 4);
		buf = ssh_write_bn_bits(bout, key->k.dsa->p, buf, &bufsize);
		buf = ssh_write_bn_bits(bout, key->k.dsa->g, buf, &bufsize);
		buf = ssh_write_bn_bits(bout, key->k.dsa->q, buf, &bufsize);
		buf = ssh_write_bn_bits(bout, key->k.dsa->pub_key, buf, &bufsize);
		buf = ssh_write_bn_bits(bout, key->k.dsa->priv_key, buf, &bufsize);
		break;
	default:
		BIO_printf(bio_err, "%s: SSH: unable to write a %s key in SSH-2 format\n", progname, kt_type_printname(key->type));
		return 1;
	}
	free(buf);
	return 0;
}

/* Write the inner contents of a public key to a BIO */
int
ssh_write_pubkey(BIO *bout, kt_key *pubkey)
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
		BIO_printf(bio_err, "%s: SSH: unable to write a %s key in SSH-2 format\n", progname, kt_type_printname(pubkey->type));
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
	BIO_write(bout, str, (int) length);
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
	BIO_write(bout, buf, (int) l);
	return buf;
}

/* Write an MPI to a BIO, but with the length being the number of bits,
 * rather than the number of bytes as with ssh_write_bn(). The memory-
 * management semantics are identical to ssh_write_bn().
 */
unsigned char *
ssh_write_bn_bits(BIO *bout, BIGNUM *num, unsigned char *buf, size_t *buflen)
{
	int bits;
	unsigned char lbuf[4];
	size_t l;

	
	bits = BN_num_bits(num);
	lbuf[0] = (bits >> 24) & 0xff;
	lbuf[1] = (bits >> 16) & 0xff;
	lbuf[2] = (bits >> 8) & 0xff;
	lbuf[3] = bits & 0xff;
	BIO_write(bout, lbuf, 4);
	l = BN_num_bytes(num) + 8;
	if(!buf || *buflen < l)
	{
		buf = realloc(buf, l);
		*buflen = l;
	}
	l = BN_bn2bin(num, buf);
	BIO_write(bout, buf, (int) l);
	return buf;
}

