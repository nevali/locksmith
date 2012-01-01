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

#define PGP_PKT_SIG                     0x02
#define PGP_PKT_PUBKEY                  0x06
#define PGP_PKT_USERID                  0x0D

#define PGP_SUB_TIMESTAMP               0x02
#define PGP_SUB_PREF_SYMMETRIC          0x0B
#define PGP_SUB_ISSUER                  0x10
#define PGP_SUB_PREF_HASH               0x15
#define PGP_SUB_PREF_COMPRESS           0x16
#define PGP_SUB_SERVERFLAGS             0x17
#define PGP_SUB_PRIMARY_USERID          0x19
#define PGP_SUB_KEYFLAGS                0x1B
#define PGP_SUB_FEATURES                0x1E

#define PGP_SIG_USERID                  0x10
#define PGP_SIG_USERID_PERSONA          0x11
#define PGP_SIG_USERID_CASUAL           0x12
#define PGP_SIG_USERID_POSITIVE         0x13
#define PGP_SIG_USERID_SELF_DEFAULT     PGP_SIG_USERID_POSITIVE

#define PGP_KT_RSA_SIGN_ENCRYPT         0x01
#define PGP_KT_RSA_ENCRYPT              0x02
#define PGP_KT_RSA_SIGN                 0x03
#define PGP_KT_ELGAMAL_ENCRYPT          0x10
#define PGP_KT_DSA                      0x11
#define PGP_KT_EC                       0x12
#define PGP_KT_ECDSA                    0x13
#define PGP_KT_ELGAMAL_ENCRYPT_SIGN     0x14
#define PGP_KT_DH                       0x15

#define PGP_ST_3DES                     0x02
#define PGP_ST_CAST5                    0x03
#define PGP_ST_AES_128                  0x07
#define PGP_ST_AES_192                  0x08
#define PGP_ST_AES_256                  0x09

#define PGP_HT_SHA1                     0x02
#define PGP_HT_SHA_256                  0x08
#define PGP_HT_SHA_384                  0x09
#define PGP_HT_SHA_512                  0x0A
#define PGP_HT_SHA_224                  0x0B

#define PGP_CT_ZIP                      0x01
#define PGP_CT_ZLIB                     0x02
#define PGP_CT_BZIP2                    0x03

#define PGP_KF_CERT                     0x01
#define PGP_KF_SIGN_DATA                0x02
#define PGP_KF_CRYPT_COMMS              0x04
#define PGP_KF_CRYPT_STORAGE            0x08
#define PGP_KF_SPLIT                    0x10
#define PGP_KF_AUTH                     0x20
#define PGP_KF_SHARED                   0x80
#define PGP_KF_DEFAULT \
	(PGP_KF_CERT|PGP_KF_SIGN_DATA|PGP_KF_CRYPT_COMMS|PGP_KF_CRYPT_STORAGE|PGP_KF_AUTH)

#define PGP_FF_MOD_DETECT               0x01
#define PGP_FF_DEFAULT                  PGP_FF_MOD_DETECT

#define PGP_SF_NO_MODIFY                0x80
#define PGP_SF_DEFAULT                  PGP_SF_NO_MODIFY

/* Handle PGP output */
int
pgp_output(kt_key *key, BIO *bout, kt_args *args)
{
	int r;

	switch(key->type)
	{
	case KT_RSA:
	case KT_DSA:
	case KT_ELGAMAL:
		break;
	default:
		BIO_printf(args->berr, "%s: PGP: Cannot write a PGP certificate for a %s key\n", progname, kt_type_printname(key->type));
		return 1;
	}
	if((r = pgp_write_pubkey_packet(bout, key)))
	{
		return r;
	}
	if(args->comment)
	{
		if(args->nosign)
		{
			pgp_write_userid_packet(bout, args->comment);
		}
		else if(key->privkey)
		{
			pgp_write_userid_packet(bout, args->comment);
			/* Sign the user ID using our key */
			pgp_write_userid_sig_packet(bout, key, args->comment, PGP_SIG_USERID_SELF_DEFAULT, args->timestamp);
		}
		else
		{
			BIO_printf(args->berr, "%s: PGP: Warning: Not writing user ID '%s' because there is no private key to generate signature and -Xnosign wasn't specified\n", progname, args->comment);
		}
	}
	return 0;
}

/* Print a PGP key fingerprint, as colon-separated octets in hexademical
 * form.
 */
int
pgp_fingerprint(kt_key *key, BIO *bout, kt_args *args)
{
	BIO *nbio;
	size_t n;
	int r;

	(void) args;

	nbio = BIO_new(BIO_s_null());
	r = pgp_write_pubkey_packet(nbio, key);
	BIO_free(nbio);
	if(r)
	{
		return r;
	}
	for(n = 0; n < key->keyid->fplen; n++)
	{
		if(n)
		{
			BIO_write(bout, ":", 1);
		}
		BIO_printf(bout, "%02x", key->keyid->fingerprint[n]);
	}
	BIO_write(bout, "\n", 1);
	return 0;
}

/* Print a PGP key ID in the form:
 * pub   <size><type>/<keyid> <created-timestamp>
 *
 * e.g.:
 * pub   1024D/DA5584122469A2C4 2001-08-09
 */
int
pgp_keyid(kt_key *key, BIO *bout, kt_args *args)
{
	BIO *nbio;
	char type;
	const struct tm *tm;
	char dbuf[16];

	(void) args;

	/* To get the key ID, create a null BIO and write the pubkey
	 *  packet to it.
	 */
	nbio = BIO_new(BIO_s_null());
	pgp_write_pubkey_packet(nbio, key);
	BIO_free(nbio);
	switch(key->type)
	{
	case KT_RSA:
		type = 'R';
		break;
	case KT_DSA:
		type = 'D';
		break;
	case KT_ELGAMAL:
		type = 'g';
		break;
	default:
		type = '?';
	}
	tm = gmtime(&(key->timestamp));
	strftime(dbuf, sizeof(dbuf) - 1, "%Y-%m-%d", tm);
	BIO_printf(bout, "pub %6d%c/%08qX %s\n", key->size, type, (unsigned long long) key->keyid->id, dbuf);
	return 0;
}

/* Write a user ID packet (tag 0x0D) to a BIO */
int
pgp_write_userid_packet(BIO *bout, const char *userid)
{
	pgp_write_packet_header(bout, PGP_PKT_USERID, strlen(userid));
	BIO_write(bout, userid, strlen(userid));
	return 0;
}

/* Write a public key packet (tag 0x06) to a BIO */
int
pgp_write_pubkey_packet(BIO *bout, kt_key *key)
{
	BIO *mem, *nbio, *mdbio;
	BUF_MEM *ptr;
	int r, i, mdlen;
	unsigned char buf[8];
	unsigned char mdbuf[EVP_MAX_MD_SIZE];

	mem = BIO_new(BIO_s_mem());
	/* Write the packet body to the memory BIO */
	if((r = pgp_write_pubkey_packet_body(mem, key, key->timestamp)))
	{
		BIO_free(mem);
		return r;
	}
	BIO_get_mem_ptr(mem, &ptr);
	/* Create a digest sink for the key ID. RFC4880 section 12.2:
	 *  "A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
	 *   followed by the two-octet packet length, followed by the entire
	 *   Public-Key packet starting with the version field.  The Key ID
	 *   is the low-order 64 bits of the fingerprint."
	 */
	nbio = BIO_new(BIO_s_null());
	mdbio = BIO_new(BIO_f_md());
	BIO_set_md(mdbio, EVP_sha1());	
	nbio = BIO_push(mdbio, nbio);
	buf[0] = 0x99;
	buf[1] = (ptr->length >> 8) & 0xff;
	buf[2] = ptr->length & 0xff;
	BIO_write(nbio, buf, 3);
	BIO_write(nbio, ptr->data, ptr->length);
	nbio = BIO_pop(nbio);
	mdlen = BIO_gets(mdbio, (char *) mdbuf, EVP_MAX_MD_SIZE);
	if(!key->keyid)
	{
		key->keyid = (kt_pgpkeyid *) malloc(sizeof(kt_pgpkeyid));
	}
	key->keyid->id = 0;
	memcpy(key->keyid->fingerprint, mdbuf, mdlen);
	key->keyid->fplen = mdlen;
	for(i = mdlen - 8; i < mdlen; i++)
	{
		key->keyid->id <<= 8;
		key->keyid->id |= (mdbuf[i] & 0xff);
	}
	BIO_free(nbio);
	BIO_free(mdbio);

	/* Write the packet header to the output BIO (tag 0x06 = pubkey) */
	r = pgp_write_packet(bout, PGP_PKT_PUBKEY, ptr);
	BIO_free(mem);
	return r;
}

/* Write a PGP public key packet (tag 0x06) body to a BIO */
int
pgp_write_pubkey_packet_body(BIO *bout, kt_key *key, time_t timestamp)
{
	unsigned char buf[8];
	unsigned long t;

	buf[0] = 4; /* Version */
	BIO_write(bout, buf, 1);
	
	t = timestamp;
	/* Key creation time (seconds since Unix epoch) */	
	buf[0] = (t >> 24) & 0xff;
	buf[1] = (t >> 16) & 0xff;
	buf[2] = (t >> 8) & 0xff;
	buf[3] = t & 0xff;
	BIO_write(bout, buf, 4);	
	return pgp_write_key_material(bout, key);
}

/* Write raw key material to a BIO */
int
pgp_write_key_material(BIO *bout, kt_key *key)
{
	unsigned char buf[1];
	
	/* Key type and type-specific material */
	switch(key->type)
	{
	case KT_RSA:
		/* 0x01 = RSA (Encrypt & Sign) */
		buf[0] = PGP_KT_RSA_SIGN_ENCRYPT;
		BIO_write(bout, buf, 1);
		pgp_write_bn(bout, key->k.rsa->n);
		pgp_write_bn(bout, key->k.rsa->e);
		break;
	case KT_DSA:
		/* 0x11 = DSA */
		buf[0] = PGP_KT_DSA;
		BIO_write(bout, buf, 1);
		pgp_write_bn(bout, key->k.dsa->p);
		pgp_write_bn(bout, key->k.dsa->q);
		pgp_write_bn(bout, key->k.dsa->g);
		pgp_write_bn(bout, key->k.dsa->pub_key);
		break;
	default:
		return -1;
	}
	return 0;
}

/* Write an SHA-1 signature packet (0x01) for a user ID */
int
pgp_write_userid_sig_packet(BIO *bout, kt_key *key, const char *userid, int sigtype, time_t timestamp)
{
	BIO *hashed, *unhashed, *target, *mem;
	BUF_MEM *hashed_ptr, *unhashed_ptr, *target_ptr, *ptr;
	int r;
	size_t l;
	unsigned char algo[16], buf[8];

	/* Hashed subpackets: key flags, preferred symmetric algorithms,
	 *   preferred hash algorithms, preferred compression algorithms,
	 *   features, key-server preferences, creation time, primary user ID
	 */
	hashed = BIO_new(BIO_s_mem());	
	pgp_write_keyflags_subpkt(hashed, PGP_KF_DEFAULT);
	algo[0] = PGP_ST_AES_256;
	algo[1] = PGP_ST_AES_192;
	algo[2] = PGP_ST_AES_128;
	algo[3] = PGP_ST_CAST5;
	algo[4] = PGP_ST_3DES;
	pgp_write_prefsymmetric_subpkt(hashed, algo, 5);
	algo[0] = PGP_HT_SHA_256;
	algo[1] = PGP_HT_SHA1;
	algo[2] = PGP_HT_SHA_384;
	algo[3] = PGP_HT_SHA_512;
	algo[4] = PGP_HT_SHA_224;
	pgp_write_prefhash_subpkt(hashed, algo, 5);
	algo[0] = PGP_CT_ZLIB;
	algo[1] = PGP_CT_BZIP2;
	algo[2] = PGP_CT_ZIP;
	pgp_write_prefcomp_subpkt(hashed, algo, 3);
	pgp_write_features_subpkt(hashed, PGP_FF_DEFAULT);
	pgp_write_serverflags_subpkt(hashed, PGP_SF_DEFAULT);
	pgp_write_timestamp_subpkt(hashed, timestamp);
	pgp_write_primary_subpkt(hashed, 1);
	/* Unhashed subpackets: issuer key ID */
	unhashed = BIO_new(BIO_s_mem());
	if(key->keyid)
	{
		/* Historically, the issuer ID has always been written to
		 * the unhashed portion. It's not especially clear why.
		 */
		pgp_write_issuer_subpkt(unhashed, key->keyid);
	}
	/* Generate the target-to-be-hashed from the key and userid string
	 * RFC4880 section 5.2.4 states:
	 * "A V4 certification hashes the constant 0xB4 for User ID
	 *  certifications or the constant 0xD1 for User Attribute
	 *  certifications, followed by a four-octet number giving
	 *  the length of the User ID or User Attribute data, and
	 *  then the User ID or User Attribute data."
	 */
	target = BIO_new(BIO_s_mem()); 
	/* Add the pubkey  */
	mem = BIO_new(BIO_s_mem());
	/* Write the packet body to the memory BIO */
	pgp_write_pubkey_packet_body(mem, key, key->timestamp);
	BIO_get_mem_ptr(mem, &ptr);
	/* Create a digest sink for the key ID. RFC4880 section 12.2:
	 *  "A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
	 *   followed by the two-octet packet length, followed by the entire
	 *   Public-Key packet starting with the version field.  The Key ID
	 *   is the low-order 64 bits of the fingerprint."
	 */
	buf[0] = 0x99;
	buf[1] = (ptr->length >> 8) & 0xff;
	buf[2] = ptr->length & 0xff;
	BIO_write(target, buf, 3);
	BIO_write(target, ptr->data, ptr->length);
	BIO_free(mem);

	/* Add the prefixed userid */
	l = strlen(userid);
	buf[0] = 0xb4;
	buf[1] = (l >> 24) & 0xff;
	buf[2] = (l >> 16) & 0xff;
	buf[3] = (l >> 8) & 0xff;
	buf[4] = l & 0xff;
	BIO_write(target, buf, 5);
	BIO_write(target, userid, l);
	
	/* Write the signature */
	BIO_get_mem_ptr(hashed, &hashed_ptr);
	BIO_get_mem_ptr(unhashed, &unhashed_ptr);
	BIO_get_mem_ptr(target, &target_ptr);
	r = pgp_write_sig_packet(bout, sigtype, key, target_ptr, hashed_ptr, unhashed_ptr);
	BIO_free(target);
	BIO_free(hashed);
	BIO_free(unhashed);
	return r;
}

/* Write an SHA-1 signature packet (tag = 0x01) */
int
pgp_write_sig_packet(BIO *bout, int sigtype, kt_key *key, BUF_MEM *target, BUF_MEM *hsub, BUF_MEM *uhsub)
{
	BIO *mem;
	BUF_MEM *ptr;
	int r;

	mem = BIO_new(BIO_s_mem());
	/* Write the packet body to the memory BIO */
	if((r = pgp_write_sig_packet_body(mem, sigtype, key, target, hsub, uhsub)))
	{
		BIO_free(mem);
		return r;
	}
	BIO_get_mem_ptr(mem, &ptr);
	/* Write the packet header to the output BIO (tag 0x02 = signature) */
	pgp_write_packet(bout, PGP_PKT_SIG, ptr);
	BIO_free(mem);
	return 0;
}

/* Write an SHA-1 signature packet body to a BIO */
int
pgp_write_sig_packet_body(BIO *bout, int sigtype, kt_key *key, BUF_MEM *target, BUF_MEM *hsub, BUF_MEM *uhsub)
{
	BIO *dbio, *nbio;
	unsigned char buf[32];
	unsigned char mdbuf[EVP_MAX_MD_SIZE];
	size_t mdlen, hashedlen;
	int r;

	hashedlen = 0;
	dbio = BIO_new(BIO_f_md());
	BIO_set_md(dbio, EVP_sha1());
	/* Create a null BIO and push the digest BIO onto it to begin computing
	 * the hash.
	 */
	nbio = BIO_new(BIO_s_null());
	if(target && target->length)
	{
		nbio = BIO_push(dbio, nbio);
		BIO_write(nbio, target->data, target->length);
		nbio = BIO_pop(nbio);
	}
	/* Push the digest BIO filter onto the output BIO */
	bout = BIO_push(dbio, bout);
	/* Write the version number */
	buf[0] = 0x04;
	BIO_write(bout, buf, 1);
	/* Write the signature type */
	buf[0] = sigtype;
	BIO_write(bout, buf, 1);
	/* Write the pubkey type */
	switch(key->type)
	{
	case KT_RSA:
		buf[0] = PGP_KT_RSA_SIGN_ENCRYPT;
		break;
	case KT_DSA:
		buf[0] = PGP_KT_DSA;
		break;
	default:
		return -1;
	}
	BIO_write(bout, buf, 1);
	/* Write the digest algorithm */
	buf[0] = PGP_HT_SHA1;
	BIO_write(bout, buf, 1);	
	hashedlen += 4;
	/* Write the hashed subpackets' length */
	if(hsub)
	{		
		buf[0] = (hsub->length >> 8) & 0xff;
		buf[1] = hsub->length & 0xff;
	}
	else
	{
		buf[0] = buf[1] = 0;
	}
	hashedlen += 2;
	BIO_write(bout, buf, 2);
	/* Write the hashed subpackets, if any */
	if(hsub && hsub->length)
	{
		BIO_write(bout, hsub->data, hsub->length);
		hashedlen += hsub->length;
	}
	/* Remove the BIO filter to stop hashing the output */
	bout = BIO_pop(bout);
	/* Write the unhashed subpackets' length */
	if(uhsub)
	{
		buf[0] = (uhsub->length >> 8) & 0xff;
		buf[1] = uhsub->length & 0xff;
	}
	else
	{
		buf[0] = buf[1] = 0;
	}
	BIO_write(bout, buf, 2);
	/* Write the unhashed subpackets, if any */
	if(uhsub && uhsub->length)
	{
		BIO_write(bout, uhsub->data, uhsub->length);
	}
	/* Add the v4 trailer (RFC4880 section 5.2.4) to the hash */
	nbio = BIO_push(dbio, nbio);
	buf[0] = 0x04; /* version */
	buf[1] = 0xff;
	buf[2] = (hashedlen >> 24) & 0xff;
	buf[3] = (hashedlen >> 16) & 0xff;
	buf[4] = (hashedlen >> 8) & 0xff;
	buf[5] = hashedlen & 0xff;
	BIO_write(nbio, buf, 6);
	nbio = BIO_pop(nbio);
	/* Retrieve the hash */
	mdlen = BIO_gets(dbio, (char *) mdbuf, EVP_MAX_MD_SIZE);
	/* Write the left 16 bits of the hash value */
	BIO_write(bout, mdbuf, 2);
	r = pgp_write_digest_signature(bout, PGP_HT_SHA1, key, mdbuf, mdlen);
	BIO_free(nbio);
	return r;
}

/* Write the signature MPI for a digest to a BIO */
int
pgp_write_digest_signature(BIO *bout, int hash, kt_key *key, const unsigned char *digest, size_t digestlen)
{
	unsigned char buf[2];
	int r, siglen, sigbits, nid;
	unsigned char *sigbuf;
	DSA_SIG *sig;

	r = -1;
	sigbuf = NULL;
	switch(hash)
	{
	case PGP_HT_SHA1:
		nid = NID_sha1;
		break;
	default:
		BIO_printf(bio_err, "%s: PGP: Unable to generate signature for hash algorithm %d\n", progname, hash);
		return -1;
	}
	switch(key->type)
	{
	case KT_RSA:
		siglen = RSA_size(key->k.rsa);
		sigbuf = (unsigned char *) malloc(siglen);
		if(RSA_sign(nid, digest, digestlen, sigbuf, (unsigned int *) &siglen, key->k.rsa))
		{
			r = 0;
		}
		if(r)
		{
			ERR_print_errors_fp(stderr);
		}
		break;
	case KT_DSA:
		if((sig = DSA_do_sign(digest, digestlen, key->k.dsa)))
		{
			r = 0;
			pgp_write_bn(bout, sig->r);
			pgp_write_bn(bout, sig->s);
			DSA_SIG_free(sig);
		}
		else
		{
			ERR_print_errors_fp(stderr);
		}
		break;
	default:
		BIO_printf(bio_err, "%s: PGP: Unable to produce a signature using a %s key\n", progname, kt_type_printname(key->type));
	}
	if(r == 0)
	{
		if(sigbuf)
		{
			sigbits = siglen * 8;
			buf[0] = (sigbits >> 8) & 0xff;
			buf[1] = sigbits & 0xff;
			BIO_write(bout, buf, 2);
			BIO_write(bout, sigbuf, siglen);
		}
	}
	free(sigbuf);
	return r;
}

/* Write a PGP MPI to a BIO */
int
pgp_write_bn(BIO *bout, BIGNUM *bn)
{
	static unsigned char *mbuf = NULL;
	static size_t mbufsize = 0;	
	size_t n;
	unsigned char buf[2], *p;
	
	n = BN_num_bits(bn);
	buf[0] = (n >> 8) & 0xff;
	buf[1] = n & 0xff;
	BIO_write(bout, buf, 2);
	/* XXX This could be optimised to use BUF_MEM_grow() if we know
	 * that bout is a memory BIO
	 */
	n = BN_num_bytes(bn);
	if(mbufsize < n)
	{
		if(!(p = realloc(mbuf, n)))
		{
			return -1;
		}
		mbuf = p;
		mbufsize = n;
	}
	n = BN_bn2bin(bn, mbuf);
	BIO_write(bout, mbuf, n);
	return 0;
}

/* Write a new-format OpenPGP packet header to a BIO */
int
pgp_write_packet_header(BIO *bout, int tag, int length)
{
	unsigned char buf[8];
	
	buf[0] = 0x80 | 0x40;
	buf[0] |= tag;
	BIO_write(bout, buf, 1);
	if(length < 192)
	{
		buf[0] = length & 0xff;
		BIO_write(bout, buf, 1);
	}
	else if(length < 8383)
	{
		length -= 192;
		buf[0] = (length /256) + 192;
		buf[1] = length % 256;
		BIO_write(bout, buf, 2);
	}
	else
	{
		buf[0] = 0xff;
		buf[1] = (length >> 24) & 0xff;
		buf[2] = (length >> 16) & 0xff;
		buf[3] = (length >> 8) & 0xff;
		buf[4] = length & 0xff;
		BIO_write(bout, buf, 5);
	}
	return 0;
}

/* Write a complete packet to a BIO */
int
pgp_write_packet(BIO *bout, int tag, BUF_MEM *buffer)
{
	int r;

	if((r = pgp_write_packet_header(bout, tag, buffer->length)))
	{
		return r;
	}
	BIO_write(bout, buffer->data, buffer->length);
	return 0;
}

/* Write a subpacket to a BIO */
int
pgp_write_subpkt(BIO *bout, int tag, BUF_MEM *buffer)
{
	int r;

	if((r = pgp_write_subpkt_header(bout, tag, buffer->length)))
	{
		return r;
	}
	BIO_write(bout, buffer->data, buffer->length);
	return 0;
}

/* Write a subpacket header to a BIO */
int
pgp_write_subpkt_header(BIO *bout, int tag, int length)
{
	unsigned char buf[8];
	
	/* RFC4880 - 5.2.3.1.  Signature Subpacket Specification
	 * "The length includes the type octet but not this length." - so, we
	 * must add the size of the type octet (which is an octet, obviously).
	 */
	length++;

	if(length < 192)
	{
		buf[0] = length & 0xff;
		BIO_write(bout, buf, 1);
	}
	else if(length < 8383)
	{
		length -= 192;
		buf[0] = (length /256) + 192;
		buf[1] = length % 256;
		BIO_write(bout, buf, 2);
	}
	else
	{
		buf[0] = 0xff;
		buf[1] = (length >> 24) & 0xff;
		buf[2] = (length >> 16) & 0xff;
		buf[3] = (length >> 8) & 0xff;
		buf[4] = length & 0xff;
		BIO_write(bout, buf, 5);
	}
	buf[0] = tag;
	BIO_write(bout, buf, 1);
	return 0;
}

/* Write a "Key flags" subpacket to a BIO */
int
pgp_write_keyflags_subpkt(BIO *bout, int flags)
{
	int r;
	unsigned char buf[1];

	if((r = pgp_write_subpkt_header(bout, PGP_SUB_KEYFLAGS, 1)))
	{
		return r;
	}
	buf[0] = flags & 0xff;
	BIO_write(bout, buf, 1);
	return 0;
}

/* Write a "Preferred symmetric algorithms" subpacket to a BIO */
int
pgp_write_prefsymmetric_subpkt(BIO *bout, unsigned char *algo, size_t nalgo)
{
	int r;

	if((r = pgp_write_subpkt_header(bout, PGP_SUB_PREF_SYMMETRIC, nalgo)))
	{
		return r;
	}
	BIO_write(bout, algo, nalgo);
	return 0;
}

/* Write a "Preferred hash algorithms" subpacket to a BIO */
int
pgp_write_prefhash_subpkt(BIO *bout, unsigned char *algo, size_t nalgo)
{
	int r;

	if((r = pgp_write_subpkt_header(bout, PGP_SUB_PREF_HASH, nalgo)))
	{
		return r;
	}
	BIO_write(bout, algo, nalgo);
	return 0;
}

/* Write a "Preferred compression algorithms" subpacket to a BIO */
int
pgp_write_prefcomp_subpkt(BIO *bout, unsigned char *algo, size_t nalgo)
{
	int r;

	if((r = pgp_write_subpkt_header(bout, PGP_SUB_PREF_COMPRESS, nalgo)))
	{
		return r;
	}
	BIO_write(bout, algo, nalgo);
	return 0;
}

/* Write a "Features" subpacket to a BIO */
int
pgp_write_features_subpkt(BIO *bout, int flags)
{
	int r;
	unsigned char buf[1];

	if((r = pgp_write_subpkt_header(bout, PGP_SUB_FEATURES, 1)))
	{
		return r;
	}
	buf[0] = flags & 0xff;
	BIO_write(bout, buf, 1);
	return 0;
}

/* Write a "Key Server Flags" subpacket to a BIO */
int
pgp_write_serverflags_subpkt(BIO *bout, int flags)
{
	int r;
	unsigned char buf[1];

	if((r = pgp_write_subpkt_header(bout, PGP_SUB_SERVERFLAGS, 1)))
	{
		return r;
	}
	buf[0] = flags & 0xff;
	BIO_write(bout, buf, 1);
	return 0;
}

/* Write a "Primary User ID" subpacket to a BIO */
int
pgp_write_primary_subpkt(BIO *bout, int value)
{
	int r;
	unsigned char buf[1];

	if((r = pgp_write_subpkt_header(bout, PGP_SUB_PRIMARY_USERID, 1)))
	{
		return r;
	}
	buf[0] = (value ? 1 : 0);
	BIO_write(bout, buf, 1);
	return 0;
}

/* Write a "Signature creation time" subpacket to a BIO */
int
pgp_write_timestamp_subpkt(BIO *bout, time_t timestamp)
{
	int r;
	unsigned char buf[4];
	unsigned long t;

	if((r = pgp_write_subpkt_header(bout, PGP_SUB_TIMESTAMP, 4)))
	{
		return r;
	}
	t = (unsigned long) timestamp;
	buf[0] = (t >> 24) & 0xff;
	buf[1] = (t >> 16) & 0xff;
	buf[2] = (t >> 8) & 0xff;
	buf[3] = t & 0xff;
	BIO_write(bout, buf, 4);
	return 0;
}

/* Write an "Issuer key ID" subpacket to a BIO */
int
pgp_write_issuer_subpkt(BIO *bout, kt_pgpkeyid *keyid)
{
	int r;
	unsigned char buf[8];

	if((r = pgp_write_subpkt_header(bout, PGP_SUB_ISSUER, 8)))
	{
		return r;
	}
	buf[0] = (keyid->id >> 56) & 0xff;
	buf[1] = (keyid->id >> 48) & 0xff;
	buf[2] = (keyid->id >> 40) & 0xff;
	buf[3] = (keyid->id >> 32) & 0xff;
	buf[4] = (keyid->id >> 24) & 0xff;
	buf[5] = (keyid->id >> 16) & 0xff;
	buf[6] = (keyid->id >> 8) & 0xff;
	buf[7] = keyid->id & 0xff;
	BIO_write(bout, buf, 8);
	return 0;	
}
