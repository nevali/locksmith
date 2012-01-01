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

#ifndef P_KEYTOOL_H_
# define P_KEYTOOL_H_                   1

# define _XOPEN_SOURCE

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <ctype.h>

# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# endif

# ifdef HAVE_INTTYPES_H
# include <inttypes.h>
# endif

# ifdef HAVE_STDINT_H
# include <stdint.h>
# endif

# ifdef TIME_WITH_SYS_TIME
#  include <sys/time.h>
#  include <time.h>
# else
#  ifdef HAVE_SYS_TIME_H
#   include <sys/time.h>
#  else
#   include <time.h>
#  endif
# endif

# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif

# ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
# endif

# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# endif

# include <openssl/err.h>
# include <openssl/buffer.h>
# include <openssl/bn.h>
# include <openssl/bio.h>
# include <openssl/evp.h>
# include <openssl/pem.h>
# include <openssl/rsa.h>
# include <openssl/engine.h>
# include <openssl/objects.h>
# include <openssl/x509.h>

# ifndef MIN
#  define MIN(a, b)                     ((a) < (b) ? (a) : (b))
# endif
# ifndef MIN3
#  define MIN3(a, b, c)                 MIN(a, MIN(b, c))
# endif

typedef struct kt_key_s kt_key;
typedef struct kt_args_s kt_args;
typedef struct kt_pgpkeyid_s kt_pgpkeyid;
typedef struct kt_handler_entry_s kt_handler_entry;
typedef struct kt_keytype_entry_s kt_keytype_entry;

typedef enum
{
	KT_ERROR = -1,
	KT_UNKNOWN = 0,
	KT_RSA,
	KT_DSAPARAM,
	KT_DSA,
	KT_ELGAMAL,
	KT_ECC,
	KT_DHPARAM,
	KT_DH
} kt_keytype;

struct kt_key_s
{
	kt_keytype type;
	int privkey;
	int size;
	time_t timestamp;
	union
	{
		RSA *rsa;
		DSA *dsa;
		DH *dh;
	} k;
	kt_pgpkeyid *keyid;
};

struct kt_args_s
{
	BIO *berr;
	const char *infile;
	const char *outfile;
	kt_handler_entry *input_handler;
	kt_handler_entry *output_handler;
	int noout;
	int keyid;
	int fingerprint;
	int readpriv;
	int writepriv;
	int generate;
	int bits;
	unsigned long exponent;   
	const char *comment;
	time_t timestamp;
	int nosign;
	int ts_explicit;
	int kts_explicit;
	const char *domain;
};

struct kt_pgpkeyid_s
{
	uint64_t id;
	unsigned char fingerprint[EVP_MAX_MD_SIZE];
	size_t fplen;
};

typedef int (*kt_input_handler)(kt_key *key, BIO *bin, kt_args *args);
typedef int (*kt_output_handler)(kt_key *key, BIO *bout, kt_args *args);
typedef int (*kt_keyid_handler)(kt_key *key, BIO *bout, kt_args *args);
typedef int (*kt_fingerprint_handler)(kt_key *key, BIO *bout, kt_args *args);

struct kt_handler_entry_s
{
	const char *name;
	const char *printname;
	const char *desc;
	kt_input_handler input;
	kt_output_handler output;
	kt_keyid_handler keyid;
	kt_fingerprint_handler fingerprint;
};

struct kt_keytype_entry_s
{
	const char *name;
	const char *printname;
	const char *desc;
	kt_keytype type;
};

extern const char *progname;
extern BIO *bio_err;

kt_handler_entry *kt_handlers(void);
kt_handler_entry *kt_handler_locate(const char *name);

extern int kt_process_args(int argc, char **argv, kt_args *args, kt_key *key);

extern kt_keytype_entry *kt_types(void);
extern kt_keytype kt_type_locate(const char *str);
extern const char *kt_type_printname(kt_keytype type);
extern kt_keytype kt_type_from_evptype(int t);
extern kt_keytype kt_type_from_evp(EVP_PKEY *pkey);
extern const char *kt_evptype_printname(EVP_PKEY *pkey);

extern int kt_generate(kt_key *key, kt_args *args);
extern int kt_get_public(kt_key *key);
extern int kt_get_size(kt_key *key);
extern EVP_PKEY *kt_key_to_evp(kt_key *key);
extern int kt_key_from_evp(EVP_PKEY *pkey, kt_key *key);

extern int text_output(kt_key *key, BIO *bout, kt_args *args);

extern int pem_input(kt_key *key, BIO *bin, kt_args *args);
extern int pem_output(kt_key *key, BIO *bout, kt_args *args);

extern int der_input(kt_key *key, BIO *bout, kt_args *args);
extern int der_output(kt_key *key, BIO *bout, kt_args *args);

extern int openssh_output(kt_key *key, BIO *bout, kt_args *args);

extern int ssh_output(kt_key *pubkey, BIO *bout, kt_args *args);
extern int ssh_fingerprint(kt_key *key, BIO *bout, kt_args *args);
extern int ssh_write_pubkey_bio(kt_key *pubkey, BIO *bout);
extern int ssh_write_str(BIO *bout, const char *str);
extern unsigned char *ssh_write_bn(BIO *bout, BIGNUM *num, unsigned char *buf, size_t *buflen);

extern int pgp_output(kt_key *key, BIO *bout, kt_args *args);
extern int pgp_keyid(kt_key *key, BIO *bout, kt_args *args);
extern int pgp_fingerprint(kt_key *key, BIO *bout, kt_args *args);

extern int pgp_write_pubkey_packet(BIO *bout, kt_key *key);
extern int pgp_write_pubkey_packet_body(BIO *bout, kt_key *key, time_t timestamp);
extern int pgp_write_userid_packet(BIO *bout, const char *userid);
extern int pgp_write_userid_sig_packet(BIO *bout, kt_key *key, const char *userid, int sigtype, time_t timestamp);
extern int pgp_write_sig_packet(BIO *bout, int sigtype, kt_key *key, BUF_MEM *target, BUF_MEM *hsub, BUF_MEM *uhsub);
extern int pgp_write_sig_packet_body(BIO *bout, int sigtype, kt_key *key, BUF_MEM *target, BUF_MEM *hsub, BUF_MEM *uhsub);
extern int pgp_write_keyflags_subpkt(BIO *bout, int flags);
extern int pgp_write_prefsymmetric_subpkt(BIO *bout, unsigned char *algo, size_t nalgo);
extern int pgp_write_prefhash_subpkt(BIO *bout, unsigned char *algo, size_t nalgo);
extern int pgp_write_prefcomp_subpkt(BIO *bout, unsigned char *algo, size_t nalgo);
extern int pgp_write_serverflags_subpkt(BIO *bout, int flags);
extern int pgp_write_features_subpkt(BIO *bout, int flags);
extern int pgp_write_primary_subpkt(BIO *bout, int value);
extern int pgp_write_timestamp_subpkt(BIO *bout, time_t timestamp);
extern int pgp_write_issuer_subpkt(BIO *bout, kt_pgpkeyid *keyid);

extern int pgp_write_bn(BIO *bout, BIGNUM *bn);
extern int pgp_write_key_material(BIO *bout, kt_key *key);
extern int pgp_write_packet(BIO *bout, int tag, BUF_MEM *buffer);
extern int pgp_write_packet_header(BIO *bout, int tag, int length);
extern int pgp_write_subpkt_header(BIO *bout, int tag, int length);
extern int pgp_write_digest_signature(BIO *bout, int hash, kt_key *key, const unsigned char *digest, size_t digestlen);

extern int rdfxml_output(kt_key *key, BIO *bout, kt_args *args);

extern int turtle_output(kt_key *key, BIO *bout, kt_args *args);

extern int dnssec_output(kt_key *key, BIO *bout, kt_args *args);
extern const char *dnssec_alg_printname(int alg);
extern int dnssec_write_public(BIO *bout, kt_key *key, int alg, const char *domain, int flags, int version);
extern int dnssec_write_private(BIO *bout, kt_key *key, int alg);
extern int dnssec_write_bn_base64(BIO *bout, const char *prefix, BIGNUM *num, const char *suffix);
extern int dnssec_write_bn_fixed(BIO *bout, BIGNUM *bn, unsigned char *buf, size_t nbytes);

extern int cert_ipgp_output(kt_key *key, BIO *bout, kt_args *args);

extern int pka_output(kt_key *key, BIO *bout, kt_args *args);

extern int pkcs8_output(kt_key *key, BIO *bout, kt_args *args);

#endif /*!P_KEYTOOL_H_*/
