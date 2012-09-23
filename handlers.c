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

static kt_handler_entry handlers[] = 
{
	{ "text", "plain text", "Readable information about the key's contents", NULL, NULL, text_output, NULL, NULL, 0 },
	{ "x509", "X.509", "PEM-encoded X.509 certificate", x509_detect, x509_input, NULL, x509_fingerprint, x509_fingerprint, 1 },
	{ "pem", "PEM", "Privacy Enhanced Mail (PEM) format key", pem_detect, pem_input, pem_output, x509_fingerprint, x509_fingerprint, 0 },
	{ "der", "DER", "ASN.1 Distinguished Encoding Rules (DER) format key", NULL, der_input, der_output, x509_fingerprint, x509_fingerprint, 0 },
	{ "openssh", "OpenSSH", "OpenSSH key format", NULL, NULL, openssh_output, NULL, ssh_fingerprint, 0 },
	{ "ssh2", "SSH-2", "SSH-2 (RFC4716) key format", NULL, NULL, ssh_output, NULL, ssh_fingerprint, 0 },
	{ "pgp", "PGP", "OpenPGP (RFC4880) version 4 key format", NULL, NULL, pgp_asc_output, pgp_keyid, pgp_fingerprint, 1 },
	{ "pgp-bin", "PGP", "OpenPGP (RFC4880) version 4 binary key format", NULL, NULL, pgp_output, pgp_keyid, pgp_fingerprint, 1 },
	{ "rdfxml", "RDF/XML", "RDF/XML format", NULL, NULL, rdfxml_output, NULL, NULL, 0 },
	{ "turtle", "Turtle", "RDF (Turtle) format", NULL, NULL, turtle_output, NULL, NULL, 0 },
	{ "dnssec", "DNSSEC", "DNSSEC key format", NULL, NULL, dnssec_output, dnssec_keyid, NULL, 0 },
	{ "ipgp", "CERT IPGP", "DNS CERT record (RFC4938) type 6 (indirect PGP)", NULL, NULL, cert_ipgp_output, pgp_keyid, pgp_fingerprint, 1 },
	{ "pka", "PKA", "DNS PKA record", NULL, NULL, pka_output, pgp_keyid, pgp_fingerprint, 1 },	
	{ "pkcs8", "PKCS#8", "PEM-format PKCS#8 keypairs", pkcs8_detect, pkcs8_input, pkcs8_output, x509_fingerprint, x509_fingerprint, 0 },
	{ "sshfp", "SSHFP", "SSHFP record (RFC4255)", NULL, NULL, sshfp_output, NULL, ssh_fingerprint, 0 },
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};

/* Return the list of handlers */
kt_handler_entry *
kt_handlers(void)
{
	return handlers;
}

/* Locate a handler entry by name */
kt_handler_entry *
kt_handler_locate(const char *name)
{
	size_t c;
	
	for(c = 0; handlers[c].name; c++)
	{
		if(!strcmp(handlers[c].name, name))
		{
			return &(handlers[c]);
		}
	}
	return NULL;
}

int
kt_detect_match(const char *bp, size_t l, kt_match_string *matchers, kt_key *k, kt_args *args)
{
	size_t c;
	const char *p;
	int t;

	(void) k;

	args->detect_match_entry = -1;
	for(c = 0; matchers[c].match; c++)
	{
		matchers[c].len = strlen(matchers[c].match);
	}
	p = bp;
	do
	{
		p = memchr(p, '-', l - (bp - p));
		if(!p)
		{
			break;
		}
		t = 0;
		for(c = 0; matchers[c].match; c++)
		{
			if(l - (bp - p) < matchers[c].len)
			{
				continue;
			}
			t = 1;
			if(!memcmp(matchers[c].match, p, matchers[c].len))
			{
				args->detect_match_entry = (ssize_t) c;
				if(matchers[c].privkey)
				{
					args->readpriv = 1;
				}
				return (int) c + 1;
			}
		}
		if(!t)
		{
			/* Remaining buffer was too short to amtch anything */
			break;
		}
		p++;
	}
	while(1);
	return 0;
}

int
kt_detect_match_bio(BIO *bin, kt_match_string *matchers, kt_key *k, kt_args *args)
{
	char *bp;
	ssize_t l;
	int c;

	bp = (char *) malloc(KT_READ_BUFFER_SIZE);
	l = BIO_read(bin, bp, KT_READ_BUFFER_SIZE);
	if(l < 0)
	{
		free(bp);
		return -1;
	}
	c = kt_detect_match(bp, l, matchers, k, args);
	free(bp);
	return c;
}

