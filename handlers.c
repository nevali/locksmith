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
	{ "text", "plain text", "Readable information about the key's contents", NULL, text_output, NULL, NULL },
	{ "pem", "PEM", "Privacy Enhanced Mail (PEM) format", pem_input, pem_output, NULL, NULL },
	{ "der", "DER", "ASN.1 Distinguished Encoding Rules (DER) format", der_input, der_output, NULL, NULL },
	{ "openssh", "OpenSSH", "OpenSSH key format", NULL, openssh_output, NULL, ssh_fingerprint },
	{ "ssh2", "SSH-2", "SSH-2 (RFC4716) key format", NULL, ssh_output, NULL, ssh_fingerprint },
	{ "pgp", "PGP", "OpenPGP (RFC4880) version 4 key format", NULL, pgp_output, pgp_keyid, pgp_fingerprint },
	{ "rdfxml", "RDF/XML", "RDF/XML format", NULL, rdfxml_output, NULL, NULL },
	{ "turtle", "Turtle", "RDF (Turtle) format", NULL, turtle_output, NULL, NULL },
	{ "dnssec", "DNSSEC", "DNSSEC key format", NULL, dnssec_output, dnssec_keyid, NULL },
	{ "ipgp", "CERT IPGP", "DNS CERT record (RFC4938) type 6 (indirect PGP)", NULL, cert_ipgp_output, NULL, NULL },
	{ "pka", "PKA", "DNS PKA record", NULL, pka_output, NULL, NULL },	
	{ "pkcs8", "PKCS#8", "PEM-format PKCS#8 keypairs", pkcs8_input, pkcs8_output, NULL, NULL },
	{ "sshfp", "SSHFP", "SSHFP record (RFC4255)", NULL, sshfp_output, NULL, NULL },
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL }	
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
