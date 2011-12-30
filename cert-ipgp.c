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

/* Write an IPGP CERT record [RFC4398] (type 6) */
int
cert_ipgp_output(kt_key *key, BIO *bout, kt_args *args)
{
	const char *domain = "example.com.";
	const char *url = NULL;
	size_t len, n;
	const char *t;
	BIO *nbio;
	int r;

	if(args->domain && args->domain[0])
	{
		domain = args->domain;
	}
	t = strchr(domain, 0);
	t--;
	if(*t != '.')
	{
		BIO_printf(args->berr, "%s: CERT-IPGP: Domain name '%s' does not include a terminating period, which is probably not what you want\n", progname, domain);
	}
	nbio = BIO_new(BIO_s_null());
	r = pgp_write_pubkey_packet(nbio, key);
	BIO_free(nbio);
	if(r)
	{
		return -1;
	}
	if(!key->keyid || !key->keyid->fplen)
	{
		BIO_printf(args->berr, "%s: CERT-IPGP: Unable to determine fingerprint of key\n", progname);
		return -1;
	}
	/* For compatibility with old DNS server software, write this as
	 * a "TYPE37" [RFC3597] record rather than a "CERT" record.
	 */
	len = 2 + 2 + 1 + 1 + key->keyid->fplen;
	if(url && *url)
	{
		len += strlen(url);
	}
	BIO_printf(bout, "%s IN TYPE37 \\# %u %04x %04x %02x ", domain, (unsigned int) len, 6, 0, (unsigned int) key->keyid->fplen);
	for(n = 0; n < key->keyid->fplen; n++)
	{
		BIO_printf(bout, "%02x", key->keyid->fingerprint[n] & 0xff);
	}
	if(url && *url)
	{
		BIO_write(bout, " ", 1);
		for(; *url; url++)
		{
			BIO_printf(bout, "%02x", *url & 0xff);
		}
	}			
	BIO_write(bout, "\n", 1);
	return 0;
}
