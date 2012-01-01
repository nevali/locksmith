/*
 * Copyright 2012 Mo McRoberts.
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

/* Write an SSHFP record (RFC4255) */
int
sshfp_output(kt_key *key, BIO *bout, kt_args *args)
{
	const char *domain = "example.com.";
	unsigned char digest[EVP_MAX_MD_SIZE];
	ssize_t mdlen, n;
	const char *t;
	int alg, fptype;

	fptype = 1; /* SHA-1 */
	if(args->domain && args->domain[0])
	{
		domain = args->domain;
	}
	t = strchr(domain, 0);
	t--;
	if(*t != '.')
	{
		BIO_printf(args->berr, "%s: SSHFP: Domain name '%s' does not include a terminating period, which is probably not what you want\n", progname, domain);
	}
	switch(key->type)
	{
	case KT_RSA:
		alg = 1;
		break;
	case KT_DSA:
		alg = 2;
		break;
	default:
		BIO_printf(args->berr, "%s: SSHFP: Unable to generate an SSHFP record for a %s key\n", progname, kt_type_printname(key->type));
		return -1;
	}
	mdlen = ssh_calc_fp(key, EVP_sha1(), digest);
	if(mdlen < 0)
	{
		BIO_printf(args->berr, "%s: SSHFP: Unable to generate an SSHFP record for a %s key\n", progname, kt_type_printname(key->type));
		return -1;
	}
	BIO_printf(bout, "%s IN SSHFP %d %d ", domain, alg, fptype);
	for(n = 0; n < mdlen; n++)
	{
		BIO_printf(bout, "%02x", digest[n] & 0xff);
	}
	BIO_write(bout, "\n", 1);
	return 0;
}
