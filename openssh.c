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
openssh_output(kt_key *k, BIO *bout, kt_args *args)
{
	const char *ktype;
	BIO *b64;

	if(k->privkey && args->writepriv)
	{
		/* An OpenSSH private key is stored in PEM format */
		return pem_output(k, bout, args);
	}
	switch(k->type)
	{
	case KT_RSA:
		ktype = "ssh-rsa";
		break;
	case KT_DSA:
		ktype = "ssh-dss";
		break;
	default:
		BIO_printf(args->berr, "openssh: unable to write a %s key in OpenSSH format\n", kt_type_printname(k->type));
		return 1;
	}
	b64 = BIO_new(BIO_f_base64());
	BIO_printf(bout, "%s ", ktype);
	bout = BIO_push(b64, bout);
	BIO_set_flags(bout, BIO_FLAGS_BASE64_NO_NL);
	ssh_write_pubkey(bout, k);
	(void) BIO_flush(bout);
	bout = BIO_pop(bout);
	if(args->comment)
	{
		BIO_printf(bout, " %s\n", args->comment);
	}
	else
	{
		BIO_write(bout, "\n", 1);
	}
	BIO_free(b64);
	return 0;
}
