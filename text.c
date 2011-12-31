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
text_output(kt_key *key, BIO *bout, kt_args *args)
{
	(void) args;

	switch(key->type)
	{
	case KT_RSA:
		fprintf(stderr, "RSA %s key\n", (key->privkey ? "private" : "public"));
		RSA_print(bout, key->k.rsa, 0);
		break;
	case KT_DSA:
		fprintf(stderr, "DSA %s key\n", (key->privkey ? "private" : "public"));
		DSA_print(bout, key->k.dsa, 0);
		break;
	case KT_DSAPARAM:
		fprintf(stderr, "DSA parameters\n");
		DSAparams_print(bout, key->k.dsa);
		break;
	case KT_DHPARAM:
		fprintf(stderr, "DH parameters\n");
		DSAparams_print(bout, key->k.dsa);
		break;
	default:
		fprintf(stderr, "text: Unable to print a %s key\n", kt_type_printname(key->type));
		return 1;
	}
	return 0;
}
