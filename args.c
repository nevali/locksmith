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

static int process_extended_opt(const char *name, const char *value, kt_args *args);
static int process_usage_opt(const char *str, kt_args *args);
static int handle_extended_arg(const char *opt, kt_args *args);
static int parse_timestamp(const char *ts, struct tm *tm);

static void usage(void);

int
kt_process_args(int argc, char **argv, kt_args *args, kt_key *key)
{
	const char *t;
	int c;
	struct tm tm;

	if(argv[0] && argv[0][0])
	{
		if((t = strrchr(argv[0], '/')))
		{
			t++;
			progname = t;
		}
		else
		{
			progname = argv[0];
		}
	}
	while((c = getopt(argc, argv, "i:o:I:O:t:C:X:S:TgnfkpPh")) != -1)
	{
		switch(c)
		{
		case 'i':
			/* -i FILE -- Specify input file */
			args->infile = optarg;
			break;
		case 'o':
			/* -i FILE -- Specify output file */
			args->outfile = optarg;
			break;
		case 'I':
			/* -I FORMAT -- Specify input format */
			if(NULL == (args->input_handler = kt_handler_locate(optarg)))
			{
				BIO_printf(bio_err, "%s: Unknown input format '%s'\n", progname, optarg);
				return 1;
			}
			break;
		case 'O':
			/* -O FORMAT -- Specify output format */
			if(NULL == (args->output_handler = kt_handler_locate(optarg)))
			{
				BIO_printf(bio_err, "%s: Unknown output format '%s'\n", progname, optarg);
				return 1;
			}
			break;
		case 'T':
			/* -T -- Equivalent to -O text */
			args->output_handler = kt_handler_locate("text");
			break;
		case 'f':
			/* -f -- Output the fingerprint */
			args->fingerprint = 1;
			break;
		case 'k':
			/* -k -- Output key ID */
			args->keyid = 1;
			break;
		case 'p':
			/* -p -- Attempt to read a private key */
			args->readpriv = 1;
			break;
		case 'P':
			/* -P -- Attempt to read and write a private key */
			args->readpriv = 1;
			args->writepriv = 1;
			break;
		case 'g':
			/* -g -- Generate a new key */
			args->generate = 1;
			args->infile = NULL;
			args->writepriv = 1;
			break;
		case 't':
			/* -t TYPE -- Specify key type */
			if(KT_ERROR == (key->type = kt_type_locate(optarg)))
			{
				BIO_printf(args->berr, "%s: Unknown key type '%s'\n", progname, optarg);
				return 1;
			}
			break;
		case 'n':
			/* -n -- Inhibit output (doesn't apply to -f, -k, -F, -s and -B) */
			args->noout = 1;
			break;
		case 'C':
			/* -C COMMENT -- Set the SSH key comment/PGP user ID */
			args->comment = optarg;
			break;
		case 'X':
			/* -Xopt[=value] -- Extended options */
			if(handle_extended_arg(optarg, args))
			{
				return 1;
			}
			break;
		case 'S':
			/* -S YYYYMMDDHHMMSS -- Set key timestamp */
			if(parse_timestamp(optarg, &tm))
			{
				return 1;
			}
			args->kts_explicit = 1;
			key->timestamp = mktime(&tm);
			break;
		case 'h':
			usage();
			exit(0);
		default:
			return 1;
		}
	}
	if(optind < argc)
	{
		usage();
		return 1;
	}
	return 0;
}

static int
process_extended_opt(const char *name, const char *value, kt_args *args)
{
	int r;
	
	r = 1;
	if(!strcmp(name, "unsigned"))
	{
		r = (*value) ? 2 : 0;
		args->nosign = 1;
	}
	else if(!strcmp(name, "nsec3"))
	{
		r = (*value) ? 2 : 0;
		args->nsec3 = 1;
	}		
	else if(!strcmp(name, "domain"))
	{
		if(*value)
		{
			args->domain = value;
			r = 0;
		}
		else
		{
			r = 3;
		}
	}
	else if(!strcmp(name, "bits"))
	{
		if(*value)
		{
			args->bits = atoi(value);
			r = 0;
		}
		else
		{
			r = 3;
		}
	}
	else if(!strcmp(name, "usage"))
	{
		if(*value)
		{
			r = 0;
			if(process_usage_opt(value, args))
			{
				r = -1;
			}
		}
		else
		{
			r = 3;
		}
	}
	switch(r)
	{
	case -1:
		break;
	case 1:
		fprintf(stderr, "x\n");
		BIO_printf(args->berr, "%s: unrecognised option `-X%s'\n", progname, name);
		break;
	case 2:
		BIO_printf(args->berr, "%s: warning: option `-X%s' does not accept an argument (ignored)\n", progname, name);
		r = 0;
		break;
	case 3:
		BIO_printf(args->berr, "%s: option `-X%s' requires an argument\n", progname, name);
		break;
	}
	return r;
}

static int
process_usage_opt(const char *str, kt_args *args)
{
	const char *p;
	
	args->keyusage = 0;
	for(p = str; *p; p++)
	{
		switch(*p)
		{
		case 'c':
			args->keyusage |= PGP_KF_CERT;
			break;
		case 's':
			args->keyusage |= PGP_KF_SIGN_DATA;
			break;
		case 'e':
			args->keyusage |= PGP_KF_CRYPT_COMMS;
			break;
		case 'E':
			args->keyusage |= PGP_KF_CRYPT_STORAGE;
			break;
		case 'S':
			args->keyusage |= PGP_KF_SPLIT;
			break;
		case 'a':
			args->keyusage |= PGP_KF_AUTH;
			break;
		case 'h':
			args->keyusage |= PGP_KF_SHARED;
			break;
		default:
			BIO_printf(args->berr, "%s: unrecognised key usage flag `%c'\n", progname, *p);
			return -1;
		}
	}
	return 0;
}

static int
handle_extended_arg(const char *opt, kt_args *args)
{
	const char *value;
	char namebuf[32];

	value = strchr(opt, '=');
	if(value)
	{
		if((size_t) (value - opt) >= sizeof(namebuf))
		{
			BIO_printf(args->berr, "%s: unrecognised option `-X%s'\n", progname, opt);
			return -1;
		}
		strncpy(namebuf, opt, value - opt);
		namebuf[value - opt] = 0;
		value++;
	}
	else
	{
		if(strlen(opt) >= sizeof(namebuf))
		{
			BIO_printf(args->berr, "%s: unrecognised option `-X%s'\n", progname, opt);
			return -1;
		}
		strcpy(namebuf, opt);
		value = "";
	}
	return process_extended_opt(namebuf, value, args);
}

static int
parse_timestamp(const char *ts, struct tm *tm)
{
	const char *p;
	char tbuf[32];
	size_t n;

	p = ts;
	memset(tm, 0, sizeof(struct tm));
	for(n = 0; *ts; ts++)
	{
		if(!isdigit(*ts))
		{
			continue;
		}
		if(n + 1 >= sizeof(tbuf))
		{
			BIO_printf(bio_err, "%s: invalid timestamp '%s'\n", progname, p);
			return -1;
		}
		tbuf[n] = *ts;
		n++;
	}
	tbuf[n] = 0;
	ts = NULL;
	if(n == 14)
	{		
		sscanf(tbuf, "%04d%02d%02d%02d%02d%02d", &tm->tm_year, &tm->tm_mon, &tm->tm_mday, &tm->tm_hour, &tm->tm_min, &tm->tm_sec);
		tm->tm_mon--;
		return 0;
	}
	if(n == 12)
	{
		sscanf(tbuf, "%04d%02d%02d%02d%02d", &tm->tm_year, &tm->tm_mon, &tm->tm_mday, &tm->tm_hour, &tm->tm_min);
		tm->tm_mon--;
		return 0;
	}
	else if(n == 10)
	{
		sscanf(tbuf, "%04d%02d%02d%02d", &tm->tm_year, &tm->tm_mon, &tm->tm_mday, &tm->tm_hour);
		tm->tm_mon--;
		return 0;
	}
	else if(n == 8)
	{
		sscanf(tbuf, "%04d%02d%02d", &tm->tm_year, &tm->tm_mon, &tm->tm_mday);
		tm->tm_mon--;
		return 0;
	}
	else if(n == 6)
	{
		sscanf(tbuf, "%04d%02d", &tm->tm_year, &tm->tm_mon);
		tm->tm_mon--;
		tm->tm_mday = 1;
		return 0;
	}
	else if(n == 4)
	{
		sscanf(tbuf, "%04d", &tm->tm_year);
		tm->tm_mday = 1;
		return 0;
	}
	BIO_printf(bio_err, "%s: invalid timestamp '%s'\n", progname, p);
	return -1;		
}

static void
usage(void)
{
	int c;
	char caps[6];
	kt_handler_entry *handlers;
	kt_keytype_entry *keytypes;

	fprintf(stderr, "Public- and private-key manipulation utility\n\n");

	fprintf(stderr, "Usage:\n"
			"  %s [OPTIONS] [< KEY-IN] [> KEY-OUT]\n"
			"\n"
			"OPTIONS is one or more of:\n"
			"\n"
			"  -i FILE           Specify input file\n"
			"  -o FILE           Specify output file\n"
			"  -n                Don't produce an output file\n"
			"  -I FORMAT         Specify input format\n"
			"  -O FORMAT         Specify output format\n"
			"  -T                Alias for '-O text'\n"
			"  -t TYPE           Set key type (required for -g)\n"
			"  -g                Generate a new key (implies -P)\n"
			"  -S YYYYMMDDHHMMSS Override key timestamp\n"
			"  -f                Print the key fingerprint\n"
			"  -k                Print the key ID\n"
			"  -p                Read a private key\n"
			"  -P                Write the private key (implies -p)\n"
			"  -C COMMENT        Key comment (SSH)/user ID (PGP)\n"
			"  -Xopt[=value]     Format-specific options (see below)\n"
			"\n", progname);
	
	fprintf(stderr, "Note that the fingerprint (-f) and key ID (-k) format is dependent\n"
			        "upon the output format (-O). Use in combination with -n if only the\n"
			"fingerprint/key ID output is required.\n\n");
	fprintf(stderr, "Key generation options:\n"
			"  -Xbits=NUM        Generate a key NUM bits in size\n"
			"\n");
	
	fprintf(stderr, "PGP-specific options:\n"
			"  -Xunsigned        Emit an unsigned user ID (requires -C)\n"
			"  -Xusage=FLAGS     Specify key usage flags\n"
			"    (e=encrypt, c=certify, s=sign, a=authenticate, E=encrypt storage, S=split\n"
			"     key, h=shared key)\n"			
			"\n");

	fprintf(stderr, "DNSSEC-specific options:\n"
			"  -Xdomain=DOMAIN   Specify doman name for a zone key\n"
			"  -Xnsec3           Write a key for NSEC3\n"
			"\n");

	handlers = kt_handlers();
	fprintf(stderr, "FORMAT may be one of the following key formats:\n\n");
	for(c = 0; handlers[c].name; c++)
	{
		if(handlers[c].cert)
		{
			continue;
		}
		caps[0] = (handlers[c].input != NULL ? 'r' : '-');
		caps[1] = (handlers[c].output != NULL ? 'w' : '-');
		caps[2] = 0;
		fprintf(stderr, " [%s] %-17s %s\n", caps, handlers[c].name, handlers[c].desc);
	}
	fprintf(stderr, "\nFORMAT may be one of the following certificate-based formats:\n\n");
	for(c = 0; handlers[c].name; c++)
	{
		if(!handlers[c].cert)
		{
			continue;
		}
		caps[0] = (handlers[c].input != NULL ? 'r' : '-');
		caps[1] = (handlers[c].output != NULL ? 'w' : '-');
		caps[2] = 0;
		fprintf(stderr, " [%s] %-17s %s\n", caps, handlers[c].name, handlers[c].desc);
	}
	fprintf(stderr, "\n(Key: r=can be read, w=can be written)\n");
	keytypes = kt_types();
	fprintf(stderr, "\nTYPE is one of:\n\n");   
	for(c = 0; keytypes[c].name; c++)
	{
		fprintf(stderr, "  %-17s %s\n", keytypes[c].name, keytypes[c].desc);
	}
}

