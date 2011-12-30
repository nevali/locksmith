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

typedef struct kt_handler_entry_s kt_handler_entry;
typedef struct kt_typestr_s kt_typestr;

struct kt_handler_entry_s
{
	const char *name;
	const char *printname;
	const char *desc;
	kt_input_handler input;
	kt_output_handler output;
};

struct kt_typestr_s
{
	const char *name;
	const char *printname;
	const char *desc;
	kt_keytype type;
};

static kt_handler_entry handlers[] = 
{
	{ "text", "text", "Readable information about the key's contents", NULL, text_output },
	{ "pem", "PEM", "Privacy Enhanced Mail (PEM) format", pem_input, pem_output },
	{ "der", "DER", "ASN.1 Distinguished Encoding Rules (DER) format", der_input, der_output },
	{ "openssh", "OpenSSH", "OpenSSH key format", NULL, openssh_output },
	{ "ssh2", "SSH-2", "SSH-2 (RFC4716) key format", NULL, ssh_output },
	{ "pgp", "PGP", "OpenPGP (RFC4880) version 4 key format", NULL, pgp_output },
	{ "rdfxml", "RDF/XML", "RDF/XML format", NULL, rdfxml_output },
	{ "turtle", "Turtle", "RDF (Turtle) format", NULL, turtle_output },
	{ "dnssec", "DNSSEC", "DNSSEC key format", NULL, dnssec_output },
	{ "ipgp", "CERT IPGP", "DNS CERT record (RFC4938) type 6 (indirect PGP)", NULL, cert_ipgp_output },
	{ NULL, NULL, NULL, NULL, NULL }
};

static kt_typestr keytypes[] = 
{
	{ "rsa", "RSA", "Rivest, Shamir, Adleman (RSA)", KT_RSA },
	{ "dsa", "DSA", "Digital Signature Algorithm (DSA)", KT_DSA },
	{ NULL, NULL, NULL, KT_ERROR }
};

const char *progname = "keytool";
BIO *bio_err = NULL;

kt_keytype
kt_type(const char *str)
{
	int c;

	for(c = 0; keytypes[c].name; c++)
	{
		if(!strcmp(str, keytypes[c].name))
		{
			return keytypes[c].type;
		}
	}
	return KT_ERROR;
}

const char *
kt_type_printname(kt_keytype type)
{
	int c;
	
	for(c = 0; keytypes[c].name; c++)
	{
		if(keytypes[c].type == type)
		{
			return keytypes[c].printname;
		}
	}
	return NULL;
}

static int
init_output(BIO *file, kt_args *args)
{
	if(args->outfile)
	{
		if (BIO_write_filename(file, (char *) args->outfile) <= 0)
		{
			BIO_printf(args->berr, "%s: Failed to open '%s' for writing\n", progname, args->outfile);
			ERR_print_errors(args->berr);
			return 1;
		}
	}
	else
	{
		args->outfile = "*standard output*";
		BIO_set_fp(file, stdout, BIO_NOCLOSE);
	}
	return 0;
}

static int
init_input(BIO *file, kt_args *args, kt_key *k)
{
	struct stat sbuf;

	if(args->generate)
	{
		return 0;
	}
	if(args->infile)
	{
		if (BIO_read_filename(file, args->infile) <= 0)
		{
			BIO_printf(args->berr, "%s: Failed to open %s for reading\n", progname, args->infile);
			ERR_print_errors(args->berr);
			return 1;
		}
		if(!args->kts_explicit && !stat(args->infile, &sbuf))
		{
			k->timestamp = MIN3(sbuf.st_mtime, sbuf.st_atime, sbuf.st_ctime);
		}
	}
	else
	{
		if(isatty(0))
		{
			BIO_printf(args->berr, "%s: Reading from standard input (use -i to specify an input file, or -h for usage information)\n", progname);
		}
		args->infile = "*standard input*";
		setvbuf(stdin, NULL, _IONBF, 0);
		BIO_set_fp(file, stdin, BIO_NOCLOSE);
	}
	return 0;
}

static kt_handler_entry *
find_handler(const char *name)
{
	int c;
	
	for(c = 0; handlers[c].name; c++)
	{
		if(!strcmp(handlers[c].name, name))
		{
			return &(handlers[c]);
		}
	}
	return NULL;
}

static void
usage(void)
{
	int c;

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
			"  -f                Print the PKCS (SHA-1) key fingerprint\n"
			"  -k                Print the PGP key ID\n"
			"  -F                Print the PGP key fingerprint\n"
			"  -s                Print the SSH (MD5) key fingerprint\n"
			"  -B                Print the SSH bubblebabble key digest\n"
			"  -p                Read a private key\n"
			"  -P                Write the private key (implies -p)\n"
			"  -C COMMENT        Key comment (SSH)/user ID (PGP)\n"
			"  -Xopt[=value]     Format-specific options (see below)\n"
			"\n", progname);
	
	fprintf(stderr, "PGP-specific options:\n"
			"  -Xunsigned        Emit an unsigned user ID (requires -C)\n"
			"\n");

	fprintf(stderr, "DNSSEC-specific options:\n"
			"  -Xdomain=DOMAIN   Specify doman name for a zone key\n"
			"\n");
	fprintf(stderr, "FORMAT is one of:\n\n");
	for(c = 0; handlers[c].name; c++)
	{
		fprintf(stderr, "  %-17s %s\n", handlers[c].name, handlers[c].desc);
	}

	fprintf(stderr, "\nTYPE is one of:\n\n");

	for(c = 0; keytypes[c].name; c++)
	{
		fprintf(stderr, "  %-17s %s\n", keytypes[c].name, keytypes[c].desc);
	}
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
	switch(r)
	{
	case -1:
		break;
	case 1:
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
		ts = strptime(tbuf, "%Y%m%d%H%M%S", tm);
	}	if(n == 12)
	{
		ts = strptime(tbuf, "%Y%m%d%H%M", tm);
	}
	else if(n == 10)
	{
		ts = strptime(tbuf, "%Y%m%d%H", tm);
	}
	else if(n == 8)
	{
		ts = strptime(tbuf, "%Y%m%d", tm);
	}
	else if(n == 6)
	{
		ts = strptime(tbuf, "%Y%m", tm);
		tm->tm_mday = 1;
	}
	else if(n == 4)
	{
		ts = strptime(tbuf, "%Y", tm);
		tm->tm_mday = 1;
	}
	if(!ts || ts[0])
	{
		BIO_printf(bio_err, "%s: invalid timestamp '%s'\n", progname, p);
		return -1;		
	}
	return 0;
}

int
main(int argc, char **argv)
{
	const char *t;
	kt_key k;
	kt_args args;
	BIO *bin, *berr, *bout;
	kt_handler_entry *output_handler = NULL;
	kt_handler_entry *input_handler = NULL;
	int r, c;
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
	memset(&k, 0, sizeof(k));
	memset(&args, 0, sizeof(args));
	berr = BIO_new(BIO_s_file());
	BIO_set_fp(berr, stderr, BIO_NOCLOSE|BIO_FP_TEXT);
	bio_err = berr;
	args.berr = berr;
	args.timestamp = time(NULL);
	k.timestamp = args.timestamp;
	while((c = getopt(argc, argv, "i:o:I:O:t:C:X:S:TgnfksBpPhF")) != -1)
	{
		switch(c)
		{
		case 'i':
			/* -i FILE -- Specify input file */
			args.infile = optarg;
			break;
		case 'o':
			/* -i FILE -- Specify output file */
			args.outfile = optarg;
			break;
		case 'I':
			/* -I FORMAT -- Specify input format */
			if(NULL == (input_handler = find_handler(optarg)))
			{
				BIO_printf(berr, "%s: Unknown input format '%s'\n", progname, optarg);
				return 1;
			}
			break;
		case 'O':
			/* -O FORMAT -- Specify output format */
			if(NULL == (output_handler = find_handler(optarg)))
			{
				BIO_printf(berr, "%s: Unknown output format '%s'\n", progname, optarg);
				return 1;
			}
			break;
		case 'T':
			/* -T -- Equivalent to -O text */
			output_handler = find_handler("text");
			break;
		case 'f':
			/* -f -- Output PKCS SHA-1 fingerprint */
			args.sha1 = 1;
			break;
		case 'k':
			/* -k -- Output PGP key ID */
			args.pgpid = 1;
			break;
		case 's':
			/* -s -- Output SSH MD5 fingerprint */
			args.md5 = 1;
			break;
		case 'B':
			/* -B -- Output SSH Bubblebabble digest */
			args.bubble = 1;
			break;
		case 'F':
			/* -F -- Output PGP key fingerprint */
			args.pgpfp = 1;
			break;
		case 'p':
			/* -p -- Attempt to read a private key */
			args.readpriv = 1;
			break;
		case 'P':
			/* -P -- Attempt to read and write a private key */
			args.readpriv = 1;
			args.writepriv = 1;
			break;
		case 'g':
			/* -g -- Generate a new key */
			args.generate = 1;
			args.infile = NULL;
			args.writepriv = 1;
			break;
		case 't':
			/* -t TYPE -- Specify key type */
			if(KT_ERROR == (k.type = kt_type(optarg)))
			{
				BIO_printf(berr, "%s: Unknown key type '%s'\n", progname, optarg);
				return 1;
			}
			break;
		case 'n':
			/* -n -- Inhibit output (doesn't apply to -f, -k, -F, -s and -B) */
			args.noout = 1;
			break;
		case 'C':
			/* -C COMMENT -- Set the SSH key comment/PGP user ID */
			args.comment = optarg;
			break;
		case 'X':
			/* -Xopt[=value] -- Extended options */
			if(handle_extended_arg(optarg, &args))
			{
				usage();
				return 1;
			}
			break;
		case 'S':
			/* -S YYYYMMDDHHMMSS -- Set key timestamp */
			if(parse_timestamp(optarg, &tm))
			{
				return 1;
			}
			args.kts_explicit = 1;
			k.timestamp = mktime(&tm);
			break;
		case 'h':
			usage();
			return 0;			
		default:
			usage();
			return 1;
		}
	}
	if(optind < argc)
	{
		usage();
		return 1;
	}
	if(args.generate && k.type == KT_UNKNOWN)
	{
		BIO_printf(berr, "%s: A key type must be specified with -t when generating a new key\n", progname);
		return 1;
	}
	if(input_handler && !input_handler->input)
	{
		BIO_printf(berr, "%s: Keys cannot be read in %s format\n", progname, input_handler->printname);
		return 1;
	}
	if(args.generate)
	{
		bin = NULL;
	}
	else
	{
		if(NULL == (bin = BIO_new(BIO_s_file())))
		{
			ERR_print_errors(berr);
			return 1;
		}
		if(init_input(bin, &args, &k))
		{
			return 1;
		}
		if(!input_handler)
		{
			/* XXX: Need to add a detection process */
			input_handler = find_handler("pem");
		}
	}
	if(!args.noout)
	{
		if(!output_handler)
		{
			output_handler = find_handler("pem");
		}
		if(!output_handler->output)
		{
			BIO_printf(berr, "%s: Keys cannot be written in %s format\n", progname, output_handler->printname);
			return 1;
		}
	}
	if(NULL == (bout = BIO_new(BIO_s_file())))
	{
		ERR_print_errors(berr);
		return 1;
	}		
	if(init_output(bout, &args))
	{
		return 1;
	}
	/* Generate a new key or read the input file */
	if(args.generate)
	{
		if((r = kt_generate(&k, &args)))
		{
			return r;
		}
	}
	else if((r = input_handler->input(&k, bin, &args)))
	{
		return r;
	}
	if(!k.size)
	{
		k.size = kt_get_size(&k);
	}
	if(args.md5)
	{
		ssh_fingerprint(&k, bout, &args);
	}
	if(args.pgpid)
	{
		pgp_keyid(&k, bout, &args);
	}
	if(args.pgpfp)
	{
		pgp_fingerprint(&k, bout, &args);
	}
	if(!args.noout)
	{
		output_handler->output(&k, bout, &args);
	}
	return 0;
}
