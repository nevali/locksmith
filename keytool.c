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
	{ "der", "DER", "ASN.1 Distinguished Encoding Rules (DER) format", NULL, der_output },
	{ "openssh", "OpenSSH", "OpenSSH key format", NULL, openssh_output },
	{ "ssh2", "SSH-2", "SSH-2 (RFC4716) key format", NULL, ssh_output },
	{ "pgp", "PGP", "OpenPGP (RFC4880) version 4 key format", NULL, pgp_output },
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
init_input(BIO *file, kt_args *args)
{
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
	}
	else
	{
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
			"  -f                Print the PKCS (SHA-1) key fingerprint\n"
			"  -k                Print the PGP key ID\n"
			"  -s                Print the SSH (MD5) key fingerprint\n"
			"  -B                Print the SSH bubblebabble key digest\n"
			"  -p                Read a private key\n"
			"  -P                Write the private key (implies -p)\n"
			"  -C COMMENT        Key comment (SSH)/user ID (PGP)\n"
			"\n", progname);
	
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

	while((c = getopt(argc, argv, "i:o:I:O:t:C:TgnfksBpPh")) != -1)
	{
		switch(c)
		{
		case 'i':
			args.infile = optarg;
			break;
		case 'o':
			args.outfile = optarg;
			break;
		case 'I':
			if(NULL == (input_handler = find_handler(optarg)))
			{
				BIO_printf(berr, "%s: Unknown input format '%s'\n", progname, optarg);
				return 1;
			}
			break;
		case 'O':			
			if(NULL == (output_handler = find_handler(optarg)))
			{
				BIO_printf(berr, "%s: Unknown output format '%s'\n", progname, optarg);
				return 1;
			}
			break;
		case 'T':
			output_handler = find_handler("text");
			break;
		case 'f':
			args.sha1 = 1;
			break;
		case 'k':
			args.pgpid = 1;
			break;
		case 's':
			args.md5 = 1;
			break;
		case 'B':
			args.bubble = 1;
			break;
		case 'p':
			args.readpriv = 1;
			break;
		case 'P':
			args.readpriv = 1;
			args.writepriv = 1;
			break;
		case 'g':
			args.generate = 1;
			args.infile = NULL;
			args.writepriv = 1;
			break;
		case 't':
			if(KT_ERROR == (k.type = kt_type(optarg)))
			{
				BIO_printf(berr, "%s: Unknown key type '%s'\n", progname, optarg);
				return 1;
			}
			break;
		case 'n':
			args.noout = 1;
			break;
		case 'C':
			args.comment = optarg;
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
		if(init_input(bin, &args))
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
	k.timestamp = args.timestamp;
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
	if(!args.noout)
	{
		output_handler->output(&k, bout, &args);
	}
	return 0;
}
