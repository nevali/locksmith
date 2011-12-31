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

static kt_keytype_entry keytypes[] = 
{
	{ "rsa", "RSA", "Rivest, Shamir, Adleman (RSA)", KT_RSA },
	{ "dsa", "DSA", "Digital Signature Algorithm (DSA)", KT_DSA },
	{ NULL, NULL, NULL, KT_ERROR }
};

const char *progname = "keytool";
BIO *bio_err = NULL;

kt_keytype_entry *
kt_types(void)
{
	return keytypes;
}

kt_keytype
kt_type_locate(const char *str)
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

int
main(int argc, char **argv)
{
	kt_key k;
	kt_args args;
	BIO *bin, *berr, *bout;
	int r;

	memset(&k, 0, sizeof(k));
	memset(&args, 0, sizeof(args));
	berr = BIO_new(BIO_s_file());
	BIO_set_fp(berr, stderr, BIO_NOCLOSE|BIO_FP_TEXT);
	bio_err = berr;
	args.berr = berr;
	args.timestamp = time(NULL);
	k.timestamp = args.timestamp;
	
	if((r = kt_process_args(argc, argv, &args, &k)))
	{
		return (r < 0 ? 1 : r);
	}
	if(args.generate && k.type == KT_UNKNOWN)
	{
		BIO_printf(berr, "%s: A key type must be specified with -t when generating a new key\n", progname);
		return 1;
	}
	if(args.input_handler && !args.input_handler->input)
	{
		BIO_printf(berr, "%s: Keys cannot be read in %s format\n", progname, args.input_handler->printname);
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
		if(!args.input_handler)
		{
			/* XXX: Need to add a detection process */
			args.input_handler = kt_handler_locate("pem");
		}
	}
	if(!args.noout)
	{
		if(!args.output_handler)
		{
			args.output_handler = kt_handler_locate("pem");
		}
		if(!args.output_handler->output)
		{
			BIO_printf(berr, "%s: Keys cannot be written in %s format\n", progname, args.output_handler->printname);
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
			return (r < 0 ? 1 : r);
		}
	}
	else if((r = args.input_handler->input(&k, bin, &args)))
	{
		return (r < 0 ? 1 : r);
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
		if((r = args.output_handler->output(&k, bout, &args)))
		{
			return (r < 0 ? 1 : r);
		}
	}
	return 0;
}
