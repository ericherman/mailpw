/* SPDX-License-Identifier: GPL-3.0-or-later */
/* pwcrypt.c: /etc/shadow style pw, uses GLibC extentions via crypt_r */
/* Copyright (C) 2020 - 2021 Eric Herman <eric@freesa.org> */
/* Copyright (C) 2021 Keith Reynolds <keithr@pwcrypt.keithr.com> */
/* cc ./pwcrypt.c -o pwcrypt -lcrypt */

/*
 * To generate a password for an /etc/shadow -like file:
 *
 *	pwcrypt \
 *		[--confirm] \
 *		[--type='email'] \
 *		[--algorithm='SHA512'] \
 *		[--salt='UD23qlwjerf']
 *
 * To test against your own passwd, get your salt:
 *
 *	make
 *	PW=`sudo grep $USER /etc/shadow | cut -f2 -d':'`
 *	ALGO=`echo "$PW" | cut -d'$' -f2`
 *	SALT=`echo "$PW" | cut -d'$' -f3`
 *	GUESS=`./pwcrypt --algorithm=$ALGO --salt="$SALT"`
 *	if [ "$GUESS" = "$PW" ]; then echo OK; else echo BAD; fi
 *
 */

#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <crypt.h>		/* Link with -lcrypt */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <termios.h>
#include <getopt.h>

/* see the "Notes" section of "man 3 crypt" for glibc crypt_r
 * algorithm options */
/* #define CRYPT_MD5 "1" */
/* #define CRYPT_BLOWFISH "2a" */
#define CRYPT_SHA256 "5"
#define CRYPT_SHA512 "6"

const char *pwcrypt_version_str = "0.0.1";

/* prototypes */
char *chomp_crlf(char *str, size_t max);
void getpass(char *buf, char *buf2, size_t size, const char *type, int confirm,
	     char *(*fgets_func)(char *buf, int size, FILE *tty), FILE *tty);
void getrandom_salt(char *buf, size_t size);
char *fgets_no_echo(char *buf, int size, FILE *stream);
int is_valid_for_salt(char c);
const char *crypt_algo(const char *in);

/* functions */
int pwcrypt(int confirm, const char *type, const char *algorithm,
	    const char *user_salt, FILE *out,
	    char *(*fgets_func)(char *buf, int size, FILE *tty), FILE *tty)
{
	/* The salt_buf_size is arbitrary, but user_salt may also contain
	 * "rounds" or other data. From man crypt_r:
	 *
	 * Since glibc 2.7, the SHA-256 and SHA-512 implementations
	 * support a user-supplied number of hashing rounds,
	 * defaulting to 5000.  If the "$id$" characters in the salt
	 * are followed by "rounds=xxx$", where xxx is an integer,
	 * then the result has the form
	 *
	 *     $id$rounds=yyy$salt$encrypted
	 */
	const size_t salt_buf_size = 200;
	char salt_buf[salt_buf_size];
	memset(salt_buf, 0x00, salt_buf_size);
	if (user_salt) {
		strncpy(salt_buf, user_salt, salt_buf_size);
		salt_buf[salt_buf_size - 1] = '\0';
	} else {
		/* limit imposed by crypt_r */
		const size_t salt_max_len = 16;
		getrandom_salt(salt_buf, salt_max_len + 1);
	}

	const char *algo = crypt_algo(algorithm);
	const size_t algo_salt_size = salt_buf_size + 10;
	char algo_salt[algo_salt_size];
	snprintf(algo_salt, algo_salt_size, "$%s$%s$", algo, salt_buf);

	struct crypt_data data;
	/* data->initialized = 0; */
	memset(&data, 0x00, sizeof(struct crypt_data));

	// TODO: use madvise with MADV_DONTDUMP, MADV_WIPEONFORK
	const size_t plaintext_passphrase_size = 1024;
	char plaintext_passphrase[plaintext_passphrase_size];
	char plaintext_passphrase2[plaintext_passphrase_size];

	getpass(plaintext_passphrase, plaintext_passphrase2,
		plaintext_passphrase_size, type, confirm, fgets_func, tty);

	char *encrypted = crypt_r(plaintext_passphrase, algo_salt, &data);
	if (!encrypted) {
		err(EXIT_FAILURE, "crypt_r failed");
	}

	memset(plaintext_passphrase, 0x00, plaintext_passphrase_size);

	fprintf(out, "%s\n", encrypted);

	return 0;
}

char *fgets_no_echo(char *buf, int size, FILE *stream)
{

	int fno = fileno(stream);

	struct termios orig;
	int error = tcgetattr(fno, &orig);
	if (error) {
		err(EXIT_FAILURE, "tcgetattr failed for fd: %d", fno);
	}

	struct termios next = orig;
	next.c_lflag &= ~ECHO;
	error = tcsetattr(fno, TCSAFLUSH, &next);
	if (error) {
		err(EXIT_FAILURE, "tcsetattr failed for fd: %d", fno);
	}

	char *str = fgets(buf, size, stream);

	error = tcsetattr(fno, TCSAFLUSH, &orig);
	if (error) {
		err(EXIT_FAILURE, "reset tcgetattr failed for fd: %d", fno);
	}

	return str;
}

void getpass(char *buf, char *buf2, size_t size, const char *type, int confirm,
	     char *(*fgets_func)(char *buf, int size, FILE *tty), FILE *tty)
{
	assert(buf);
	assert(!confirm || buf2);
	assert(size);
	assert(tty);

	if (!type) {
		type = "";
	}
	const char *space = type[0] ? " " : "";

	int diff = 0;
	do {
		if (diff) {
			fprintf(tty, "inputs did not match\n");
		}
		fprintf(tty, " input %s%spassphrase: ", type, space);
		fflush(tty);
		char *r = fgets_func(buf, size, tty);
		if (!r) {
			err(EXIT_FAILURE,
			    "fgets_no_echo returned NULL reading buf of %zu",
			    size);
		}
		chomp_crlf(buf, size);
		fprintf(tty, "\n");
		fflush(tty);

		if (confirm) {
			fprintf(tty, "repeat %s%spassphrase: ", type, space);
			fflush(tty);
			r = fgets_func(buf2, size, tty);
			if (!r) {
				err(EXIT_FAILURE,
				    "fgets_no_echo returned NULL"
				    " reading buf of %zu?", size);
			}
			chomp_crlf(buf2, size);
			fprintf(tty, "\n");
			fflush(tty);

			diff = strncmp(buf, buf2, size);
		}
	} while (diff);
}

const char *crypt_algo(const char *in)
{
	if (!in || !in[0] || strcasecmp(in, "default") == 0) {
		return CRYPT_SHA512;
	}

	if (strcasecmp(in, "SHA512") == 0 || strcasecmp(in, CRYPT_SHA512) == 0) {
		return CRYPT_SHA512;
	}

	if (strcasecmp(in, "SHA256") == 0 || strcasecmp(in, CRYPT_SHA256) == 0) {
		return CRYPT_SHA256;
	}

	return in;
}

void getrandom_salt(char *buf, size_t size)
{
	assert(buf);
	assert(size);

	memset(buf, 0x00, size);

	size_t max = (size - 1);
	size_t len = 0;
	do {
		const size_t rnd_buf_size = 128;
		char rnd_buf[rnd_buf_size];
		unsigned int flags = 0;
		ssize_t got = getrandom(rnd_buf, rnd_buf_size, flags);

		for (ssize_t i = 0; i < got && len < max; ++i) {
			char c = rnd_buf[i];
			if (is_valid_for_salt(c)) {
				buf[len++] = c;
			}
		}
	} while (len < max);
}

char *chomp_crlf(char *str, size_t size)
{
	if (!str) {
		return NULL;
	}
	for (size_t i = 0; i < size && str[i] != '\0'; ++i) {
		if (str[i] == '\r' || str[i] == '\n') {
			str[i] = '\0';
			return str;
		}
	}
	return str;
}

int is_valid_for_salt(char c)
{
	/* from "man 5 crypt", we see the hashed passphrase format:
	 * [./0-9A-Za-z] */
	if (c == '.') {
		return c;
	}
	if (c == '/') {
		return c;
	}
	/* the standard LibC "isalnum()" results may depend upon the locale
	 * ( see: https://www.cplusplus.com/reference/cctype/isalnum/ )
	 * thus do it by hand */
	if (c >= 'A' && c <= 'Z') {
		return c;
	}
	if (c >= 'a' && c <= 'z') {
		return c;
	}
	if (c >= '0' && c <= '9') {
		return c;
	}
	return 0;
}

void pwcrypt_parse_options(int *help, int *version, int *confirm,
			   const char **type, const char **algorithm,
			   const char **salt, int argc, char **argv)
{
	assert(help);
	assert(version);
	assert(confirm);
	assert(type);
	assert(algorithm);
	assert(salt);
	assert(argc);
	assert(argv);

	/* omg, optstirng is horrible */
	const char *optstring = "hvct::a::s::";
	struct option long_options[] = {
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'v' },
		{ "confirm", no_argument, 0, 'c' },
		{ "type", optional_argument, 0, 't' },
		{ "algorithm", optional_argument, 0, 'a' },
		{ "salt", optional_argument, 0, 's' },
		{ 0, 0, 0, 0 }
	};

	while (1) {
		int option_index = 0;
		int opt_char = getopt_long(argc, argv, optstring, long_options,
					   &option_index);

		/* Detect the end of the options */
		if (opt_char == -1) {
			break;
		}

		switch (opt_char) {
		case 'h':
			*help = 1;
			break;
		case 'v':
			*version = 1;
			break;
		case 'c':
			*confirm = 1;
			break;
		case 't':
			*type = optarg;
			break;
		case 'a':
			*algorithm = optarg;
			break;
		case 's':
			*salt = optarg;
			break;
		default:	/* can this happen? */
			break;
		}
	}
}

void pwcrypt_help(FILE *out)
{
	fprintf(out, "%s:%s() %d: \n", __FILE__, __func__, __LINE__);
	fprintf(out, "Usage: pwcrypt [options]\n");
	fprintf(out, "Options:\n");

	fprintf(out, "  -a STRING, --algorithm=STRING");
	fprintf(out, "   Use algorithm of STRING. Valid values are\n");
	fprintf(out, "                               ");
	fprintf(out, "   SHA512 (6, default), SHA256 (5)\n");
	fprintf(out, "                               ");
	fprintf(out, "   or other values supported by crypt_r(3).\n");

	fprintf(out, "  -c, --confirm                ");
	fprintf(out, "   Prompts twice to enter the passphrase.\n");

	fprintf(out, "  -h, --help                   ");
	fprintf(out, "   Prints this message and exits.\n");

	fprintf(out, "  -s STRING, --salt=STRING     ");
	fprintf(out, "   Use the STRING as the salt.\n");

	fprintf(out, "  -t STRING, --type=STRING     ");
	fprintf(out, "   Add the STRING to the prompt.\n");

	fprintf(out, "  -v, --version                ");
	fprintf(out, "   Prints the version (%s) and exits.\n",
		pwcrypt_version_str);
}

void pwcrypt_version(FILE *out)
{
	fprintf(out, "pwcrypt version %s\n", pwcrypt_version_str);
}

int pwcrypt_cli(int argc, char **argv, FILE *out)
{
	int help = 0;
	int version = 0;
	int confirm = 0;
	const char *type = NULL;
	const char *algorithm = NULL;
	const char *salt = NULL;

	pwcrypt_parse_options(&help, &version, &confirm, &type, &algorithm,
			      &salt, argc, argv);

	if (help) {
		pwcrypt_help(out);
		return EXIT_SUCCESS;
	}
	if (version) {
		pwcrypt_version(out);
		return EXIT_SUCCESS;
	}
	FILE *tty = fopen("/dev/tty", "r+");
	if (!tty) {
		err(EXIT_FAILURE, "fopen(/dev/tty, r+) failed");
	}

	int rv = pwcrypt(confirm, type, algorithm, salt, out,
			 fgets_no_echo, tty);

	fclose(tty);

	return rv;
}

#ifndef PWCRYPT_TEST
int main(int argc, char **argv)
{
	return pwcrypt_cli(argc, argv, stdout);
}
#endif
