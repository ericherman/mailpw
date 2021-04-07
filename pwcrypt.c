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
 *		[--algorthm='SHA512'] \
 *		[--salt='UD23qlwjerf']
 *
 * To test against your own passwd, get your salt:
 *
 *	PW=`sudo grep $USER /etc/shadow | cut -f2 -d':' `
 *	SALT=`echo "$PW" | cut -d'$' -f3`
 *	GUESS=`pwcrypt --salt="$SALT"`
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

/* limit imposed by crypt_r */
#define Max_salt_len 16

/* see the "Notes" section of "man 3 crypt" for glibc crypt_r
 * algorithm options */
#define CRYPT_MD5 "1"
/* #define CRYPT_BLOWFISH "2a" */
#define CRYPT_SHA256 "5"
#define CRYPT_SHA512 "6"

/* prototypes */
char *chomp_crlf(char *str, size_t max);
void getpass(char *buf, char *buf2, size_t len, const char *type, int confirm);
void getrandom_salt(char *buf, size_t len);
char *fgetpass(char *buf, size_t len, FILE *stream);
int is_valid_for_salt(char c);
const char *crypt_algo(const char *in);

/* functions */
int pwcrypt(int confirm, const char *type, const char *algorithm,
	    const char *salt)
{
	const size_t plain_salt_size = Max_salt_len + 1;
	char plain_salt[plain_salt_size];
	memset(plain_salt, 0x00, plain_salt_size);
	if (salt) {
		strncpy(plain_salt, salt, plain_salt_size);
	} else {
		getrandom_salt(plain_salt, plain_salt_size);
	}

	const char *algo = crypt_algo(algorithm);
	const size_t algo_salt_size = plain_salt_size + 10;
	char algo_salt[algo_salt_size];
	snprintf(algo_salt, algo_salt_size, "$%s$%s$", algo, plain_salt);

	struct crypt_data data;
	/* data->initialized = 0; */
	memset(&data, 0x00, sizeof(struct crypt_data));

	// TODO: use madvise with MADV_DONTDUMP, MADV_WIPEONFORK
	const size_t plaintext_passphrase_size = 1024;
	char plaintext_passphrase[plaintext_passphrase_size];
	char plaintext_passphrase2[plaintext_passphrase_size];

	getpass(plaintext_passphrase, plaintext_passphrase2,
		plaintext_passphrase_size, type, confirm);

	char *encrypted = crypt_r(plaintext_passphrase, algo_salt, &data);
	if (!encrypted) {
		err(EXIT_FAILURE, "crypt_r failed");
	}

	memset(plaintext_passphrase, 0x00, plaintext_passphrase_size);

	printf("%s\n", encrypted);

	return 0;
}

char *fgetpass(char *buf, size_t len, FILE *stream)
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

	char *str = chomp_crlf(fgets(buf, len, stream), len);

	error = tcsetattr(fno, TCSAFLUSH, &orig);
	if (error) {
		err(EXIT_FAILURE, "reset tcgetattr failed for fd: %d", fno);
	}

	return str;
}

void getpass(char *buf, char *buf2, size_t size, const char *type, int confirm)
{
	FILE *tty = fopen("/dev/tty", "r+");
	if (!tty) {
		err(EXIT_FAILURE, "fopen(/dev/tty, r+) failed");
	}

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
		char *r = fgetpass(buf, size, tty);
		if (!r) {
			err(EXIT_FAILURE,
			    "fgetpass returned NULL reading buf of %zu", size);
		}
		fprintf(tty, "\n");
		fflush(tty);

		if (confirm) {
			fprintf(tty, "repeat %s%spassphrase: ", type, space);
			fflush(tty);
			r = fgetpass(buf2, size, tty);
			if (!r) {
				err(EXIT_FAILURE,
				    "fgetpass returned NULL reading buf of %zu?",
				    size);
			}
			fprintf(tty, "\n");
			fflush(tty);

			diff = strncmp(buf, buf2, size);
		}
	} while (diff);
	fclose(tty);
}

const char *crypt_algo(const char *in)
{
	if (!in) {
		return CRYPT_SHA512;
	}

	if (strcasecmp(in, "SHA512") == 0 || strcasecmp(in, CRYPT_SHA512) == 0) {
		return CRYPT_SHA512;
	}

	if (strcasecmp(in, "SHA256") == 0 || strcasecmp(in, CRYPT_SHA256) == 0) {
		return CRYPT_SHA256;
	}

	if (strcasecmp(in, "MD5") == 0 || strcasecmp(in, CRYPT_MD5) == 0) {
		return CRYPT_SHA256;
	}

	return in;
}

void getrandom_salt(char *buf, size_t len)
{
	assert(buf);
	assert(len);
	size_t max = (len - 1);
	size_t pos = 0;
	do {
		const size_t rnd_buf_len = 10 * Max_salt_len;
		char rnd_buf[rnd_buf_len];
		unsigned int flags = 0;
		ssize_t got = getrandom(rnd_buf, rnd_buf_len, flags);

		for (ssize_t i = 0; i < got && pos < max; ++i) {
			char c = rnd_buf[i];
			if (is_valid_for_salt(c)) {
				buf[pos++] = c;
			}
		}
	} while (pos < max);
	buf[pos++] = '\0';
}

/* boring stuff */
char *chomp_crlf(char *str, size_t max)
{
	if (!str) {
		return NULL;
	}
	for (size_t i = 0; i < max && str[i] != '\0'; ++i) {
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

int main(void)
{
	int confirm = 1;
	const char *type = NULL;
	const char *algorithm = "sha512";
	const char *salt = NULL;

	return pwcrypt(confirm, type, algorithm, salt);
}
