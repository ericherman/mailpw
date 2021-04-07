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
void getpass(char *buf, char *buf2, size_t len, int confirm);
void getrandom_alphanumeric(char *buf, size_t len);
char *fgetpass(char *buf, size_t len, FILE *stream);
int is_english_alphanumeric(char c);

/* functions */
int main(void)
{
	const size_t plain_salt_size = Max_salt_len + 1;
	char plain_salt[plain_salt_size];
	getrandom_alphanumeric(plain_salt, plain_salt_size);

	const char *algo = CRYPT_SHA512;
	const size_t algo_salt_size = plain_salt_size + 10;
	char algo_salt[algo_salt_size];
	snprintf(algo_salt, algo_salt_size, "$%s$%s$", algo, plain_salt);

	struct crypt_data data;
	/* data->initialized = 0; */
	memset(&data, 0x00, sizeof(struct crypt_data));

	int confirm = 1;

	// TODO: use madvise with MADV_DONTDUMP, MADV_WIPEONFORK
	const size_t plaintext_passphrase_size = 1024;
	char plaintext_passphrase[plaintext_passphrase_size];
	char plaintext_passphrase2[plaintext_passphrase_size];

	getpass(plaintext_passphrase, plaintext_passphrase2,
		plaintext_passphrase_size, confirm);

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

void getpass(char *buf, char *buf2, size_t size, int confirm)
{
	FILE *tty = fopen("/dev/tty", "r+");
	if (!tty) {
		err(EXIT_FAILURE, "fopen(/dev/tty, r+) failed");
	}

	int diff = 0;
	do {
		if (diff) {
			fprintf(tty, "inputs did not match\n");
		}
		fprintf(tty, " input passphrase: ");
		char *r = fgetpass(buf, size, tty);
		if (!r) {
			err(EXIT_FAILURE,
			    "fgetpass returned NULL reading buf of %zu", size);
		}
		fprintf(tty, "\n");

		if (confirm) {
			fprintf(tty, "repeat passphrase: ");
			r = fgetpass(buf2, size, tty);
			if (!r) {
				err(EXIT_FAILURE,
				    "fgetpass returned NULL reading buf of %zu?",
				    size);
			}
			fprintf(tty, "\n");

			diff = strncmp(buf, buf2, size);
		}
	} while (diff);
}

void getrandom_alphanumeric(char *buf, size_t len)
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
			if (is_english_alphanumeric(c)) {
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

/* the standard C libarary "isalnum" results may depend upon the locale */
/* https://www.cplusplus.com/reference/cctype/isalnum/ */
int is_english_alphanumeric(char c)
{
	if (c >= '0' && c <= '9') {
		return c;
	}
	if (c >= 'A' && c <= 'Z') {
		return c;
	}
	if (c >= 'a' && c <= 'z') {
		return c;
	}
	return 0;
}

/* [1] https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html#tag_15_05_01 */
