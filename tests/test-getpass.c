/* SPDX-License-Identifier: GPL-3.0-or-later */
/* test-getpass.c */
/* Copyright (C) 2021 Eric Herman <eric@freesa.org> */

#include "pwcrypt.c"
#include "test-util.c"

/*************************************************************************/
/* Rather than make the API dirty with an extra void pointer only used by
 * tests, let's just put a global in our test .... */
/*************************************************************************/
static void *global_ctx = NULL;
/*************************************************************************/

struct getpass_testing_context {
	unsigned *failures;
	unsigned call_counter;
	FILE *tty;
};

char *fgets_bogus(char *s, int size, FILE *stream)
{
	struct getpass_testing_context *ctx = global_ctx;
	++(ctx->call_counter);
	*(ctx->failures) += check(ctx->tty == stream, "tty");

	strncpy(s, "bogus\n", size);
	return s;
}

unsigned test_getpass_no_confirm_no_type(void)
{
	unsigned failures = 0;

	struct getpass_testing_context ctx;
	ctx.failures = &failures;
	ctx.call_counter = 0;
	const size_t fake_tty_buf_size = 2048;
	char fake_tty_buf[fake_tty_buf_size];
	memset(fake_tty_buf, 0x00, fake_tty_buf_size);
	ctx.tty = fmemopen(fake_tty_buf, fake_tty_buf_size, "r+");
	if (!ctx.tty) {
		err(EXIT_FAILURE, "fmemopen stack buf");
	}

	const size_t buf_size = 80;
	char buf[buf_size];
	char buf2[buf_size];
	const char *type = NULL;
	int confirm = 0;

	global_ctx = &ctx;

	getpass(buf, buf2, buf_size, type, confirm, fgets_bogus, ctx.tty);

	fclose(ctx.tty);

	failures += check(strcmp(buf, "bogus") == 0, "buf:'%s'", buf);
	failures += check(ctx.call_counter == 1, "cnt: %zu", ctx.call_counter);
	failures +=
	    check(strstr(fake_tty_buf, "input passphrase:"), "'%s'",
		  fake_tty_buf);
	failures +=
	    check(!strstr(fake_tty_buf, "repeat"), "'%s'", fake_tty_buf);

	return failures;
}

char *wrong_first_try(char *s, int size, FILE *stream)
{
	struct getpass_testing_context *ctx = global_ctx;
	(void)stream;

	++(ctx->call_counter);

	const char *passphrase;
	if (ctx->call_counter == 1) {
		passphrase = "wrong!\n";
	} else {
		passphrase = "right!\n";
	}
	strncpy(s, passphrase, size);
	return s;
}

unsigned test_getpass_wrong_first_try(void)
{
	unsigned failures = 0;

	struct getpass_testing_context ctx;
	ctx.failures = &failures;
	ctx.call_counter = 0;
	const size_t fake_tty_buf_size = 2048;
	char fake_tty_buf[fake_tty_buf_size];
	memset(fake_tty_buf, 0x00, fake_tty_buf_size);
	ctx.tty = fmemopen(fake_tty_buf, fake_tty_buf_size, "r+");
	if (!ctx.tty) {
		err(EXIT_FAILURE, "fmemopen stack buf");
	}

	const size_t buf_size = 80;
	char buf[buf_size];
	char buf2[buf_size];
	const char *type = "foo";
	int confirm = 1;

	global_ctx = &ctx;

	getpass(buf, buf2, buf_size, type, confirm, wrong_first_try, ctx.tty);

	fclose(ctx.tty);

	failures += check(strcmp(buf, "right!") == 0, "buf:'%s'", buf);
	failures += check(ctx.call_counter == 4, "cnt: %zu", ctx.call_counter);
	failures +=
	    check(strstr(fake_tty_buf, "input foo passphrase:"), "'%s'",
		  fake_tty_buf);
	failures += check(strstr(fake_tty_buf, "repeat"), "'%s'", fake_tty_buf);

	return failures;
}

int main(void)
{
	unsigned failures = 0;

	failures += run_test(test_getpass_no_confirm_no_type);
	failures += run_test(test_getpass_wrong_first_try);

	return failures_to_status("test-getpass", failures);
}
