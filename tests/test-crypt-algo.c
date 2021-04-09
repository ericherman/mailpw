/* SPDX-License-Identifier: GPL-3.0-or-later */
/* test-crypt-algo.c */
/* Copyright (C) 2021 Eric Herman <eric@freesa.org> */

#include "pwcrypt.c"
#include "test-util.c"

unsigned test_crypt_algo_sha512(void)
{
	unsigned failures = 0;

	failures += check_str(CRYPT_SHA512, crypt_algo("sha512"), "lower");
	failures += check_str(CRYPT_SHA512, crypt_algo("SHA512"), "upper");
	failures += check_str(CRYPT_SHA512, crypt_algo("6"), "number");

	return failures;
}

unsigned test_crypt_algo_sha256(void)
{
	unsigned failures = 0;

	failures += check_str(CRYPT_SHA256, crypt_algo("sha256"), "lc");
	failures += check_str(CRYPT_SHA256, crypt_algo("SHA256"), "uc");
	failures += check_str(CRYPT_SHA256, crypt_algo("5"), "num");

	return failures;
}

unsigned test_crypt_algo_defaults(void)
{
	unsigned failures = 0;

	failures += check_str(CRYPT_SHA512, crypt_algo(NULL), "(null)");
	failures += check_str(CRYPT_SHA512, crypt_algo(""), "(empty)");
	failures += check_str(CRYPT_SHA512, crypt_algo("default"), "(literal)");

	return failures;
}

unsigned test_crypt_algo_garbage_in_garbage_out(void)
{
	unsigned failures = 0;

	failures += check_str("1", crypt_algo("1"), "md5");
	failures += check_str("2a", crypt_algo("2a"), "blowfish");
	failures += check_str("garbage", crypt_algo("garbage"), "bogus");

	return failures;
}

int main(void)
{
	unsigned failures = 0;

	failures += run_test(test_crypt_algo_sha512);
	failures += run_test(test_crypt_algo_sha256);
	failures += run_test(test_crypt_algo_defaults);
	failures += run_test(test_crypt_algo_garbage_in_garbage_out);

	return failures_to_status("test-crypt-algo", failures);
}
