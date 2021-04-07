/* SPDX-License-Identifier: GPL-3.0-or-later */
/* test-is-valid-for-salt.c */
/* Copyright (C) 2021 Eric Herman <eric@freesa.org> */

#include "pwcrypt.c"
#include "test-util.c"

unsigned test_valid(void)
{
	unsigned failures = 0;

	char c = '.';
	failures += check(is_valid_for_salt(c), "%c", c);

	c = '/';
	failures += check(is_valid_for_salt(c), "%c", c);

	for (size_t i = 0; i < 10; ++i) {
		c = '0' + i;
		failures += check(is_valid_for_salt(c), "%c", c);
	}

	for (size_t i = 0; i < 26; ++i) {
		c = 'A' + i;
		failures += check(is_valid_for_salt(c), "%c", c);
	}

	for (size_t i = 0; i < 26; ++i) {
		c = 'a' + i;
		failures += check(is_valid_for_salt(c), "%c", c);
	}

	return failures;
}

unsigned test_whitespace(void)
{
	unsigned failures = 0;

	char c = '\0';
	failures += check(is_valid_for_salt(c) == 0, "(empty)");

	c = ' ';
	failures += check(is_valid_for_salt(c) == 0, "space");

	c = '\t';
	failures += check(is_valid_for_salt(c) == 0, "tab");

	c = '\r';
	failures += check(is_valid_for_salt(c) == 0, "cr");

	c = '\n';
	failures += check(is_valid_for_salt(c) == 0, "lf");

	return failures;
}

unsigned test_invalid(void)
{
	unsigned failures = 0;

	const char *invalid = "$:;*!\\";
	for (size_t i = 0; i < strlen(invalid); ++i) {
		char c = invalid[i];
		failures += check(is_valid_for_salt(c) == 0, "'%c'", c);
	}

	return failures;
}

int main(void)
{
	unsigned failures = 0;

	failures += run_test(test_valid);
	failures += run_test(test_whitespace);
	failures += run_test(test_invalid);

	return failures_to_status("test-is-valid-for-salt", failures);
}
