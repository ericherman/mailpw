/* SPDX-License-Identifier: GPL-3.0-or-later */
/* test-util.c */
/* Copyright (C) 2020, 2021 Eric Herman <eric@freesa.org> */

#include <limits.h>
#include <stdarg.h>

#include <stdio.h>
#include <stdlib.h>

#include "test-util.h"

unsigned run_named_test(const char *name, unsigned (*func)(void))
{
	fprintf(stderr, "  %s", name);
	fprintf(stderr, " ...");
	unsigned failures = func();
	if (failures) {
		fprintf(stderr, " %u failures. FAIL!\n", failures);
	} else {
		fprintf(stderr, " ok.\n");
	}
	return failures;
}

int failures_to_status(const char *name, unsigned failures)
{
	int exit_code;

	fprintf(stderr, "%s ", name);
	if (failures) {
		exit_code = EXIT_FAILURE;
		fprintf(stderr, "%u FAILURES\n", failures);
	} else {
		exit_code = EXIT_SUCCESS;
		fprintf(stderr, "SUCCESS\n");
	}

	return exit_code;
}

unsigned check_expression_result(const char *file, int line, const char *func,
				 int result, const char *expr_str,
				 const char *format, ...)
{
	if (result) {
		return 0;
	}

	fflush(stdout);
	fprintf(stderr, "\n%s:%d %s() (%s) FAIL ", file, line, func, expr_str);

	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	fprintf(stderr, "\n");

	return 1;
}
