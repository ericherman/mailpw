/* SPDX-License-Identifier: GPL-3.0-or-later */
/* test-util.h */
/* Copyright (C) 2020, 2021 Eric Herman <eric@freesa.org> */

#ifndef TEST_UTIL_H
#define TEST_UTIL_H 1

#include <stddef.h>

#include <string.h>

unsigned run_named_test(const char *name, unsigned (*func)(void));

#define run_test(func) run_named_test(#func, func)

unsigned check_expression_flf(const char *file, int line, const char *func,
			      int expression, const char *expr_str,
			      const char *format, ...);

#define check(expression, format, ...) \
	check_expression_flf(__FILE__, __LINE__, __func__, \
			(expression) ? 1 : 0, #expression, \
			format __VA_OPT__(,) __VA_ARGS__)

#define check_str(a, b, format, ...) \
	check((strcmp(a, b) == 0), format __VA_OPT__(,) __VA_ARGS__)

int failures_to_status(const char *name, unsigned failures);

#endif /* #ifndef TEST_UTIL_H */
