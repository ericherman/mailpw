/* SPDX-License-Identifier: GPL-3.0-or-later */
/* test-alloc-madvised.c */
/* Copyright (C) 2021 Eric Herman <eric@freesa.org> */
/* Copyright (C) 2021 Rutger Bazen <rutger.bazen@gmail.com> */

#include "pwcrypt.c"
#include "test-util.c"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

unsigned alloc_and_fork(void)
{
	unsigned failures = 0;

	size_t buf_size = 0;
	char *buf_madvised = alloc_madvised_or_die(&buf_size, 1);

	size_t page_size = getpagesize();
	failures += check(buf_size == page_size, "expected %zu but was %zu",
			  getpagesize(), buf_size);

	const char *test_data = "This is test data";
	snprintf(buf_madvised, buf_size, test_data);

	char *buf2 = malloc(buf_size);
	if (!buf2) {
		err(EXIT_FAILURE, "malloc failed?");
	}
	snprintf(buf2, buf_size, test_data);

	pid_t pid = fork();
	if (pid < 0) {
		err(EXIT_FAILURE, "fork failed\n");
	} else if (pid == 0) {
		/* we are the child */
		if (strcmp(buf_madvised, test_data) == 0) {
			err(EXIT_FAILURE,
			    "unexpected ability to read buf_madvised %p,"
			    " madvise failed.", buf_madvised);
		}

		if (strcmp(buf2, test_data) != 0) {
			err(EXIT_FAILURE,
			    "why couldn't we read buf2 (%p) from parent?",
			    buf2);
		}

		exit(EXIT_SUCCESS);
	} else {
		int wstatus;
		int options = 0;
		waitpid(pid, &wstatus, options);
		int child_exit_status = WEXITSTATUS(wstatus);
		failures +=
		    check(child_exit_status == EXIT_SUCCESS,
			  "expected 0, but was %d", child_exit_status);
	}

	free(buf2);
	free_madvised(buf_madvised, buf_size);

	return failures;
}

int main(void)
{
	unsigned failures = 0;

	failures += run_test(alloc_and_fork);

	return failures_to_status("test-alloc-madvised", failures);
}
