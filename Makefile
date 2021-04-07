# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2021 Eric Herman <eric@freesa.org>
# Copyright (C) 2021 Keith Reynolds <keithr@pwcrypt.keithr.com>

# $@ : target label
# $< : the first prerequisite after the colon
# $^ : all of the prerequisite files
# $* : wildcard matched part
# Target-specific Variable syntax:
# https://www.gnu.org/software/make/manual/html_node/Target_002dspecific.html
#
# patsubst : $(patsubst pattern,replacement,text)
#       https://www.gnu.org/software/make/manual/html_node/Text-Functions.html


PWC_CFLAGS=-g -Wall -Wextra -Wpedantic -Werror
PWC_LDADD=-lcrypt

pwcrypt: pwcrypt.c
	$(CC) $(PWC_CFLAGS) $< -o $@ $(PWC_LDADD)

TEST_DEPS=pwcrypt.c tests/test-util.h tests/test-util.c
TEST_CFLAGS=-DPWCRYPT_TEST=1 -I. $(PWC_CFLAGS)

test-crypt-algo: tests/test-crypt-algo.c $(TEST_DEPS)
	$(CC) $(TEST_CFLAGS) $< -o $@ $(PWC_LDADD)

check-crypt-algo: test-crypt-algo
	./test-crypt-algo
	@echo "SUCCESS! ($@)"

test-is-valid-for-salt: tests/test-is-valid-for-salt.c $(TEST_DEPS)
	$(CC) $(TEST_CFLAGS) $< -o $@ $(PWC_LDADD)

check-is-valid-for-salt: test-is-valid-for-salt
	./test-is-valid-for-salt
	@echo "SUCCESS! ($@)"

check: check-crypt-algo \
		check-is-valid-for-salt
	@echo "SUCCESS! ($@)"

# extracted from https://github.com/torvalds/linux/blob/master/scripts/Lindent
LINDENT=indent -npro -kr -i8 -ts8 -sob -l80 -ss -ncs -cp1 -il0
# see also: https://www.kernel.org/doc/Documentation/process/coding-style.rst
tidy:
	$(LINDENT) \
		-T FILE \
		-T size_t -T ssize_t \
		-T crypt_data \
		-T termios \
		tests/*.h tests/*.c \
		pwcrypt.c

clean:
	rm -fv `cat .gitignore`
