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

PERL ?= perl
SHELL = /bin/bash

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

test-getpw: tests/test-getpw.c $(TEST_DEPS)
	$(CC) $(TEST_CFLAGS) $< -o $@ $(PWC_LDADD)

check-getpw: test-getpw
	./test-getpw
	@echo "SUCCESS! ($@)"

test-alloc-madvised: tests/test-alloc-madvised.c $(TEST_DEPS)
	$(CC) $(TEST_CFLAGS) $< -o $@ $(PWC_LDADD)

check-alloc-madvised: test-alloc-madvised
	./test-alloc-madvised
	@echo "SUCCESS! ($@)"

test-is-valid-for-salt: tests/test-is-valid-for-salt.c $(TEST_DEPS)
	$(CC) $(TEST_CFLAGS) $< -o $@ $(PWC_LDADD)

check-is-valid-for-salt: test-is-valid-for-salt
	./test-is-valid-for-salt
	@echo "SUCCESS! ($@)"

check-mailpw-get-instances: tests/test-mailpw-get-instances.pl mailpw
	$(PERL) tests/test-mailpw-get-instances.pl
	@echo "SUCCESS! ($@)"

check-mailpw-who-am-i: tests/test-mailpw-who-am-i.pl mailpw
	SUDO_USER=foo $(PERL) tests/test-mailpw-who-am-i.pl foo
	@echo "SUCCESS! ($@)"

check-mailpw-who-am-i-no-sudo-user: tests/test-mailpw-who-am-i.pl mailpw
	$(PERL) tests/test-mailpw-who-am-i.pl $(USER)
	@echo "SUCCESS! ($@)"

check-mailpw-replace-hash: tests/test-mailpw-replace-hash.pl mailpw
	$(PERL) tests/test-mailpw-replace-hash.pl
	@echo "SUCCESS! ($@)"

check-mailpw-change-passwd: tests/test-mailpw-change-passwd.pl mailpw pwcrypt
	$(PERL) tests/test-mailpw-change-passwd.pl
	@echo "SUCCESS! ($@)"

check-unit: check-crypt-algo \
		check-getpw \
		check-is-valid-for-salt \
		check-alloc-madvised \
		check-mailpw-get-instances \
		check-mailpw-who-am-i \
		check-mailpw-who-am-i-no-sudo-user \
		check-mailpw-replace-hash \
		check-mailpw-change-passwd
	@echo "SUCCESS! ($@)"

check-acceptance-sha512: ./tests/check-sha512 tests/expect-no-confirm \
		pwcrypt
	$(PERL) ./tests/check-sha512
	@echo "SUCCESS! ($@)"

check-acceptance-md5: ./tests/check-md5 tests/expect-confirm pwcrypt
	$(PERL) ./tests/check-md5
	@echo "SUCCESS! ($@)"

check-acceptance-mailpw: tests/expect-mailpw mailpw pwcrypt \
		tests/faux/faux-mailpw.conf \
		tests/faux/bar/dovecot-passwd \
		tests/faux/bar/dovecot-passwd.expected \
		tests/faux/bar/opensmtpd-users \
		tests/faux/bar/opensmtpd-users.expected \
		tests/faux/baz/dovecot-passwd \
		tests/faux/baz/dovecot-passwd.expected \
		tests/faux/baz/opensmtpd-users \
		tests/faux/baz/opensmtpd-users.expected \
		tests/faux/foo/dovecot-passwd \
		tests/faux/foo/dovecot-passwd.expected \
		tests/faux/foo/opensmtpd-users \
		tests/faux/foo/opensmtpd-users.expected
	@echo creatig modifiable copies of user/passwd files
	rm -rfv faux
	cp -ir tests/faux .
	sed -i -e "s/USER/$$USER/g" faux/foo/* faux/bar/* faux/baz/*
	tests/expect-mailpw tests/faux/faux-mailpw.conf \
		pinch.of.salt Ever.expanding.circles.of.love
	diff -u faux/baz/opensmtpd-users faux/baz/opensmtpd-users.expected
	diff -u faux/baz/dovecot-passwd faux/baz/dovecot-passwd.expected
	diff -u faux/foo/opensmtpd-users faux/foo/opensmtpd-users.expected
	diff -u faux/foo/dovecot-passwd faux/foo/dovecot-passwd.expected
	diff -u faux/bar/opensmtpd-users faux/bar/opensmtpd-users.expected
	diff -u faux/bar/dovecot-passwd faux/bar/dovecot-passwd.expected
	@echo Success, thus removing modified copies of user/passwd files
	rm -rf faux
	@echo "SUCCESS! ($@)"

check-acceptance: check-acceptance-md5 \
		check-acceptance-sha512 \
		check-acceptance-mailpw
	@echo "SUCCESS! ($@)"

check: check-unit check-acceptance
	@echo "SUCCESS! ($@)"

# extracted from https://github.com/torvalds/linux/blob/master/scripts/Lindent
LINDENT=indent -npro -kr -i8 -ts8 -sob -l80 -ss -ncs -cp1 -il0
# see also: https://www.kernel.org/doc/Documentation/process/coding-style.rst
tidy-c:
	$(LINDENT) \
		-T FILE \
		-T size_t -T ssize_t \
		-T crypt_data \
		-T termios \
		tests/*.h tests/*.c \
		pwcrypt.c

PERL_SRC=mailpw \
	tests/check-md5 \
	tests/check-sha512 \
	tests/*.pl

tidy-perl:
	#TODO: replace for-loop with Makefile magic
	for FILE in $(PERL_SRC); do \
		$(PERL) -c $$FILE \
			&& perltidy $$FILE \
			&& mv $$FILE $$FILE~ \
			&& mv $$FILE.tdy $$FILE; \
	done

tidy: tidy-c tidy-perl

clean:
	rm -rfv faux
	rm -fv `cat .gitignore`
	pushd tests; rm -fv `cat ../.gitignore`; popd
